using System.Net.Http.Headers;
using IdentityServices.IntegrationTests.Infrastructure;
using Meshmakers.Octo.Backend.IdentityServices.Methods;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.DataPermissions;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Microsoft.Extensions.DependencyInjection;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Methods;
using Meshmakers.Octo.Services.Notifications.Generated.System.Notification.v2;
using Meshmakers.Octo.Services.Notifications.Services;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using NSubstitute;

namespace IdentityServices.IntegrationTests.Api.TenantApi;

/// <summary>The caller of a REST request in the facade tests: a user (subject) or a client-credentials caller.</summary>
internal sealed record FacadeCaller(string? Subject, string? ClientId, string[] Roles, string? TokenTenant = null)
{
    public static FacadeCaller User(params string[] roles) => new(Guid.NewGuid().ToString("N"), null, roles);

    public static FacadeCaller Service(params string[] roles) => new(null, $"svc_{Guid.NewGuid():N}", roles);

    /// <summary>A REST client of <paramref name="host" /> carrying this caller (test bearer scheme).</summary>
    public HttpClient Client(WebApplicationFactory<Program> host)
    {
        var client = host.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "test-token");
        if (ClientId != null)
        {
            client.DefaultRequestHeaders.Add(TestAuthHandler.ClientCredentialsHeader, ClientId);
        }
        else
        {
            client.DefaultRequestHeaders.Add(TestAuthHandler.UserIdHeader, Subject);
            client.DefaultRequestHeaders.Add(TestAuthHandler.UserNameHeader, "caller");
        }

        if (Roles.Length == 0)
        {
            client.DefaultRequestHeaders.Add(TestAuthHandler.NoRolesHeader, "true");
        }

        foreach (var role in Roles)
        {
            client.DefaultRequestHeaders.Add(TestAuthHandler.RoleHeader, role);
        }

        if (TokenTenant != null)
        {
            client.DefaultRequestHeaders.Add(TestAuthHandler.TenantIdHeader, TokenTenant);
            // the tenant gate only judges a "Bearer" principal
            client.DefaultRequestHeaders.Add(TestAuthHandler.RealBearerPrincipalHeader, "true");
        }

        return client;
    }
}

/// <summary>
///     Captures the <c>Identity.Method</c> audit events and the REST refusal records (<c>Identity.RoleChangeRefused</c>) of a
///     test host through a substitute <see cref="IEventRepository" />.
/// </summary>
internal sealed class FacadeAuditCapture
{
    private readonly List<Dictionary<string, string>> _methodEvents = [];
    private readonly List<string> _refusals = [];

    public FacadeAuditCapture()
    {
        Events = Substitute.For<IEventRepository>();
        Events.When(e => e.StoreErrorEvent(Arg.Any<string>(), Arg.Any<RtEventSourcesEnum>(), Arg.Any<string>(),
                Arg.Any<RtEntityId?>()))
            .Do(call =>
            {
                lock (_refusals)
                {
                    _refusals.Add(call.ArgAt<string>(2));
                }
            });
        Events.When(e => e.StoreEventAsync(Arg.Any<string>(), Arg.Any<RtEventSourcesEnum>(),
                Arg.Any<RtEventLevelsEnum>(), Arg.Any<string>(), Arg.Any<string?>(),
                Arg.Any<IReadOnlyCollection<KeyValuePair<string, string>>?>(), Arg.Any<RtEntityId?>()))
            .Do(call =>
            {
                if (call.ArgAt<string?>(4) != IdentityMethodAuditWriter.Category)
                {
                    return;
                }

                lock (_methodEvents)
                {
                    _methodEvents.Add((call.ArgAt<IReadOnlyCollection<KeyValuePair<string, string>>?>(5) ?? [])
                        .ToDictionary(d => d.Key, d => d.Value));
                }
            });
    }

    public IEventRepository Events { get; }

    public int RefusalCount
    {
        get
        {
            lock (_refusals)
            {
                return _refusals.Count;
            }
        }
    }

    /// <summary>The <c>Identity.Method</c> events of <paramref name="methodId" /> on <paramref name="targetRtId" />.</summary>
    public List<Dictionary<string, string>> For(string methodId, string? targetRtId)
    {
        lock (_methodEvents)
        {
            return _methodEvents.Where(d => d.GetValueOrDefault("methodId") == methodId &&
                                            d.GetValueOrDefault("targetRtId") == targetRtId).ToList();
        }
    }

    /// <summary>Every captured <c>Identity.Method</c> event.</summary>
    public List<Dictionary<string, string>> All
    {
        get
        {
            lock (_methodEvents)
            {
                return _methodEvents.ToList();
            }
        }
    }

    /// <summary>All <c>Identity.Method</c> events whose details carry <paramref name="key" /> = <paramref name="value" />.</summary>
    public List<Dictionary<string, string>> Where(string key, string value)
    {
        lock (_methodEvents)
        {
            return _methodEvents.Where(d => d.GetValueOrDefault(key) == value).ToList();
        }
    }
}

/// <summary>
///     Tripwire of the in-process transport for the facade tests: asked at handler entry, in the handler's own flow
///     and DI scope. A REST facade must call its method outside the request: no HTTP context (and so no request-bound Mongo
///     session or transaction of the request) and no request-bound ambient value may be visible there. The test host sets
///     <see cref="RequestMarker" /> for the whole request through <see cref="MarkRequestsStartupFilter" />; detaching makes it
///     empty inside the handler. Reporting <c>true</c> fails the call with <c>METHOD_HANDLER_FAILED</c>.
/// </summary>
internal sealed class RequestStateProbe : ICkInProcessAmbientStateProbe
{
    /// <summary>Set for every HTTP request of the test host (an ambient value the request flow owns).</summary>
    public static readonly AsyncLocal<string?> RequestMarker = new();

    private int _calls;
    private int _violations;

    /// <summary>How often the probe was asked (once per in-process handler entry).</summary>
    public int Calls => Volatile.Read(ref _calls);

    /// <summary>How often it saw request state at handler entry.</summary>
    public int Violations => Volatile.Read(ref _violations);

    public bool IsRequestStateVisible(IServiceProvider handlerServices)
    {
        Interlocked.Increment(ref _calls);
        var visible = RequestMarker.Value != null ||
                      handlerServices.GetService<IHttpContextAccessor>()?.HttpContext != null;
        if (visible)
        {
            Interlocked.Increment(ref _violations);
        }

        return visible;
    }
}

/// <summary>Sets <see cref="RequestStateProbe.RequestMarker" /> for the whole HTTP request, ahead of every other middleware.</summary>
internal sealed class MarkRequestsStartupFilter : IStartupFilter
{
    public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
    {
        app.Use(async (context, nextMiddleware) =>
        {
            RequestStateProbe.RequestMarker.Value = context.TraceIdentifier;
            try
            {
                await nextMiddleware(context);
            }
            finally
            {
                RequestStateProbe.RequestMarker.Value = null;
            }
        });
        next(app);
    };
}

/// <summary>A data-permission evaluator of an enforcing policy for the facade tests: the caller may read nothing.</summary>
internal static class FacadeDataPolicy
{
    public static IRtDataPermissionEvaluator DenyAllReads()
    {
        var evaluator = Substitute.For<IRtDataPermissionEvaluator>();
        evaluator.EvaluateAsync(Arg.Any<IRuntimeRepository>(), Arg.Any<RtSecurityContext>(), Arg.Any<RtEntityId>(),
                Arg.Any<RtDataAction>(), Arg.Any<bool>(), Arg.Any<CancellationToken>())
            .Returns(new RtDataPermissionVerdict(RtDataPermissionDecision.NotVisible, RtDataPermissionReason.NoGrant));
        return evaluator;
    }
}
