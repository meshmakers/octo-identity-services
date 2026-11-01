using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using IdentityServerPersistence.SystemStores;
using IdentityServices.IntegrationTests.Infrastructure;
using Meshmakers.Octo.Backend.IdentityServices.Methods;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Methods;
using Meshmakers.Octo.Services.Methods;
using Meshmakers.Octo.Services.Methods.Authorization;
using Meshmakers.Octo.Services.Methods.Handlers;
using Meshmakers.Octo.Services.Notifications.Generated.System.Notification.v2;
using Meshmakers.Octo.Services.Notifications.Services;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.Methods;

/// <summary>
///     AB#7780: <c>Client.AddSecret</c> and <c>Client.RemoveSecret</c> served by the identity service. Real MongoDB, the real
///     identity host with <c>Methods:Identity:EnablePasswordMethods=true</c>, the real token endpoint for the client credentials
///     grant. The handlers run in a fresh DI scope without an HTTP request, as on the bus, with the principal the host
///     validated. The event repository and the logger are captured: the generated secret (and a clear text passed to
///     RemoveSecret) must appear in no audit event and no log line.
/// </summary>
public class ClientSecretMethodTests : IntegrationTestBase
{
    private const string ApiScope = "client-secret-method-api";
    private static readonly string[] TenantAdminRoles = ["TenantManagement"];

    private readonly WebApplicationFactory<Program> _enabled;
    private readonly ConcurrentQueue<CapturedEvent> _events = new();
    private readonly CapturingLoggerProvider _logs = new();

    public ClientSecretMethodTests(CustomWebApplicationFactory factory) : base(factory)
    {
        _enabled = factory.WithWebHostBuilder(Configure);
    }

    private void Configure(Microsoft.AspNetCore.Hosting.IWebHostBuilder b)
    {
        // UseSetting reaches the host configuration before Program reads Methods:Identity.
        b.UseSetting("Methods:Identity:EnablePasswordMethods", "true");
        b.ConfigureTestServices(services =>
        {
            // The test host has no broker: drop the bus side of the method host.
            foreach (var descriptor in services
                         .Where(d => d.ImplementationType?.Name is "CkMethodHandlerStartupService"
                             or "CkMethodHandlerHeartbeatService").ToList())
            {
                services.Remove(descriptor);
            }

            services.AddLogging(l => l.AddProvider(_logs));
            var events = Substitute.For<IEventRepository>();
            events.StoreEventAsync(Arg.Any<string>(), Arg.Any<RtEventSourcesEnum>(), Arg.Any<RtEventLevelsEnum>(),
                    Arg.Any<string>(), Arg.Any<string?>(),
                    Arg.Any<IReadOnlyCollection<KeyValuePair<string, string>>?>(), Arg.Any<RtEntityId?>())
                .Returns(call =>
                {
                    _events.Enqueue(new CapturedEvent(call.ArgAt<string>(0), call.ArgAt<string>(3),
                        call.ArgAt<string?>(4),
                        (call.ArgAt<IReadOnlyCollection<KeyValuePair<string, string>>?>(5) ?? [])
                        .ToDictionary(p => p.Key, p => p.Value)));
                    return Task.CompletedTask;
                });
            services.RemoveAll<IEventRepository>();
            services.AddSingleton(events);
        });
    }

    [Fact]
    public void SwitchOff_TheHostRegistersNoSecretHandler_SoTheGatewayAnswersHandlerNotAvailable()
    {
        using var scope = Factory.Services.CreateScope();
        scope.ServiceProvider.GetService<ClientAddSecretHandler>().Should().BeNull();
        scope.ServiceProvider.GetService<ClientRemoveSecretHandler>().Should().BeNull();
    }

    [Fact]
    public void SwitchOn_TheHostHostsBothHandlers()
    {
        using var scope = _enabled.Services.CreateScope();
        scope.ServiceProvider.GetService<ClientAddSecretHandler>().Should().NotBeNull();
        scope.ServiceProvider.GetService<ClientRemoveSecretHandler>().Should().NotBeNull();
    }

    [Fact]
    public async Task AddSecret_ReturnsTheSecretOnce_StoresOnlyTheHash_ClientAuthenticates_RemoveSecret_EndsIt()
    {
        var ct = TestContext.Current.CancellationToken;
        var client = await CreateConfidentialClientAsync();
        (await RequestTokenAsync(client.ClientId, "no-secret-yet", ct)).Should().Be(HttpStatusCode.Unauthorized);

        var added = await AddAsync(Admin(), client.RtId.ToString(), "ci pipeline", null, ct);

        added.IsSuccess.Should().BeTrue();
        var secret = added.Value!.Value!;
        secret.Should().NotBeNullOrWhiteSpace();
        Base64UrlLength(secret).Should().Be(32, "256 bit from the CSPRNG, as REST");
        var stored = (await FindAsync(client.ClientId)).ClientSecrets.Should().ContainSingle().Subject;
        stored.Value.Should().NotBe(secret).And.Be(Sha256Base64(secret), "only the hash is stored");
        stored.Description.Should().Be("ci pipeline");
        stored.Type.Should().Be("SharedSecret");
        (await RequestTokenAsync(client.ClientId, secret, ct)).Should().Be(HttpStatusCode.OK);
        (await RequestTokenAsync(client.ClientId, secret + "x", ct)).Should().Be(HttpStatusCode.Unauthorized);

        var removed = await RemoveAsync(Admin(), client.RtId.ToString(), secret, ct);

        removed.IsSuccess.Should().BeTrue();
        (await FindAsync(client.ClientId)).ClientSecrets.Should().BeEmpty();
        (await RequestTokenAsync(client.ClientId, secret, ct)).Should().Be(HttpStatusCode.Unauthorized,
            "authentication with a removed secret fails");

        var audits = Audits(client.RtId.ToString());
        audits.Should().HaveCount(2, "one audit record per call");
        audits.Should().OnlyContain(a => a.Details["outcome"] == "SUCCESS" &&
                                         a.Details["clientId"] == client.ClientId &&
                                         a.Details["callerSubject"] == AdminSubject);
        audits.Select(a => a.Details["methodId"]).Should().Equal(SystemIdentityCkIds.ClientAddSecretMethodId,
            SystemIdentityCkIds.ClientRemoveSecretMethodId);
        audits[1].Details["removedCount"].Should().Be("1");
        NoSecretAnywhere(secret);
        NoHashInAuditOrLogsAboveDebug(stored.Value!);
    }

    [Fact]
    public async Task RemoveSecret_ByTheStoredValue_AsTheListShowsIt_RemovesOnlyThatSecret()
    {
        var ct = TestContext.Current.CancellationToken;
        var client = await CreateConfidentialClientAsync();
        var first = (await AddAsync(Admin(), client.RtId.ToString(), null, null, ct)).Value!.Value!;
        var second = (await AddAsync(Admin(), client.RtId.ToString(), null, null, ct)).Value!.Value!;
        first.Should().NotBe(second);

        var outcome = await RemoveAsync(Admin(), client.RtId.ToString(), Sha256Base64(first), ct);

        outcome.IsSuccess.Should().BeTrue();
        (await FindAsync(client.ClientId)).ClientSecrets.Select(s => s.Value).Should().Equal(Sha256Base64(second));
        (await RequestTokenAsync(client.ClientId, first, ct)).Should().Be(HttpStatusCode.Unauthorized);
        (await RequestTokenAsync(client.ClientId, second, ct)).Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task UserManagement_MayAddSecretsToo_AsTheRestPolicyAllows()
    {
        var ct = TestContext.Current.CancellationToken;
        var client = await CreateConfidentialClientAsync();

        var outcome = await AddAsync(new CkMethodPrincipal(AdminSubject, ["UserManagement"], ["octo_api"]),
            client.RtId.ToString(), null, null, ct);

        outcome.IsSuccess.Should().BeTrue();
    }

    [Fact]
    public async Task ServiceToken_WithTheRole_AddsASecret_ActorIsTheClient()
    {
        var ct = TestContext.Current.CancellationToken;
        var client = await CreateConfidentialClientAsync();

        var outcome = await AddAsync(new CkMethodPrincipal(null, TenantAdminRoles, ["octo_api"], "svc-client"),
            client.RtId.ToString(), null, null, ct);

        outcome.IsSuccess.Should().BeTrue();
        Audits(client.RtId.ToString()).Single().Details["callerSubject"].Should().Be("svc-client");
    }

    public static TheoryData<string[], string[]> RefusedCallers => new()
    {
        { ["AdminPanelManagement"], ["octo_api"] },
        { [], ["octo_api"] },
        { ["TenantManagement"], ["octo_api.read_only"] },
        { ["UserManagement"], [] }
    };

    [Theory]
    [MemberData(nameof(RefusedCallers))]
    public async Task CallerWithoutRoleOrScope_IsForbidden_ForAnExistingAndAMissingTarget_Identically_AndChangesNothing(
        string[] roles, string[] scopes)
    {
        var ct = TestContext.Current.CancellationToken;
        var client = await CreateConfidentialClientAsync();
        var secret = (await AddAsync(Admin(), client.RtId.ToString(), null, null, ct)).Value!.Value!;
        var caller = new CkMethodPrincipal("507f1f77bcf86cd799439013", roles, scopes);

        var addExisting = await AddAsync(caller, client.RtId.ToString(), null, null, ct);
        var addMissing = await AddAsync(caller, "507f1f77bcf86cd799439011", null, null, ct);
        var removeExisting = await RemoveAsync(caller, client.RtId.ToString(), secret, ct);
        var removeMissing = await RemoveAsync(caller, "507f1f77bcf86cd799439011", secret, ct);

        addExisting.Failure!.Code.Should().Be("METHOD_FORBIDDEN");
        addMissing.Failure.Should().BeEquivalentTo(addExisting.Failure, "an unauthorized caller learns nothing");
        removeExisting.Failure!.Code.Should().Be("METHOD_FORBIDDEN");
        removeMissing.Failure.Should().BeEquivalentTo(removeExisting.Failure);
        (await FindAsync(client.ClientId)).ClientSecrets.Should().ContainSingle("a refused call changes nothing");
        (await RequestTokenAsync(client.ClientId, secret, ct)).Should().Be(HttpStatusCode.OK);
        _events.Count(e => e.Details["outcome"] == "METHOD_FORBIDDEN").Should().Be(4, "one audit record per call");
        NoSecretAnywhere(secret);
    }

    [Fact]
    public async Task NoPrincipal_IsForbidden()
    {
        var ct = TestContext.Current.CancellationToken;
        var client = await CreateConfidentialClientAsync();

        (await AddAsync(null, client.RtId.ToString(), null, null, ct)).Failure!.Code.Should().Be("METHOD_FORBIDDEN");
        (await RemoveAsync(null, client.RtId.ToString(), "x", ct)).Failure!.Code.Should().Be("METHOD_FORBIDDEN");
    }

    [Theory]
    [InlineData("507f1f77bcf86cd799439011")]
    [InlineData("not-an-object-id")]
    public async Task UnknownTarget_IsTargetNotFound_ForAnAuthorizedCaller(string target)
    {
        var ct = TestContext.Current.CancellationToken;

        (await AddAsync(Admin(), target, null, null, ct)).Failure!.Code.Should().Be("METHOD_TARGET_NOT_FOUND");
        (await RemoveAsync(Admin(), target, "x", ct)).Failure!.Code.Should().Be("METHOD_TARGET_NOT_FOUND");
        Audits(target).Should().HaveCount(2).And.OnlyContain(a => a.Details["outcome"] == "METHOD_TARGET_NOT_FOUND");
    }

    [Fact]
    public async Task PublicClient_IsRefused_WithClientSecretNotRequired_AndKeepsNoSecret()
    {
        var ct = TestContext.Current.CancellationToken;
        var client = await CreateClientAsync(b => b.WithGrantTypes("authorization_code").RequireClientSecret(false));

        var outcome = await AddAsync(Admin(), client.RtId.ToString(), null, null, ct);

        outcome.Failure!.Code.Should().Be(ClientSecretMethodErrors.ClientSecretNotRequired);
        (await FindAsync(client.ClientId)).ClientSecrets.Should().BeEmpty();
        Audits(client.RtId.ToString()).Single().Details["outcome"].Should().Be("CLIENT_SECRET_NOT_REQUIRED");
    }

    [Fact]
    public async Task ExpirationDate_IsStoredInUtc_AndAnExpirationInThePast_IsAValidationFailure()
    {
        var ct = TestContext.Current.CancellationToken;
        var client = await CreateConfidentialClientAsync();
        var expires = DateTime.UtcNow.AddDays(30);

        (await AddAsync(Admin(), client.RtId.ToString(), null, expires, ct)).IsSuccess.Should().BeTrue();
        var past = await AddAsync(Admin(), client.RtId.ToString(), null, DateTime.UtcNow.AddMinutes(-1), ct);

        (await FindAsync(client.ClientId)).ClientSecrets.Single().ExpirationDateTime.Should()
            .BeCloseTo(expires, TimeSpan.FromSeconds(1));
        past.Failure!.Code.Should().Be("METHOD_VALIDATION_FAILED");
        past.Failure.Parameters["field"].Should().Be("expirationDate");
    }

    [Fact]
    public async Task RemoveSecret_UnknownValue_IsSecretNotFound_WithoutEchoingTheValue()
    {
        var ct = TestContext.Current.CancellationToken;
        var client = await CreateConfidentialClientAsync();
        var kept = (await AddAsync(Admin(), client.RtId.ToString(), null, null, ct)).Value!.Value!;
        const string canary = "Canary-7780-not-a-secret-of-this-client";

        var outcome = await RemoveAsync(Admin(), client.RtId.ToString(), canary, ct);

        outcome.Failure!.Code.Should().Be(ClientSecretMethodErrors.SecretNotFound);
        outcome.Failure.Parameters.Should().BeEmpty();
        JsonSerializer.Serialize(outcome.Failure).Should().NotContain(canary);
        (await FindAsync(client.ClientId)).ClientSecrets.Should().ContainSingle();
        (await RequestTokenAsync(client.ClientId, kept, ct)).Should().Be(HttpStatusCode.OK);
        Audits(client.RtId.ToString()).Last().Details["removedCount"].Should().Be("0");
        NoSecretAnywhere(canary, kept);
        NoHashInAuditOrLogsAboveDebug(Sha256Base64(kept));
    }

    [Fact]
    public async Task WhenTheStoreFails_TheCallThrows_AndTheAuditStillRecordsTheFailure()
    {
        var ct = TestContext.Current.CancellationToken;
        var client = await CreateConfidentialClientAsync();
        var failing = _enabled.WithWebHostBuilder(b => b.ConfigureTestServices(services =>
        {
            var store = Substitute.For<IOctoClientStore>();
            store.UpdateAsync(Arg.Any<string>(), Arg.Any<RtClient>())
                .Returns(Task.FromException(new InvalidOperationException("store down")));
            services.RemoveAll<IOctoClientStore>();
            services.AddScoped(_ => store);
        }));

        var act = () => AddAsync(Admin(), client.RtId.ToString(), null, null, ct, failing);

        await act.Should().ThrowAsync<InvalidOperationException>();
        Audits(client.RtId.ToString()).Single().Details["outcome"].Should().Be("METHOD_HANDLER_FAILED");
        (await FindAsync(client.ClientId)).ClientSecrets.Should().BeEmpty();
    }

    [Fact]
    public async Task AForgedCaller_WithoutAValidToken_IsRejectedByTheHost_AndTheHandlerIsNotCalled()
    {
        var ct = TestContext.Current.CancellationToken;
        var client = await CreateConfidentialClientAsync();
        var invoker = _enabled.Services.GetRequiredService<ICkMethodHandlerInvoker>();
        var target = client.RtId.ToString();

        foreach (var methodId in new[]
                 {
                     SystemIdentityCkIds.ClientAddSecretMethodId, SystemIdentityCkIds.ClientRemoveSecretMethodId
                 })
        {
            foreach (var token in new string?[] { null, "" })
            {
                var response = await invoker.InvokeAsync(Request(methodId, target, token), ct);
                response.Success.Should().BeFalse();
                response.Error!.Code.Should().Be("METHOD_FORBIDDEN");
            }

            // The authority is not reachable in this test host, so a token cannot be validated and the host fails closed.
            foreach (var token in new[]
                     {
                         "not-a-jwt", "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4Iiwicm9sZSI6IlRlbmFudE1hbmFnZW1lbnQifQ."
                     })
            {
                var response = await invoker.InvokeAsync(Request(methodId, target, token), ct);
                response.Success.Should().BeFalse();
                response.Error!.Code.Should().BeOneOf("METHOD_FORBIDDEN", "METHOD_HANDLER_FAILED");
            }

            var forged = Request(methodId, target, "not-a-jwt") with
            {
                Caller = new CkMethodCaller { SubjectId = AdminSubject, Roles = ["TenantManagement"] }
            };
            (await invoker.InvokeAsync(forged, ct)).Success.Should().BeFalse();
        }

        (await FindAsync(client.ClientId)).ClientSecrets.Should().BeEmpty("nothing changed");
        _events.Should().BeEmpty("the handler was never called");
    }

    #region Helpers

    private const string AdminSubject = "507f1f77bcf86cd799439012";

    private static CkMethodPrincipal Admin() => new(AdminSubject, TenantAdminRoles, ["octo_api"]);

    private Task<RtClient> CreateConfidentialClientAsync() =>
        CreateClientAsync(b => b.WithGrantTypes("client_credentials").WithScopes(ApiScope).RequireClientSecret()
            .RequirePkce(false));

    private async Task<RtClient> CreateClientAsync(Action<RtClientBuilder> configure)
    {
        using var scope = _enabled.Services.CreateScope();
        var resourceStore = scope.ServiceProvider.GetRequiredService<IOctoResourceStore>();
        if (await resourceStore.GetApiScopeByNameAsync(ApiScope) == null)
        {
            await resourceStore.CreateApiScopeAsync(new RtApiScope
            {
                RtId = OctoObjectId.GenerateNewId(),
                Name = ApiScope,
                DisplayName = "Client secret method API",
                Enabled = true,
                ShowInDiscoveryDocument = true,
                Claims = new AttributeStringValueList(),
                IsEmphasized = false,
                IsRequired = false
            });
        }

        var builder = new RtClientBuilder().WithClientId($"m7780-{Guid.NewGuid():N}");
        configure(builder);
        var client = builder.Build();
        await scope.ServiceProvider.GetRequiredService<IOctoClientStore>().CreateAsync(client);
        return client;
    }

    private async Task<RtClient> FindAsync(string clientId)
    {
        using var scope = _enabled.Services.CreateScope();
        return (await scope.ServiceProvider.GetRequiredService<IOctoClientStore>().FindRtClientByIdAsync(clientId))!;
    }

    private async Task<HttpStatusCode> RequestTokenAsync(string clientId, string secret, CancellationToken ct)
    {
        using var http = _enabled.CreateClient();
        var response = await http.PostAsync("/connect/token", new FormUrlEncodedContent(
            new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = clientId,
                ["client_secret"] = secret,
                ["scope"] = ApiScope,
                ["acr_values"] = $"tenant:{NormalizedSystemTenantId}"
            }), ct);
        return response.StatusCode;
    }

    private async Task<CkMethodOutcome<ClientAddSecretResult>> AddAsync(CkMethodPrincipal? principal, string target,
        string? description, DateTime? expirationDate, CancellationToken ct,
        WebApplicationFactory<Program>? factory = null)
    {
        using var scope = (factory ?? _enabled).Services.CreateScope();
        var handler = ActivatorUtilities.CreateInstance<ClientAddSecretHandler>(scope.ServiceProvider);
        var context = new CkMethodContext<ClientAddSecretParameters>(
            Request(SystemIdentityCkIds.ClientAddSecretMethodId, target, null),
            new ClientAddSecretParameters { Description = description, ExpirationDate = expirationDate })
        {
            CallerPrincipal = principal
        };
        return await handler.HandleAsync(context, ct);
    }

    private async Task<CkMethodOutcome> RemoveAsync(CkMethodPrincipal? principal, string target, string secretValue,
        CancellationToken ct)
    {
        using var scope = _enabled.Services.CreateScope();
        var handler = ActivatorUtilities.CreateInstance<ClientRemoveSecretHandler>(scope.ServiceProvider);
        var context = new CkMethodContext<ClientRemoveSecretParameters>(
            Request(SystemIdentityCkIds.ClientRemoveSecretMethodId, target, null),
            new ClientRemoveSecretParameters { SecretValue = secretValue })
        {
            CallerPrincipal = principal
        };
        return await handler.HandleAsync(context, ct);
    }

    private CkMethodRequest Request(string methodId, string target, string? token) => new(NormalizedSystemTenantId)
    {
        InvocationId = Guid.NewGuid(),
        MethodId = methodId,
        CkTypeId = "System.Identity/Client",
        TargetRtId = target,
        DeadlineUtc = DateTime.UtcNow.AddSeconds(30),
        CallerAccessToken = token,
        ParametersJson = methodId == SystemIdentityCkIds.ClientRemoveSecretMethodId
            ? JsonSerializer.Serialize(new { secretValue = "forged-call-value" })
            : "{}"
    };

    private List<CapturedEvent> Audits(string target) =>
        _events.Where(e => e.Category == IdentityMethodAuditWriter.Category &&
                           e.Details.GetValueOrDefault("targetRtId") == target).ToList();

    /// <summary>The canary scan of this suite: none of the clear-text values in any audit event (message, details) or log line, any level.</summary>
    private void NoSecretAnywhere(params string[] values)
    {
        var audited = _events.SelectMany(e => e.Details.Values).Concat(_events.Select(e => e.Message)).ToList();
        foreach (var value in values)
        {
            audited.Should().NotContain(v => v.Contains(value));
            _logs.Messages.Should().NotContain(m => m.Text.Contains(value));
        }
    }

    /// <summary>
    ///     The stored hash is in no audit event and no log line at Information or above. The engine's MongoDB command log at
    ///     Debug (<c>MongoRepositoryClient</c>, off in every environment by default) renders the whole update command, so it
    ///     carries the stored hash of every client secret write, REST and method alike; that is not part of this handler.
    /// </summary>
    private void NoHashInAuditOrLogsAboveDebug(string hash)
    {
        _events.SelectMany(e => e.Details.Values).Concat(_events.Select(e => e.Message)).Should()
            .NotContain(v => v.Contains(hash));
        _logs.Messages.Where(m => m.Level >= LogLevel.Information).Should().NotContain(m => m.Text.Contains(hash));
    }

    private static string Sha256Base64(string value) =>
        Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    private static int Base64UrlLength(string value) =>
        Convert.FromBase64String(value.Replace('-', '+').Replace('_', '/').PadRight((value.Length + 3) / 4 * 4, '='))
            .Length;

    private sealed record CapturedEvent(string TenantId, string Message, string? Category,
        Dictionary<string, string> Details);

    private sealed class CapturingLoggerProvider : ILoggerProvider
    {
        public ConcurrentQueue<(LogLevel Level, string Text)> Messages { get; } = new();

        public ILogger CreateLogger(string categoryName) => new CapturingLogger(this);

        public void Dispose()
        {
        }

        private sealed class CapturingLogger(CapturingLoggerProvider owner) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
                Func<TState, Exception?, string> formatter)
                => owner.Messages.Enqueue((logLevel, formatter(state, exception) + exception));
        }
    }

    #endregion
}
