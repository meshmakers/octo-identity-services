using System.Reflection;
using System.Security.Claims;
using System.Text.Json;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.Services.SourceTenantGrants;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Backend.Authentication.DynamicAuth;
using Meshmakers.Octo.Backend.IdentityServices.Authorization;
using Meshmakers.Octo.Backend.IdentityServices.Authorization.RoleChange;
using Meshmakers.Octo.Backend.IdentityServices.CrossTenantAudit;
using Meshmakers.Octo.Backend.IdentityServices.Methods;
using Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;
using Meshmakers.Octo.Runtime.Contracts.DataPermissions;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Configuration;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Methods;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Meshmakers.Octo.Services.Methods;
using Meshmakers.Octo.Services.Methods.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;

namespace IdentityServices.IntegrationTests.Persistence;

/// <summary>
///     For the persistence tests that call <c>AdminProvisioningController</c> and <c>ExternalTenantUserMappingsController</c>
///     directly (no web host): the controllers are REST facades of the static <c>ExternalTenantUserMapping</c> methods, so
///     this facade runs the <b>real handler</b> of the method with the test's services (system context, ancestry guard,
///     stores) and returns the envelope the dispatcher would answer. The caller is admitted with the REST roles and the
///     <c>octo_api</c> scope; the target-tenant rule admits every target here (it has tests of its own:
///     <c>AdminProvisioningMethodFacadeTests</c>). The real dispatcher path is covered by the facade tests.
/// </summary>
internal sealed class ProvisioningMethodTestFacade : IIdentityMethodFacade
{
    private readonly string _tenantId;
    private readonly IServiceProvider _services;
    private readonly AllTargetsInScope _discovery = new();
    private readonly RecordingAudit _audit = new();

    public ProvisioningMethodTestFacade(ISystemContext systemContext,
        ICrossTenantAncestryGuard? ancestryGuard = null, ICrossTenantGrantAuditRecorder? grantAudit = null,
        IExternalTenantUserMappingStore? mappingStore = null, IGroupStore? groupStore = null,
        IRoleChangeGuard? roleChangeGuard = null, ISourceTenantGrantAdmission? grantAdmission = null,
        string? tenantId = null)
    {
        _tenantId = tenantId ?? systemContext.TenantId;
        if (roleChangeGuard == null)
        {
            roleChangeGuard = Substitute.For<IRoleChangeGuard>();
            roleChangeGuard.EvaluateAsync(default!, default(RoleGraphChange)!, default)
                .ReturnsForAnyArgs(RoleChangeDecision.Allowed);
        }

        var authorization = Substitute.For<IOptionsMonitor<IdentityApiAuthorizationOptions>>();
        authorization.CurrentValue.Returns(new IdentityApiAuthorizationOptions());
        // No data policy: the declaring type of the static methods is writable (the type check runs in the handlers).
        var dataPermissions = Substitute.For<IRtDataPermissionEvaluator>();
        dataPermissions.EvaluateTypeAsync(default!, default!, default!, default, default, default)
            .ReturnsForAnyArgs(new RtDataPermissionVerdict(RtDataPermissionDecision.Allowed, RtDataPermissionReason.NoGrant));
        _services = new ServiceCollection()
            .AddSingleton(systemContext)
            .AddSingleton<IDynamicAuthSchemeService>(new NoOpAuthSchemes())
            .AddSingleton<ICrossTenantShadowUserChainResolver>(new CrossTenantShadowUserChainResolver(systemContext))
            .AddSingleton(ancestryGuard ?? TestAncestryGuards.Create(systemContext))
            .AddSingleton(grantAudit ?? Substitute.For<ICrossTenantGrantAuditRecorder>())
            .AddSingleton(mappingStore ?? Substitute.For<IExternalTenantUserMappingStore>())
            .AddSingleton(groupStore ?? Substitute.For<IGroupStore>())
            .AddSingleton(roleChangeGuard)
            .AddSingleton(grantAdmission ?? Substitute.For<ISourceTenantGrantAdmission>())
            .AddSingleton<ITenantDiscoveryService>(_discovery)
            .AddSingleton(Options.Create(new OctoSystemConfiguration { SystemTenantId = systemContext.TenantId }))
            .AddSingleton(authorization)
            .AddSingleton(dataPermissions)
            .AddSingleton(Substitute.For<IMultiTenancyResolverService>())
            .AddSingleton<IMethodTenantAccessor>(new BoundTenant())
            .AddSingleton<IIdentityMethodAuditWriter>(_audit)
            .AddSingleton<ILoggerFactory>(NullLoggerFactory.Instance)
            .AddSingleton(typeof(ILogger<>), typeof(Logger<>))
            .BuildServiceProvider();
    }

    /// <summary>The <c>Identity.Method</c> records the handlers wrote (method id, outcome).</summary>
    public List<(string MethodId, string Outcome)> Audit => _audit.Records;


    /// <summary>The controller, wired to this facade, with <paramref name="user" /> as the HTTP user.</summary>
    public static AdminProvisioningController Controller(ISystemContext systemContext,
        ICrossTenantAncestryGuard? ancestryGuard = null, ICrossTenantGrantAuditRecorder? grantAudit = null,
        ClaimsPrincipal? user = null, HttpContext? httpContext = null)
    {
        var facade = new ProvisioningMethodTestFacade(systemContext, ancestryGuard, grantAudit);
        var context = httpContext ?? new DefaultHttpContext();
        context.User = user ?? context.User ?? new ClaimsPrincipal(new ClaimsIdentity());
        return new AdminProvisioningController(systemContext, ancestryGuard ?? TestAncestryGuards.Create(systemContext),
            facade)
        {
            ControllerContext = new ControllerContext { HttpContext = context }
        };
    }

    public async Task<CkMethodResponse> InvokeAsync<TParameters>(string ckTypeId, string methodId, string? targetRtId,
        TParameters parameters, ClaimsPrincipal user, CancellationToken cancellationToken) where TParameters : class
    {
        var request = new CkMethodRequest(_tenantId)
        {
            InvocationId = Guid.NewGuid(),
            MethodId = methodId,
            CkTypeId = ckTypeId,
            TargetRtId = targetRtId,
            ParametersJson = JsonSerializer.Serialize(parameters, CkMethodJson.Options),
            DeadlineUtc = DateTime.UtcNow.AddSeconds(60)
        };
        var wireParameters = JsonSerializer.Deserialize<TParameters>(request.ParametersJson, CkMethodJson.Options)!;
        foreach (var name in new[] { "TargetTenantId", "ChildTenantId" })
        {
            if (typeof(TParameters).GetProperty(name)?.GetValue(wireParameters) is string target)
            {
                _discovery.Admit(target);
            }
        }

        var mapped = CkMethodPrincipal.FromClaimsPrincipal(user);
        var context = new CkMethodContext<TParameters>(request, wireParameters)
        {
            CallerPrincipal = mapped with
            {
                Roles = ["TenantManagement", "UserManagement"],
                Scopes = ["octo_api"],
                TokenTenantId = mapped.TokenTenantId ?? _tenantId
            }
        };

        var handler = CreateHandler(methodId);
        try
        {
            if (handler is ICkMethodHandler<TParameters> plain)
            {
                var outcome = await plain.HandleAsync(context, cancellationToken);
                return outcome.Failure is { } failure
                    ? Failed(request, failure)
                    : CkMethodResponse.Succeeded(request.InvocationId, "test");
            }

            var typed = handler.GetType().GetInterfaces().Single(i =>
                i.IsGenericType && i.GetGenericTypeDefinition() == typeof(ICkMethodHandler<,>));
            var task = (Task)typed.GetMethod("HandleAsync")!.Invoke(handler, [context, cancellationToken])!;
            await task;
            var result = task.GetType().GetProperty("Result")!.GetValue(task)!;
            if (result.GetType().GetProperty("Failure")!.GetValue(result) is CkMethodFailure typedFailure)
            {
                return Failed(request, typedFailure);
            }

            var value = result.GetType().GetProperty("Value")!.GetValue(result);
            using var document = JsonSerializer.SerializeToDocument(value, value!.GetType(), CkMethodJson.Options);
            return CkMethodResponse.Succeeded(request.InvocationId, "test",
                document.RootElement.GetProperty("value").GetRawText());
        }
        catch (Exception e) when (e is TargetInvocationException or InvalidOperationException or ArgumentException)
        {
            return CkMethodResponse.Failed(request.InvocationId, "test",
                new CkMethodError { Code = CkMethodErrorCodes.MethodHandlerFailed });
        }
    }

    public Task<CkMethodResponse> InvokeForAccountOwnerAsync<TParameters>(string methodId, string userRtId,
        TParameters parameters, ClaimsPrincipal accountUser, CancellationToken cancellationToken) where TParameters : class =>
        throw new NotSupportedException();

    private object CreateHandler(string methodId) => methodId switch
    {
        _ when methodId == SystemIdentityCkIds.ExternalTenantUserMappingProvisionAdminMethodId =>
            new ExternalTenantUserMappingProvisionAdminHandler(_services),
        _ when methodId == SystemIdentityCkIds.ExternalTenantUserMappingProvisionAdminWithGroupsMethodId =>
            new ExternalTenantUserMappingProvisionAdminWithGroupsHandler(_services),
        _ when methodId == SystemIdentityCkIds.ExternalTenantUserMappingProvisionCurrentUserMethodId =>
            new ExternalTenantUserMappingProvisionCurrentUserHandler(_services),
        _ when methodId == SystemIdentityCkIds.ExternalTenantUserMappingRemoveAdminProvisioningMethodId =>
            new ExternalTenantUserMappingRemoveAdminProvisioningHandler(_services),
        _ when methodId == SystemIdentityCkIds.ExternalTenantUserMappingCreateMappingMethodId =>
            new ExternalTenantUserMappingCreateMappingHandler(_services),
        _ => throw new NotSupportedException(methodId)
    };

    private static CkMethodResponse Failed(CkMethodRequest request, CkMethodFailure failure) =>
        CkMethodResponse.Failed(request.InvocationId, "test",
            new CkMethodError { Code = failure.Code, Parameters = failure.Parameters });

    private sealed class BoundTenant : IMethodTenantAccessor
    {
        public Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories.ITenantRepository? TenantRepository => null;

        public Task<bool> BindAsync(string tenantId) => Task.FromResult(true);
    }

    private sealed class NoOpAuthSchemes : IDynamicAuthSchemeService
    {
        public Task ConfigureAsync(string tenantId) => Task.CompletedTask;
    }

    /// <summary>Admits every target the harness saw in a call's parameters (the scope rule is tested elsewhere).</summary>
    private sealed class AllTargetsInScope : ITenantDiscoveryService
    {
        private readonly HashSet<string> _targets = new(StringComparer.OrdinalIgnoreCase);

        public void Admit(string target)
        {
            lock (_targets)
            {
                _targets.Add(target);
            }
        }

        public Task<IReadOnlySet<string>?> GetScopeDescendantsAsync(string scopeTenantId)
        {
            lock (_targets)
            {
                return Task.FromResult<IReadOnlySet<string>?>(
                    new HashSet<string>(_targets, StringComparer.OrdinalIgnoreCase));
            }
        }

        public Task<IReadOnlyList<string>> FindTenantsForUserAsync(string emailOrUsername, string? scopeTenantId = null) =>
            Task.FromResult<IReadOnlyList<string>>([]);
    }

    private sealed class RecordingAudit : IIdentityMethodAuditWriter
    {
        public List<(string MethodId, string Outcome)> Records { get; } = [];

        public Task RecordAsync(string tenantId, string methodId, Guid invocationId, string? targetRtId,
            string? callerSubject, string outcome, IReadOnlyDictionary<string, string>? extraDetails = null)
        {
            lock (Records)
            {
                Records.Add((methodId, outcome));
            }

            return Task.CompletedTask;
        }
    }
}
