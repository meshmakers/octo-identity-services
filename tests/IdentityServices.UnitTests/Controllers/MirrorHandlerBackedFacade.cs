using System.Reflection;
using System.Security.Claims;
using System.Text.Json;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Backend.IdentityServices.Authorization;
using Meshmakers.Octo.Backend.IdentityServices.Methods;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.DataPermissions;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Configuration;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Methods;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Meshmakers.Octo.Services.Methods;
using Meshmakers.Octo.Services.Methods.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;

namespace IdentityServices.UnitTests.Controllers;

/// <summary>
///     The mirror endpoints of <c>ClientMirrorController</c> and <c>ClientAutoProvisionFlagController</c> are REST facades of
///     the <c>Client.*Mirror*</c> methods. For the controller unit tests this facade runs the <b>real mirror handler</b> with
///     the test's substitutes (client store, mirror service) and turns its outcome into the envelope the dispatcher would
///     answer. The caller holds the REST roles and the token tenant is the system tenant, so the target-tenant rule admits
///     every child here; the service's own subtree refusal (<see cref="ClientMirrorScopeException" />) still applies. The
///     declared authorization and the real dispatcher path are covered by the integration tests.
/// </summary>
internal sealed class MirrorHandlerBackedFacade : IIdentityMethodFacade
{
    /// <summary>The tenant of the calls, which is also the system tenant here.</summary>
    public const string TenantId = "octosystem";

    private readonly Dictionary<OctoObjectId, RtClient> _clientsByRtId = new();

    public MirrorHandlerBackedFacade(IOctoClientStore clientStore, IClientMirrorProvisioningService mirrorService)
    {
        var repository = Substitute.For<ITenantRepository>();
        repository.GetRtEntityByRtIdAsync<RtClient>(Arg.Any<IOctoSession>(), Arg.Any<OctoObjectId>())
            .Returns(call => _clientsByRtId.GetValueOrDefault(call.ArgAt<OctoObjectId>(1)));
        var tenantResolver = Substitute.For<IMultiTenancyResolverService>();
        tenantResolver.GetTenantId().Returns(TenantId);
        tenantResolver.GetTenantRepository().Returns(repository);
        var allowAll = Substitute.For<IRtDataPermissionEvaluator>();
        allowAll.EvaluateAsync(default!, default!, default, default, default, default).ReturnsForAnyArgs(
            new RtDataPermissionVerdict(RtDataPermissionDecision.Allowed, default));
        var authorization = Substitute.For<IOptionsMonitor<IdentityApiAuthorizationOptions>>();
        authorization.CurrentValue.Returns(new IdentityApiAuthorizationOptions());

        Services = new ServiceCollection()
            .AddSingleton<IMethodTenantAccessor>(new BoundTenant())
            .AddSingleton(tenantResolver)
            .AddSingleton(clientStore)
            .AddSingleton(mirrorService)
            .AddSingleton(allowAll)
            .AddSingleton(Substitute.For<ITenantDiscoveryService>())
            .AddSingleton(Options.Create(new OctoSystemConfiguration { SystemTenantId = TenantId }))
            .AddSingleton(authorization)
            .AddSingleton<IIdentityMethodAuditWriter>(Audit)
            .AddSingleton<ILoggerFactory>(NullLoggerFactory.Instance)
            .AddSingleton(typeof(ILogger<>), typeof(Logger<>))
            .BuildServiceProvider();
    }

    public IServiceProvider Services { get; }

    public HandlerBackedMethodFacade.RecordingAudit Audit { get; } = new();

    /// <summary>Makes <paramref name="client" /> visible to the handlers by its rtId (the method target).</summary>
    public RtClient Know(RtClient client)
    {
        if (client.RtId == OctoObjectId.Empty)
        {
            client.RtId = OctoObjectId.GenerateNewId();
        }

        _clientsByRtId[client.RtId] = client;
        return client;
    }

    public async Task<CkMethodResponse> InvokeAsync<TParameters>(string ckTypeId, string methodId, string? targetRtId,
        TParameters parameters, ClaimsPrincipal user, CancellationToken cancellationToken) where TParameters : class
    {
        var request = new CkMethodRequest(TenantId)
        {
            InvocationId = Guid.NewGuid(),
            MethodId = methodId,
            CkTypeId = ckTypeId,
            TargetRtId = targetRtId,
            ParametersJson = JsonSerializer.Serialize(parameters, CkMethodJson.Options),
            DeadlineUtc = DateTime.UtcNow.AddSeconds(30)
        };
        var wireParameters = JsonSerializer.Deserialize<TParameters>(request.ParametersJson, CkMethodJson.Options)!;
        var context = new CkMethodContext<TParameters>(request, wireParameters)
        {
            CallerPrincipal = CkMethodPrincipal.FromClaimsPrincipal(user) with
            {
                Roles = ["TenantManagement", "UserManagement", "SecretManagement"],
                Scopes = ["octo_api"],
                TokenTenantId = TenantId
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
        catch (Exception e) when (e is TargetInvocationException or InvalidOperationException)
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
        _ when methodId == SystemIdentityCkIds.ClientProvisionMirrorsMethodId => new ClientProvisionMirrorsHandler(Services),
        _ when methodId == SystemIdentityCkIds.ClientProvisionMirrorInTenantMethodId =>
            new ClientProvisionMirrorInTenantHandler(Services),
        _ when methodId == SystemIdentityCkIds.ClientRotateMirrorSecretMethodId =>
            new ClientRotateMirrorSecretHandler(Services),
        _ when methodId == SystemIdentityCkIds.ClientRemoveMirrorMethodId => new ClientRemoveMirrorHandler(Services),
        _ when methodId == SystemIdentityCkIds.ClientSetMirrorAutoProvisionMethodId =>
            new ClientSetMirrorAutoProvisionHandler(Services),
        _ => throw new NotSupportedException(methodId)
    };

    private static CkMethodResponse Failed(CkMethodRequest request, CkMethodFailure failure) =>
        CkMethodResponse.Failed(request.InvocationId, "test",
            new CkMethodError { Code = failure.Code, Parameters = failure.Parameters });

    private sealed class BoundTenant : IMethodTenantAccessor
    {
        public ITenantRepository? TenantRepository => null;

        public Task<bool> BindAsync(string tenantId) => Task.FromResult(true);
    }
}
