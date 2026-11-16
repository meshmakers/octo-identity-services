using System.Reflection;
using System.Security.Claims;
using System.Text.Json;
using IdentityServerPersistence.Services.ScratchTenants;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Backend.IdentityServices.Authorization.RoleChange;
using Meshmakers.Octo.Backend.IdentityServices.Methods;
using Meshmakers.Octo.Common.DistributionEventHub.Services;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.DataPermissions;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Methods;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Meshmakers.Octo.Services.Methods;
using Meshmakers.Octo.Services.Methods.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;

namespace IdentityServices.UnitTests.Controllers;

/// <summary>
///     The REST facades of <c>GroupsController</c> and <c>ClientsController</c> call their CK methods through
///     <see cref="IIdentityMethodFacade" />. For controller unit tests this facade runs the <b>real handler</b> directly with
///     the test's substitutes (stores, guard, event hub) and turns its outcome into the envelope the dispatcher would answer
///     (error code and parameters, result JSON in the wire form of <c>CkMethodResultShape</c>, an exception as
///     <c>METHOD_HANDLER_FAILED</c>). The declared authorization of the invocation core is not run here; the integration tests
///     cover the real dispatcher path.
/// </summary>
internal sealed class HandlerBackedMethodFacade : IIdentityMethodFacade
{
    private const string TenantId = "t1";

    private readonly Dictionary<OctoObjectId, RtClient> _clientsByRtId = new();

    public HandlerBackedMethodFacade(IOctoClientStore? clientStore = null, IClientRoleStore? clientRoleStore = null,
        RoleManager<RtRole>? roleManager = null, IRoleChangeGuard? guard = null,
        IDistributionEventHubService? eventHub = null, IGroupStore? groupStore = null,
        IScratchTenantGrantService? grantService = null, IMultiTenancyResolverService? tenantResolver = null)
    {
        var repository = Substitute.For<ITenantRepository>();
        repository.GetRtEntityByRtIdAsync<RtClient>(Arg.Any<IOctoSession>(), Arg.Any<OctoObjectId>())
            .Returns(call => _clientsByRtId.GetValueOrDefault(call.ArgAt<OctoObjectId>(1)));
        if (tenantResolver == null)
        {
            tenantResolver = Substitute.For<IMultiTenancyResolverService>();
            tenantResolver.GetTenantId().Returns(TenantId);
            tenantResolver.GetTenantRepository().Returns(repository);
        }

        var allowAll = Substitute.For<IRtDataPermissionEvaluator>();
        allowAll.EvaluateAsync(default!, default!, default, default, default, default).ReturnsForAnyArgs(
            new RtDataPermissionVerdict(RtDataPermissionDecision.Allowed, default));
        if (guard == null)
        {
            guard = Substitute.For<IRoleChangeGuard>();
            guard.EvaluateClientGrantAsync(default!, default!, default!, default).ReturnsForAnyArgs(RoleChangeDecision.Allowed);
            guard.EvaluateAsync(default!, default(RoleGraphChange)!, default).ReturnsForAnyArgs(RoleChangeDecision.Allowed);
        }

        Services = new ServiceCollection()
            .AddSingleton<IMethodTenantAccessor>(new BoundTenant())
            .AddSingleton(tenantResolver)
            .AddSingleton(clientStore ?? Substitute.For<IOctoClientStore>())
            .AddSingleton(clientRoleStore ?? Substitute.For<IClientRoleStore>())
            .AddSingleton(roleManager ?? Substitute.For<RoleManager<RtRole>>(Substitute.For<IRoleStore<RtRole>>(), null,
                null, null, null))
            .AddSingleton(guard)
            .AddSingleton(eventHub ?? Substitute.For<IDistributionEventHubService>())
            .AddSingleton(groupStore ?? Substitute.For<IGroupStore>())
            .AddSingleton(grantService ?? Substitute.For<IScratchTenantGrantService>())
            .AddSingleton(allowAll)
            .AddSingleton<IIdentityMethodAuditWriter>(Audit)
            .AddSingleton<ILoggerFactory>(NullLoggerFactory.Instance)
            .AddSingleton(typeof(ILogger<>), typeof(Logger<>))
            .BuildServiceProvider();
    }

    public IServiceProvider Services { get; }

    public RecordingAudit Audit { get; } = new();

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

        // The wire round trip of the parameters, as the dispatcher does it.
        var wireParameters = JsonSerializer.Deserialize<TParameters>(request.ParametersJson, CkMethodJson.Options)!;
        var context = new CkMethodContext<TParameters>(request, wireParameters)
        {
            // The caller as the facade maps it, with the roles and the scope the REST policy already required.
            CallerPrincipal = CkMethodPrincipal.FromClaimsPrincipal(user) with
            {
                Roles = ["TenantManagement", "UserManagement"], Scopes = ["octo_api"]
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
        catch (TargetInvocationException e) when (e.InnerException is not null)
        {
            return HandlerFailed(request);
        }
        catch (Exception)
        {
            return HandlerFailed(request);
        }
    }

    public Task<CkMethodResponse> InvokeForAccountOwnerAsync<TParameters>(string methodId, string userRtId,
        TParameters parameters, ClaimsPrincipal accountUser, CancellationToken cancellationToken) where TParameters : class =>
        throw new NotSupportedException();

    private object CreateHandler(string methodId) => methodId switch
    {
        _ when methodId == SystemIdentityCkIds.GroupSetRolesMethodId => new GroupSetRolesHandler(Services),
        _ when methodId == SystemIdentityCkIds.GroupAddMemberMethodId => new GroupAddMemberHandler(Services),
        _ when methodId == SystemIdentityCkIds.GroupRemoveMemberMethodId => new GroupRemoveMemberHandler(Services),
        _ when methodId == SystemIdentityCkIds.GroupAddChildGroupMethodId => new GroupAddChildGroupHandler(Services),
        _ when methodId == SystemIdentityCkIds.GroupRemoveChildGroupMethodId => new GroupRemoveChildGroupHandler(Services),
        _ when methodId == SystemIdentityCkIds.ClientSetRolesMethodId => new ClientSetRolesHandler(Services),
        _ when methodId == SystemIdentityCkIds.ClientAddRoleMethodId => new ClientAddRoleHandler(Services),
        _ when methodId == SystemIdentityCkIds.ClientRemoveRoleMethodId => new ClientRemoveRoleHandler(Services),
        _ when methodId == SystemIdentityCkIds.ClientApplyOverlayUrisMethodId => new ClientApplyOverlayUrisHandler(Services),
        _ when methodId == SystemIdentityCkIds.ClientCleanOverlayEntriesMethodId =>
            new ClientCleanOverlayEntriesHandler(Services),
        _ => throw new NotSupportedException(methodId)
    };

    private static CkMethodResponse Failed(CkMethodRequest request, CkMethodFailure failure) =>
        CkMethodResponse.Failed(request.InvocationId, "test",
            new CkMethodError { Code = failure.Code, Parameters = failure.Parameters });

    private static CkMethodResponse HandlerFailed(CkMethodRequest request) =>
        CkMethodResponse.Failed(request.InvocationId, "test",
            new CkMethodError { Code = CkMethodErrorCodes.MethodHandlerFailed });

    private sealed class BoundTenant : IMethodTenantAccessor
    {
        public ITenantRepository? TenantRepository => null;

        public Task<bool> BindAsync(string tenantId) => Task.FromResult(true);
    }

    /// <summary>The <c>Identity.Method</c> records the handlers wrote.</summary>
    internal sealed class RecordingAudit : IIdentityMethodAuditWriter
    {
        public List<(string MethodId, string? Target, string Outcome, IReadOnlyDictionary<string, string>? Details)>
            Records { get; } = [];

        public Task RecordAsync(string tenantId, string methodId, Guid invocationId, string? targetRtId,
            string? callerSubject, string outcome, IReadOnlyDictionary<string, string>? extraDetails = null)
        {
            Records.Add((methodId, targetRtId, outcome,
                extraDetails == null ? null : new Dictionary<string, string>(extraDetails)));
            return Task.CompletedTask;
        }
    }
}
