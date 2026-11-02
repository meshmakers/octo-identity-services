using System.Net;
using System.Text.Json;
using FluentAssertions;
using IdentityServerPersistence.SystemStores;
using IdentityServices.IntegrationTests.Infrastructure;
using Meshmakers.Octo.Backend.IdentityServices.Methods;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.DataPermissions;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Methods;
using Meshmakers.Octo.Services.Methods;
using Meshmakers.Octo.Services.Methods.Authorization;
using Meshmakers.Octo.Services.Methods.Handlers;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.Methods;

/// <summary>
///     AB#7779: <c>DataPermission.GrantToRole</c> and <c>DataPermission.RevokeFromRole</c> served by the identity service, and
///     their parity with <c>POST/DELETE system/v1/dataPermissions/{permissionId}/roles/{roleName}</c> of
///     <c>DataPermissionsController</c>.
/// </summary>
public class DataPermissionMethodTests(CustomWebApplicationFactory factory) : GroupMethodTestBase(factory)
{
    private const string Type = "System.Identity/DataPermission";

    [Fact]
    public void TheDataPermissionHandlers_AreHosted_WithTheDefaultConfiguration()
    {
        using var scope = Host.Services.CreateScope();

        scope.ServiceProvider.GetService<DataPermissionGrantToRoleHandler>().Should().NotBeNull();
        scope.ServiceProvider.GetService<DataPermissionRevokeFromRoleHandler>().Should().NotBeNull();
    }

    #region Grant and revoke

    [Fact]
    public async Task GrantToRole_StoresTheGrant_ByRoleNameCaseInsensitive_AndRevokeRemovesIt()
    {
        var (id, permissionId) = await NewPermissionAsync();
        var role = await NewRoleAsync();

        (await GrantAsync(id, Admin(), role.ToUpperInvariant())).IsSuccess.Should().BeTrue();
        (await GrantedAsync(id)).Should().ContainSingle().Which.Should().BeEquivalentTo(role);

        (await RevokeAsync(id, Admin(), role.ToLowerInvariant())).IsSuccess.Should().BeTrue();
        (await GrantedAsync(id)).Should().BeEmpty();
        permissionId.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task GrantToRole_Twice_IsPermissionAlreadyGranted_AndRevokeWithoutGrant_IsPermissionNotGranted()
    {
        var (id, _) = await NewPermissionAsync();
        var role = await NewRoleAsync();

        (await RevokeAsync(id, Admin(), role)).Failure!.Code.Should().Be("PERMISSION_NOT_GRANTED");
        (await GrantAsync(id, Admin(), role)).IsSuccess.Should().BeTrue();
        (await GrantAsync(id, Admin(), role)).Failure!.Code.Should().Be("PERMISSION_ALREADY_GRANTED");

        (await GrantedAsync(id)).Should().ContainSingle();
    }

    [Fact]
    public async Task AnUnknownRole_IsRoleNotFound_ForBothMethods()
    {
        var (id, _) = await NewPermissionAsync();

        var grant = await GrantAsync(id, Admin(), "NoSuchRole");
        var revoke = await RevokeAsync(id, Admin(), "NoSuchRole");

        grant.Failure!.Code.Should().Be("ROLE_NOT_FOUND");
        grant.Failure.Parameters.Should().Contain("roleName", "NoSuchRole");
        revoke.Failure!.Code.Should().Be("ROLE_NOT_FOUND");
        (await GrantAsync(id, Admin(), "")).Failure!.Code.Should().Be("ROLE_NOT_FOUND");
    }

    [Fact]
    public async Task AMissingPermission_IsTargetNotFound_ForBothMethods()
    {
        var missing = OctoObjectId.GenerateNewId().ToString();
        var role = await NewRoleAsync();

        (await GrantAsync(missing, Admin(), role)).Failure!.Code.Should().Be("METHOD_TARGET_NOT_FOUND");
        (await RevokeAsync(missing, Admin(), role)).Failure!.Code.Should().Be("METHOD_TARGET_NOT_FOUND");
        (await GrantAsync("not-an-id", Admin(), role)).Failure!.Code.Should().Be("METHOD_TARGET_NOT_FOUND");
    }

    #endregion

    #region Caller guards

    public static TheoryData<string, CkMethodPrincipal?> RefusedCallers => new()
    {
        { "no principal", null },
        { "no role", new CkMethodPrincipal("someone", [], ["octo_api"]) },
        { "another administrative role", new CkMethodPrincipal("someone", ["TenantManagement"], ["octo_api"]) },
        { "UserManagement without the scope", new CkMethodPrincipal("someone", [UserManagement], []) },
        { "UserManagement with the read-only scope", new CkMethodPrincipal("someone", [UserManagement], ["octo_api.read_only"]) }
    };

    [Theory]
    [MemberData(nameof(RefusedCallers))]
    public async Task EveryMethod_RefusesACallerThatTheRestPolicyWouldRefuse_AndChangesNothing(string caller,
        CkMethodPrincipal? principal)
    {
        var (id, _) = await NewPermissionAsync();
        var granted = await NewRoleAsync();
        var other = await NewRoleAsync();
        await GrantViaStoreAsync(id, granted);

        var results = new[] { await GrantAsync(id, principal, other), await RevokeAsync(id, principal, granted) };

        foreach (var outcome in results)
        {
            outcome.Failure!.Code.Should().Be("METHOD_FORBIDDEN", caller);
            outcome.Failure.Parameters.Should().Contain("reason", "role-required");
        }

        (await GrantedAsync(id)).Should().ContainSingle().Which.Should().BeEquivalentTo(granted);
    }

    [Fact]
    public async Task AForgedCaller_WithoutAValidToken_IsRejectedByTheHost_AndTheHandlerIsNotCalled()
    {
        var ct = TestContext.Current.CancellationToken;
        var (id, _) = await NewPermissionAsync();
        var role = await NewRoleAsync();
        var invoker = Host.Services.GetRequiredService<ICkMethodHandlerInvoker>();

        foreach (var methodId in new[]
                 {
                     SystemIdentityCkIds.DataPermissionGrantToRoleMethodId,
                     SystemIdentityCkIds.DataPermissionRevokeFromRoleMethodId
                 })
        {
            foreach (var token in new string?[] { null, "", "not-a-jwt", "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0." })
            {
                var request = Request(methodId, Type, id, token, JsonSerializer.Serialize(new { roleName = role })) with
                {
                    Caller = new CkMethodCaller { SubjectId = "admin", Roles = [UserManagement] }
                };

                var response = await invoker.InvokeAsync(request, ct);

                response.Success.Should().BeFalse(methodId);
                response.Error!.Code.Should().BeOneOf("METHOD_FORBIDDEN", "METHOD_HANDLER_FAILED");
            }
        }

        (await GrantedAsync(id)).Should().BeEmpty();
    }

    #endregion

    #region Parity with REST

    [Fact]
    public async Task Parity_GrantAndRevoke_LeaveTheSameAssociations()
    {
        var (restId, restPermission) = await NewPermissionAsync();
        var (methodId, _) = await NewPermissionAsync();
        var role = await NewRoleAsync();

        (await RestPostAsync(Caller(Guid.NewGuid().ToString("N")), $"dataPermissions/{restPermission}/roles/{role}"))
            .StatusCode.Should().Be(HttpStatusCode.OK);
        (await GrantAsync(methodId, Admin(), role)).IsSuccess.Should().BeTrue();
        (await GrantedAsync(restId)).Should().BeEquivalentTo(await GrantedAsync(methodId)).And.ContainSingle();

        (await RestDeleteAsync(Caller(Guid.NewGuid().ToString("N")), $"dataPermissions/{restPermission}/roles/{role}"))
            .StatusCode.Should().Be(HttpStatusCode.OK);
        (await RevokeAsync(methodId, Admin(), role)).IsSuccess.Should().BeTrue();
        (await GrantedAsync(restId)).Should().BeEmpty();
        (await GrantedAsync(methodId)).Should().BeEmpty();
    }

    [Fact]
    public async Task Parity_TheCallerRules_AreTheSame_NoRole_ReadOnlyScope_ServiceClient()
    {
        var (restId, restPermission) = await NewPermissionAsync();
        var (methodId, _) = await NewPermissionAsync();
        var role = await NewRoleAsync();
        var path = $"dataPermissions/{restPermission}/roles/{role}";

        (await RestPostAsync(Caller("c", "TenantManagement"), path)).StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await GrantAsync(methodId, new CkMethodPrincipal("c", ["TenantManagement"], ["octo_api"]), role)).Failure!.Code
            .Should().Be("METHOD_FORBIDDEN");

        (await RestPostAsync(Caller("c", UserManagement) with { Scopes = ["octo_api.read_only"] }, path)).StatusCode
            .Should().Be(HttpStatusCode.Forbidden);
        (await GrantAsync(methodId, new CkMethodPrincipal("c", [UserManagement], ["octo_api.read_only"]), role)).Failure!
            .Code.Should().Be("METHOD_FORBIDDEN");

        (await GrantedAsync(restId)).Should().BeEmpty();
        (await GrantedAsync(methodId)).Should().BeEmpty();
    }

    [Fact]
    public async Task Parity_NoRoleChangeGuard_RestAndMethod_BothGrantADataPermissionToTheCallersOwnRole()
    {
        // Data permissions grant data access, not roles: REST has no role change guard for them, and the methods add none.
        var (restId, restPermission) = await NewPermissionAsync();
        var (methodId, _) = await NewPermissionAsync();
        var builtIn = await NewRoleAsync(builtIn: true); // a built-in role the caller does not hold

        (await RestPostAsync(Caller(Guid.NewGuid().ToString("N")), $"dataPermissions/{restPermission}/roles/{builtIn}"))
            .StatusCode.Should().Be(HttpStatusCode.OK);
        (await GrantAsync(methodId, Admin(), builtIn)).IsSuccess.Should().BeTrue();

        (await GrantedAsync(restId)).Should().BeEquivalentTo(await GrantedAsync(methodId));
    }

    #endregion

    #region Audit

    [Fact]
    public async Task EveryCall_WritesOneAuditEvent_WithActorTargetOutcomePermissionAndRole()
    {
        var (id, permissionId) = await NewPermissionAsync();
        var role = await NewRoleAsync();
        var actor = Guid.NewGuid().ToString("N");
        var principal = new CkMethodPrincipal(actor, [UserManagement], ["octo_api"]);
        var before = AuditEvents().Count;

        await GrantAsync(id, principal, role); // success
        await GrantAsync(id, principal, role); // PERMISSION_ALREADY_GRANTED
        await RevokeAsync(id, new CkMethodPrincipal(actor, [], ["octo_api"]), role); // METHOD_FORBIDDEN

        var written = AuditEvents().Where(e => e.Details["callerSubject"] == actor).ToList();
        AuditEvents().Count.Should().Be(before + 3, "one event per call, success and refusal alike");
        written.Select(e => e.Details["outcome"]).Should()
            .Equal("SUCCESS", "PERMISSION_ALREADY_GRANTED", "METHOD_FORBIDDEN");
        written.Should().OnlyContain(e => e.Details["targetRtId"] == id);
        written[0].Details.Should().Contain("permissionId", permissionId).And.Contain("roleName", role);
        written[0].Level.Should().Be("Information");
        written[1].Level.Should().Be("Warning");
        written[2].Details.Should().NotContainKey("roleName", "a refused caller does not get as far as the role");
        written.Select(e => e.Details["methodId"]).Should().Equal(SystemIdentityCkIds.DataPermissionGrantToRoleMethodId,
            SystemIdentityCkIds.DataPermissionGrantToRoleMethodId, SystemIdentityCkIds.DataPermissionRevokeFromRoleMethodId);
    }

    #endregion

    #region The referenced role is checked with the data-permission API (AB#7035)

    [Fact]
    public async Task ARoleThatTheCallerCannotRead_IsRoleNotFound()
    {
        using var host = HostWithEvaluator(Verdict(RtDataAction.Read, RtDataPermissionDecision.NotVisible));
        var (id, _) = await NewPermissionAsync();
        var role = await NewRoleAsync();

        var outcome = await InvokeOnAsync(host, id, Admin(), role);

        outcome.Failure!.Code.Should().Be("ROLE_NOT_FOUND");
        (await GrantedAsync(id)).Should().BeEmpty();
    }

    [Fact]
    public async Task ARoleThatTheCallerCannotWrite_IsRefused_DataPermission_AndNothingIsGranted()
    {
        using var host = HostWithEvaluator(Verdict(RtDataAction.Write, RtDataPermissionDecision.NotPermitted));
        var (id, _) = await NewPermissionAsync();
        var role = await NewRoleAsync();

        var outcome = await InvokeOnAsync(host, id, Admin(), role);

        outcome.Failure!.Code.Should().Be("METHOD_FORBIDDEN");
        outcome.Failure.Parameters.Should().Contain("reason", "data-permission");
        (await GrantedAsync(id)).Should().BeEmpty();
    }

    private WebApplicationFactoryHost HostWithEvaluator(Func<RtDataAction, RtDataPermissionVerdict> verdict)
    {
        var evaluator = Substitute.For<IRtDataPermissionEvaluator>();
        evaluator.EvaluateAsync(Arg.Any<IRuntimeRepository>(), Arg.Any<RtSecurityContext>(), Arg.Any<RtEntityId>(),
                Arg.Any<RtDataAction>(), Arg.Any<bool>(), Arg.Any<CancellationToken>())
            .Returns(call => verdict(call.ArgAt<RtDataAction>(3)));
        return new WebApplicationFactoryHost(Host.WithWebHostBuilder(b =>
            b.ConfigureTestServices(s => s.AddSingleton(evaluator))));
    }

    private static Func<RtDataAction, RtDataPermissionVerdict> Verdict(RtDataAction denied,
        RtDataPermissionDecision decision) =>
        action => action == denied
            ? new RtDataPermissionVerdict(decision, RtDataPermissionReason.NoGrant)
            : new RtDataPermissionVerdict(RtDataPermissionDecision.Allowed, RtDataPermissionReason.Open);

    private sealed class WebApplicationFactoryHost(Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactory<Program> host)
        : IDisposable
    {
        public IServiceProvider Services => host.Services;

        public void Dispose() => host.Dispose();
    }

    private async Task<CkMethodOutcome> InvokeOnAsync(WebApplicationFactoryHost host, string target,
        CkMethodPrincipal principal, string role)
    {
        using var scope = host.Services.CreateScope();
        var handler = ActivatorUtilities.CreateInstance<DataPermissionGrantToRoleHandler>(scope.ServiceProvider);
        var context = new CkMethodContext<DataPermissionGrantToRoleParameters>(
            Request(SystemIdentityCkIds.DataPermissionGrantToRoleMethodId, Type, target, null, "{}"),
            new DataPermissionGrantToRoleParameters { RoleName = role }) { CallerPrincipal = principal };
        return await handler.HandleAsync(context, TestContext.Current.CancellationToken);
    }

    #endregion

    #region Helpers

    private async Task<(string RtId, string PermissionId)> NewPermissionAsync()
    {
        var permissionId = NewName("dp7779");
        using var scope = CreateScope();
        var id = await scope.ServiceProvider.GetRequiredService<IDataPermissionStore>().CreateAsync(permissionId, null);
        return (id.ToString(), permissionId);
    }

    private async Task GrantViaStoreAsync(string rtId, string roleName)
    {
        using var scope = CreateScope();
        var store = scope.ServiceProvider.GetRequiredService<IDataPermissionStore>();
        var permission = (await store.GetAllAsync()).Single(p => p.RtId.ToString() == rtId);
        await store.GrantToRoleAsync(permission.PermissionId!, roleName);
    }

    private async Task<string[]> GrantedAsync(string rtId)
    {
        using var scope = CreateScope();
        return (await scope.ServiceProvider.GetRequiredService<IDataPermissionStore>()
            .GetGrantedRoleNamesAsync(new OctoObjectId(rtId))).ToArray();
    }

    private Task<CkMethodOutcome> GrantAsync(string target, CkMethodPrincipal? principal, string role) =>
        InvokeAsync<DataPermissionGrantToRoleHandler, DataPermissionGrantToRoleParameters>(
            SystemIdentityCkIds.DataPermissionGrantToRoleMethodId, Type, target, principal,
            new DataPermissionGrantToRoleParameters { RoleName = role });

    private Task<CkMethodOutcome> RevokeAsync(string target, CkMethodPrincipal? principal, string role) =>
        InvokeAsync<DataPermissionRevokeFromRoleHandler, DataPermissionRevokeFromRoleParameters>(
            SystemIdentityCkIds.DataPermissionRevokeFromRoleMethodId, Type, target, principal,
            new DataPermissionRevokeFromRoleParameters { RoleName = role });

    #endregion
}
