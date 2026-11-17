using System.Net;
using System.Net.Http.Json;
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
using Meshmakers.Octo.Services.Infrastructure.Services;
using Meshmakers.Octo.Services.Methods;
using Meshmakers.Octo.Services.Methods.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.TenantApi;

/// <summary>
///     AB#9039: <c>POST/DELETE dataPermissions/{permissionId}/roles/{roleName}</c> and
///     <c>PUT dataPermissions/policies/{policyRtId}/enforcementMode</c> are facades of <c>DataPermission.GrantToRole</c>,
///     <c>DataPermission.RevokeFromRole</c> and the new <c>DataPolicy.SetEnforcementMode</c>. Real MongoDB, real identity host.
///     The grant and revoke parity of the end state stays covered by <c>DataPermissionMethodTests</c>; these tests prove that
///     every endpoint runs its method in-process outside the request with one <c>Identity.Method</c> event, that switching a
///     policy to Enforce over REST and over the method gives the same (fail-closed) read result, the REST answers of today,
///     the abuse cases and the data permission of the referenced role (CWE-863).
/// </summary>
public class DataPermissionRestMethodFacadeTests : IntegrationTestBase, IDisposable
{
    private const string UserManagement = "UserManagement";

    private readonly FacadeAuditCapture _audit = new();
    private readonly RequestStateProbe _probe = new();
    private readonly List<WebApplicationFactory<Program>> _hosts = [];

    public DataPermissionRestMethodFacadeTests(CustomWebApplicationFactory factory) : base(factory)
    {
    }

    public void Dispose()
    {
        foreach (var host in _hosts)
        {
            host.Dispose();
        }
    }

    #region REST runs the method

    [Fact]
    public async Task EveryEndpoint_RunsItsMethodInProcess_OutsideTheRequest_WithExactlyOneIdentityMethodEvent()
    {
        var host = Host();
        var (permissionRtId, permissionId) = await NewPermissionAsync();
        var policyRtId = await NewPolicyAsync(permissionId, "System/BlueprintBackup", "AuditOnly");
        var role = await NewRoleAsync();
        var caller = FacadeCaller.User(UserManagement);
        using var http = caller.Client(host);
        var ct = TestContext.Current.CancellationToken;

        (await http.PostAsync(TenantApiUrl($"dataPermissions/{permissionId}/roles/{role}"), null, ct)).StatusCode.Should()
            .Be(HttpStatusCode.OK);
        (await http.DeleteAsync(TenantApiUrl($"dataPermissions/{permissionId}/roles/{role}"), ct)).StatusCode.Should()
            .Be(HttpStatusCode.OK);
        (await http.PutAsJsonAsync(TenantApiUrl($"dataPermissions/policies/{policyRtId}/enforcementMode"), "AuditOnly", ct))
            .StatusCode.Should().Be(HttpStatusCode.OK);

        foreach (var (methodId, target) in new[]
                 {
                     (SystemIdentityCkIds.DataPermissionGrantToRoleMethodId, permissionRtId),
                     (SystemIdentityCkIds.DataPermissionRevokeFromRoleMethodId, permissionRtId),
                     (SystemIdentityCkIds.DataPolicySetEnforcementModeMethodId, policyRtId)
                 })
        {
            var events = _audit.For(methodId, target);
            events.Should().ContainSingle(methodId);
            events[0]["outcome"].Should().Be("SUCCESS");
            events[0]["callerSubject"].Should().Be(caller.Subject);
        }

        _probe.Calls.Should().Be(3, "every REST call ran its method through the in-process transport");
        _probe.Violations.Should().Be(0, "the facade opens no request state (session, transaction) around the call");
    }

    #endregion

    #region Enforcement mode

    [Fact]
    public async Task SwitchingToEnforce_OverRestAndOverTheMethod_GivesTheSameFailClosedReadResult()
    {
        var host = Host();
        var (_, restPermission) = await NewPermissionAsync();
        var (_, methodPermission) = await NewPermissionAsync();
        const string restType = "System/BlueprintBackup";
        const string methodType = "System/BlueprintHistory";
        var restPolicy = await NewPolicyAsync(restPermission, restType, "AuditOnly");
        var methodPolicy = await NewPolicyAsync(methodPermission, methodType, "AuditOnly");
        try
        {
            // AuditOnly: a caller without the grant still reads (the violation is only logged)
            (await ReadVerdictAsync(host, restType)).Should().Be(RtDataPermissionDecision.Allowed);
            (await ReadVerdictAsync(host, methodType)).Should().Be(RtDataPermissionDecision.Allowed);

            using var http = FacadeCaller.User(UserManagement).Client(host);
            (await http.PutAsJsonAsync(TenantApiUrl($"dataPermissions/policies/{restPolicy}/enforcementMode"), "Enforce",
                TestContext.Current.CancellationToken)).StatusCode.Should().Be(HttpStatusCode.OK);
            (await DispatchAsync(host, Admin(), SystemIdentityCkIds.DataPolicySetEnforcementModeMethodId,
                    IdentityMethodFacade.DataPolicyCkTypeId, methodPolicy,
                    new DataPolicySetEnforcementModeParameters { EnforcementMode = RtDataPolicyEnforcementModeEnum.Enforce }))
                .Success.Should().BeTrue();

            (await StoredModeAsync(restPolicy)).Should().Be(RtDataPolicyEnforcementModeEnum.Enforce);
            (await StoredModeAsync(methodPolicy)).Should().Be(RtDataPolicyEnforcementModeEnum.Enforce);
            var restVerdict = await ReadVerdictAsync(host, restType);
            var methodVerdict = await ReadVerdictAsync(host, methodType);
            restVerdict.Should().Be(RtDataPermissionDecision.NotVisible, "fail-closed: no grant, nothing visible");
            methodVerdict.Should().Be(restVerdict);

            var audit = _audit.For(SystemIdentityCkIds.DataPolicySetEnforcementModeMethodId, methodPolicy).Single();
            audit.Should().Contain("enforcementModeBefore", "AuditOnly").And.Contain("enforcementModeAfter", "Enforce");
        }
        finally
        {
            await RemovePermissionAsync(restPermission);
            await RemovePermissionAsync(methodPermission);
        }
    }

    [Fact]
    public async Task SetEnforcementMode_KeepsTheRestAnswers_AndFixesThe500ForAnUnknownPolicy()
    {
        var host = Host();
        var (_, permissionId) = await NewPermissionAsync();
        var policy = await NewPolicyAsync(permissionId, "System/BlueprintBackup", "AuditOnly");
        using var http = FacadeCaller.User(UserManagement).Client(host);
        var ct = TestContext.Current.CancellationToken;

        // invalid mode: 400 before anything is called, as before
        (await http.PutAsJsonAsync(TenantApiUrl($"dataPermissions/policies/{policy}/enforcementMode"), "Sometimes", ct))
            .StatusCode.Should().Be(HttpStatusCode.BadRequest);
        // intended change: unknown policy and a malformed id were an unhandled 500, now 404
        (await http.PutAsJsonAsync(TenantApiUrl(
                $"dataPermissions/policies/{OctoObjectId.GenerateNewId()}/enforcementMode"), "Enforce", ct)).StatusCode
            .Should().Be(HttpStatusCode.NotFound);
        (await http.PutAsJsonAsync(TenantApiUrl("dataPermissions/policies/not-an-id/enforcementMode"), "Enforce", ct))
            .StatusCode.Should().Be(HttpStatusCode.NotFound);
        // the mode it already has: 200, nothing written
        (await http.PutAsJsonAsync(TenantApiUrl($"dataPermissions/policies/{policy}/enforcementMode"), "AuditOnly", ct))
            .StatusCode.Should().Be(HttpStatusCode.OK);
        (await StoredModeAsync(policy)).Should().Be(RtDataPolicyEnforcementModeEnum.AuditOnly);
    }

    #endregion

    #region Grant and revoke: REST answers

    [Fact]
    public async Task GrantAndRevoke_KeepTheSilent200s_AndAnswer404ForAnUnknownPermissionOrRole()
    {
        var host = Host();
        var (_, permissionId) = await NewPermissionAsync();
        var role = await NewRoleAsync();
        using var http = FacadeCaller.User(UserManagement).Client(host);
        var ct = TestContext.Current.CancellationToken;
        var url = TenantApiUrl($"dataPermissions/{permissionId}/roles/{role}");

        // revoke without a grant, grant twice: 200 as before (PERMISSION_NOT_GRANTED / PERMISSION_ALREADY_GRANTED)
        (await http.DeleteAsync(url, ct)).StatusCode.Should().Be(HttpStatusCode.OK);
        (await http.PostAsync(url, null, ct)).StatusCode.Should().Be(HttpStatusCode.OK);
        (await http.PostAsync(url, null, ct)).StatusCode.Should().Be(HttpStatusCode.OK);
        (await GrantedAsync(permissionId)).Should().ContainSingle().Which.Should().BeEquivalentTo(role);

        // intended change: an unknown permission or role was an unhandled 500, now 404
        (await http.PostAsync(TenantApiUrl($"dataPermissions/no.such.permission/roles/{role}"), null, ct)).StatusCode
            .Should().Be(HttpStatusCode.NotFound);
        (await http.PostAsync(TenantApiUrl($"dataPermissions/{permissionId}/roles/NoSuchRole9039"), null, ct)).StatusCode
            .Should().Be(HttpStatusCode.NotFound);
        (await http.DeleteAsync(TenantApiUrl($"dataPermissions/{permissionId}/roles/NoSuchRole9039"), ct)).StatusCode
            .Should().Be(HttpStatusCode.NotFound);
        (await GrantedAsync(permissionId)).Should().ContainSingle();
    }

    #endregion

    #region Abuse cases and data permission

    [Fact]
    public async Task ATokenOfAnotherTenant_IsRefused_AndNothingChanges()
    {
        var host = Host(enforceTenantGate: true);
        var (permissionRtId, permissionId) = await NewPermissionAsync();
        var policy = await NewPolicyAsync(permissionId, "System/BlueprintBackup", "AuditOnly");
        var role = await NewRoleAsync();
        var foreign = new CkMethodPrincipal(Guid.NewGuid().ToString("N"), [UserManagement], ["octo_api"])
        {
            IsFromAccessToken = true, TokenTenantId = "othertenant9039"
        };

        var grant = await DispatchAsync(host, foreign, SystemIdentityCkIds.DataPermissionGrantToRoleMethodId,
            IdentityMethodFacade.DataPermissionCkTypeId, permissionRtId, new DataPermissionGrantToRoleParameters { RoleName = role });
        var mode = await DispatchAsync(host, foreign, SystemIdentityCkIds.DataPolicySetEnforcementModeMethodId,
            IdentityMethodFacade.DataPolicyCkTypeId, policy,
            new DataPolicySetEnforcementModeParameters { EnforcementMode = RtDataPolicyEnforcementModeEnum.Enforce });

        foreach (var refusal in new[] { grant, mode })
        {
            refusal.Error!.Code.Should().Be(CkMethodErrorCodes.MethodForbidden);
            refusal.Error.Parameters.Should().Contain("reason", "tenant-not-allowed");
        }

        using var http = (FacadeCaller.User(UserManagement) with { TokenTenant = "othertenant9039" }).Client(host);
        var ct = TestContext.Current.CancellationToken;
        (await http.PostAsync(TenantApiUrl($"dataPermissions/{permissionId}/roles/{role}"), null, ct)).StatusCode
            .Should().Be(HttpStatusCode.Forbidden);
        (await http.PutAsJsonAsync(TenantApiUrl($"dataPermissions/policies/{policy}/enforcementMode"), "Enforce", ct))
            .StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await GrantedAsync(permissionId)).Should().BeEmpty();
        (await StoredModeAsync(policy)).Should().Be(RtDataPolicyEnforcementModeEnum.AuditOnly);
    }

    [Fact]
    public async Task ACallerWithoutTheDeclaredRole_IsRefused_AndNothingChanges()
    {
        var host = Host();
        var (_, permissionId) = await NewPermissionAsync();
        var policy = await NewPolicyAsync(permissionId, "System/BlueprintBackup", "AuditOnly");
        var outsider = new CkMethodPrincipal(Guid.NewGuid().ToString("N"), ["TenantManagement"], ["octo_api"]);

        var mode = await DispatchAsync(host, outsider, SystemIdentityCkIds.DataPolicySetEnforcementModeMethodId,
            IdentityMethodFacade.DataPolicyCkTypeId, policy,
            new DataPolicySetEnforcementModeParameters { EnforcementMode = RtDataPolicyEnforcementModeEnum.Enforce });
        mode.Error!.Code.Should().Be(CkMethodErrorCodes.MethodForbidden);

        using var http = FacadeCaller.User("TenantManagement").Client(host);
        (await http.PutAsJsonAsync(TenantApiUrl($"dataPermissions/policies/{policy}/enforcementMode"), "Enforce",
            TestContext.Current.CancellationToken)).StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await StoredModeAsync(policy)).Should().Be(RtDataPolicyEnforcementModeEnum.AuditOnly);
    }

    [Fact]
    public async Task RevokingAGrantedRoleTheCallerCannotRead_Is403_AndTheGrantStays()
    {
        // CWE-863: the grant is visible through the permission; an enforcing policy on roles must not let it be removed
        // behind the caller's back (before the facade: removed, 200)
        var host = Host(evaluator: RolesInvisible());
        var (permissionRtId, permissionId) = await NewPermissionAsync();
        var role = await NewRoleAsync();
        await GrantViaStoreAsync(permissionId, role);
        using var http = FacadeCaller.User(UserManagement).Client(host);

        var response = await http.DeleteAsync(TenantApiUrl($"dataPermissions/{permissionId}/roles/{role}"),
            TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        var problem = await response.Content.ReadFromJsonAsync<JsonElement>(TestContext.Current.CancellationToken);
        problem.GetProperty("code").GetString().Should().Be(CkMethodErrorCodes.MethodForbidden);
        problem.GetProperty("parameters").GetProperty("reason").GetString().Should().Be("data-permission");
        var method = await DispatchAsync(host, Admin(), SystemIdentityCkIds.DataPermissionRevokeFromRoleMethodId,
            IdentityMethodFacade.DataPermissionCkTypeId, permissionRtId,
            new DataPermissionRevokeFromRoleParameters { RoleName = role });
        method.Error!.Code.Should().Be(CkMethodErrorCodes.MethodForbidden);
        (await GrantedAsync(permissionId)).Should().ContainSingle();
    }

    [Fact]
    public async Task RevokingAnUnreadableRoleThatHoldsNoGrant_AnswersAsForAnUnknownRole()
    {
        var host = Host(evaluator: RolesInvisible());
        var (permissionRtId, permissionId) = await NewPermissionAsync();
        var role = await NewRoleAsync();
        using var http = FacadeCaller.User(UserManagement).Client(host);

        (await http.DeleteAsync(TenantApiUrl($"dataPermissions/{permissionId}/roles/{role}"),
            TestContext.Current.CancellationToken)).StatusCode.Should().Be(HttpStatusCode.NotFound);
        (await DispatchAsync(host, Admin(), SystemIdentityCkIds.DataPermissionRevokeFromRoleMethodId,
                IdentityMethodFacade.DataPermissionCkTypeId, permissionRtId,
                new DataPermissionRevokeFromRoleParameters { RoleName = role })).Error!.Code.Should()
            .Be(UserRoleMethodErrors.RoleNotFound);
    }

    [Fact]
    public async Task SwitchingAPolicyWhosePermissionTheCallerMayNotWrite_Is403_AndTheModeStays()
    {
        // the mode decides whether the permission is enforced at all: switching it is a change of the permission too
        var host = Host(evaluator: PermissionsReadOnly());
        var (_, permissionId) = await NewPermissionAsync();
        var policy = await NewPolicyAsync(permissionId, "System/BlueprintBackup", "Enforce");
        using var http = FacadeCaller.User(UserManagement).Client(host);

        var response = await http.PutAsJsonAsync(TenantApiUrl($"dataPermissions/policies/{policy}/enforcementMode"),
            "AuditOnly", TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        var problem = await response.Content.ReadFromJsonAsync<JsonElement>(TestContext.Current.CancellationToken);
        problem.GetProperty("parameters").GetProperty("reason").GetString().Should().Be("data-permission");
        (await StoredModeAsync(policy)).Should().Be(RtDataPolicyEnforcementModeEnum.Enforce);
    }

    [Fact]
    public async Task APolicyOrPermissionTheCallerCannotRead_AnswersAsUnknown_AndNothingChanges()
    {
        var host = Host(evaluator: FacadeDataPolicy.DenyAllReads());
        var (_, permissionId) = await NewPermissionAsync();
        var policy = await NewPolicyAsync(permissionId, "System/BlueprintBackup", "AuditOnly");
        var role = await NewRoleAsync();
        using var http = FacadeCaller.User(UserManagement).Client(host);
        var ct = TestContext.Current.CancellationToken;

        (await http.PutAsJsonAsync(TenantApiUrl($"dataPermissions/policies/{policy}/enforcementMode"), "Enforce", ct))
            .StatusCode.Should().Be(HttpStatusCode.NotFound);
        (await http.PostAsync(TenantApiUrl($"dataPermissions/{permissionId}/roles/{role}"), null, ct)).StatusCode
            .Should().Be(HttpStatusCode.NotFound);
        (await StoredModeAsync(policy)).Should().Be(RtDataPolicyEnforcementModeEnum.AuditOnly);
        (await GrantedAsync(permissionId)).Should().BeEmpty();
    }

    #endregion

    #region Helpers

    private static CkMethodPrincipal Admin() => new(Guid.NewGuid().ToString("N"), [UserManagement], ["octo_api"]);

    private WebApplicationFactory<Program> Host(bool enforceTenantGate = false, IRtDataPermissionEvaluator? evaluator = null)
    {
        var host = Factory.WithWebHostBuilder(b =>
        {
            if (enforceTenantGate)
            {
                b.UseSetting("TenantAuthorization:UserTokenEnforcement", "Enforce");
            }

            b.ConfigureTestServices(services =>
            {
                services.AddSingleton(_audit.Events);
                services.AddSingleton<ICkInProcessAmbientStateProbe>(_probe);
                services.AddSingleton<IStartupFilter, MarkRequestsStartupFilter>();
                if (evaluator != null)
                {
                    services.AddSingleton(evaluator);
                }
            });
        });
        _hosts.Add(host);
        return host;
    }

    /// <summary>An enforcing data policy on roles only: every role is invisible, everything else is open.</summary>
    private static IRtDataPermissionEvaluator RolesInvisible()
    {
        var evaluator = Substitute.For<IRtDataPermissionEvaluator>();
        evaluator.EvaluateAsync(Arg.Any<IRuntimeRepository>(), Arg.Any<RtSecurityContext>(), Arg.Any<RtEntityId>(),
                Arg.Any<RtDataAction>(), Arg.Any<bool>(), Arg.Any<CancellationToken>())
            .Returns(call => call.ArgAt<RtEntityId>(2).CkTypeId.ToString().EndsWith("/Role", StringComparison.Ordinal)
                ? new RtDataPermissionVerdict(RtDataPermissionDecision.NotVisible, RtDataPermissionReason.NoGrant)
                : new RtDataPermissionVerdict(RtDataPermissionDecision.Allowed, RtDataPermissionReason.Open));
        return evaluator;
    }

    /// <summary>An enforcing data policy on data permissions: readable, never writable; everything else is open.</summary>
    private static IRtDataPermissionEvaluator PermissionsReadOnly()
    {
        var evaluator = Substitute.For<IRtDataPermissionEvaluator>();
        evaluator.EvaluateAsync(Arg.Any<IRuntimeRepository>(), Arg.Any<RtSecurityContext>(), Arg.Any<RtEntityId>(),
                Arg.Any<RtDataAction>(), Arg.Any<bool>(), Arg.Any<CancellationToken>())
            .Returns(call =>
                call.ArgAt<RtEntityId>(2).CkTypeId.ToString().EndsWith("/DataPermission", StringComparison.Ordinal) &&
                call.ArgAt<RtDataAction>(3) != RtDataAction.Read
                    ? new RtDataPermissionVerdict(RtDataPermissionDecision.NotPermitted, RtDataPermissionReason.NoGrant)
                    : new RtDataPermissionVerdict(RtDataPermissionDecision.Allowed, RtDataPermissionReason.Open));
        return evaluator;
    }

    /// <summary>The method as the GraphQL gateway reaches it: the dispatcher of the identity host, caller in scope.</summary>
    private async Task<CkMethodResponse> DispatchAsync(WebApplicationFactory<Program> host, CkMethodPrincipal caller,
        string methodId, string ckTypeId, string targetRtId, object parameters)
    {
        var request = new CkMethodRequest(NormalizedSystemTenantId)
        {
            InvocationId = Guid.NewGuid(),
            MethodId = methodId,
            CkTypeId = ckTypeId,
            TargetRtId = targetRtId,
            ParametersJson = JsonSerializer.Serialize(parameters, parameters.GetType(), CkMethodJson.Options),
            DeadlineUtc = DateTime.UtcNow.AddSeconds(30)
        };
        using (CkMethodPrincipalScope.Begin(caller))
        {
            return await host.Services.GetRequiredService<ICkMethodDispatcher>()
                .InvokeAsync(request, TestContext.Current.CancellationToken);
        }
    }

    /// <summary>The read verdict for <paramref name="ckTypeId" /> of a caller who holds no grant, as the engine decides it.</summary>
    private async Task<RtDataPermissionDecision> ReadVerdictAsync(WebApplicationFactory<Program> host, string ckTypeId)
    {
        using var scope = host.Services.CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IMultiTenancyResolverService>()
            .GetTenantRepository();
        var verdict = await scope.ServiceProvider.GetRequiredService<IRtDataPermissionEvaluator>().EvaluateTypeAsync(
            repository, RtSecurityContext.ForUser("no-grant-9039", ["DashboardViewer"]), new RtCkId<CkTypeId>(ckTypeId),
            RtDataAction.Read, cancellationToken: TestContext.Current.CancellationToken);
        return verdict.Decision;
    }

    private async Task<(string RtId, string PermissionId)> NewPermissionAsync()
    {
        var permissionId = $"dp9039.{Guid.NewGuid():N}";
        using var scope = CreateScope();
        var id = await scope.ServiceProvider.GetRequiredService<IDataPermissionStore>().CreateAsync(permissionId, null);
        return (id.ToString(), permissionId);
    }

    private async Task<string> NewPolicyAsync(string permissionId, string ckTypeId, string mode)
    {
        using var scope = CreateScope();
        var rtId = await scope.ServiceProvider.GetRequiredService<IDataPermissionStore>().CreatePolicyAsync(permissionId,
            [ckTypeId], ["Read"], RtDataPolicyScopeEnum.All, Enum.Parse<RtDataPolicyEnforcementModeEnum>(mode));
        return rtId.ToString();
    }

    private async Task RemovePermissionAsync(string permissionId)
    {
        using var scope = CreateScope();
        await scope.ServiceProvider.GetRequiredService<IDataPermissionStore>().RemoveAsync(permissionId);
        scope.ServiceProvider.GetService<IDataPermissionResolver>()?.Invalidate(NormalizedSystemTenantId);
    }

    private async Task<RtDataPolicyEnforcementModeEnum> StoredModeAsync(string policyRtId)
    {
        using var scope = CreateScope();
        var repository = scope.ServiceProvider.GetRequiredService<IMultiTenancyResolverService>().GetTenantRepository();
        using var session = await repository.GetSessionAsync();
        session.StartTransaction();
        var policy = await repository.GetRtEntityByRtIdAsync<RtDataPolicy>(session, new OctoObjectId(policyRtId));
        await session.CommitTransactionAsync();
        return policy!.EnforcementMode;
    }

    private async Task<string> NewRoleAsync()
    {
        var name = $"r9039_{Guid.NewGuid():N}";
        using var scope = CreateScope();
        (await scope.ServiceProvider.GetRequiredService<RoleManager<RtRole>>()
            .CreateAsync(new RtRoleBuilder().WithName(name).Build())).Succeeded.Should().BeTrue();
        return name;
    }

    private async Task GrantViaStoreAsync(string permissionId, string roleName)
    {
        using var scope = CreateScope();
        await scope.ServiceProvider.GetRequiredService<IDataPermissionStore>().GrantToRoleAsync(permissionId, roleName);
    }

    private async Task<string[]> GrantedAsync(string permissionId)
    {
        using var scope = CreateScope();
        var store = scope.ServiceProvider.GetRequiredService<IDataPermissionStore>();
        var permission = await store.FindByPermissionIdAsync(permissionId);
        return (await store.GetGrantedRoleNamesAsync(permission!.RtId)).ToArray();
    }

    #endregion
}
