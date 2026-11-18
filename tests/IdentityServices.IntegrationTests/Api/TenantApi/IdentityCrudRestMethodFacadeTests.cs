using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using FluentAssertions;
using IdentityServerPersistence.SystemStores;
using IdentityServices.IntegrationTests.Infrastructure;
using Meshmakers.Octo.Backend.IdentityServices.Methods;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.DataPermissions;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using NSubstitute;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Methods;
using Meshmakers.Octo.Services.Methods;
using Meshmakers.Octo.Services.Methods.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.TenantApi;

/// <summary>
///     The REST create, update and delete endpoints of roles, groups, API scopes and API resources are facades of the
///     System.Identity 3.7.0 methods <c>Role.CreateRole/UpdateRole/DeleteRole</c>, <c>Group.CreateGroup/UpdateGroup/DeleteGroup</c>,
///     <c>ApiScope.CreateApiScope/UpdateApiScope/DeleteApiScope</c> and <c>ApiResource.CreateApiResource/UpdateApiResource/
///     DeleteApiResource</c> (generic writes of these types are refused since 3.6.0). Real MongoDB, real identity host. The
///     tests prove: every endpoint runs its method in-process outside the request with exactly one <c>Identity.Method</c>
///     event; REST and the method through the dispatcher (the GraphQL path) leave the same stored state and refuse alike
///     (derived names, duplicates, unknown target); the REST policy and the declared roles; another tenant's token; the
///     guard on built-in roles and on the initial roles of a new group; a renamed role is used at once.
/// </summary>
public class IdentityCrudRestMethodFacadeTests : IntegrationTestBase, IDisposable
{
    private const string UserManagement = "UserManagement";
    private const string TenantManagement = "TenantManagement";

    private readonly FacadeAuditCapture _audit = new();
    private readonly RequestStateProbe _probe = new();
    private readonly List<WebApplicationFactory<Program>> _hosts = [];

    public IdentityCrudRestMethodFacadeTests(CustomWebApplicationFactory factory) : base(factory)
    {
    }

    public static TheoryData<string> Endpoints => new()
    {
        "createRole", "updateRole", "deleteRole", "createGroup", "updateGroup", "deleteGroup", "createScope",
        "updateScope", "deleteScope", "createResource", "updateResource", "deleteResource"
    };

    public void Dispose()
    {
        foreach (var host in _hosts)
        {
            host.Dispose();
        }
    }

    [Theory]
    [MemberData(nameof(Endpoints))]
    public async Task EveryEndpoint_RunsItsMethodInProcess_OutsideTheRequest_WithExactlyOneIdentityMethodEvent(
        string endpoint)
    {
        var host = Host();
        var caller = FacadeCaller.User(UserManagement);
        using var client = caller.Client(host);

        var call = await CallAsync(client, endpoint);

        call.Response.StatusCode.Should().Be(call.Expected, endpoint);
        var events = _audit.All.Where(e => e.GetValueOrDefault("methodId") == call.MethodId).ToList();
        events.Should().ContainSingle(endpoint);
        events[0]["outcome"].Should().Be(IdentityMethodAuditWriter.SuccessOutcome);
        events[0]["callerSubject"].Should().Be(caller.Subject);
        events[0].GetValueOrDefault("targetRtId").Should().NotBeNullOrEmpty("the created or changed entity is the target");
        _probe.Calls.Should().BeGreaterThan(0, "the method ran through the in-process transport");
        _probe.Violations.Should().Be(0, "the facade opens no request state (session, transaction) around the call");
    }

    [Theory]
    [MemberData(nameof(Endpoints))]
    public async Task ACallerWithoutTheRestPolicyRole_Is403_AndNoMethodRuns(string endpoint)
    {
        var host = Host();
        // Role and group endpoints need UserManagement, the resource endpoints TenantManagement or UserManagement.
        using var client = FacadeCaller.User("CommunicationManagement").Client(host);

        var call = await CallAsync(client, endpoint);

        call.Response.StatusCode.Should().Be(HttpStatusCode.Forbidden, endpoint);
        _audit.All.Where(e => e.GetValueOrDefault("methodId") == call.MethodId).Should().BeEmpty();
    }

    [Fact]
    public async Task RoleAndGroupEndpoints_StillRequireUserManagement_TenantManagementIsNotEnough()
    {
        var host = Host();
        using var client = FacadeCaller.User(TenantManagement).Client(host);
        var ct = TestContext.Current.CancellationToken;

        (await client.PostAsJsonAsync(TenantApiUrl("roles"), new RoleDto { Name = NewName("rx") }, ct)).StatusCode
            .Should().Be(HttpStatusCode.Forbidden);
        (await client.PostAsJsonAsync(TenantApiUrl("groups"), new CreateGroupDto { GroupName = NewName("gx") }, ct))
            .StatusCode.Should().Be(HttpStatusCode.Forbidden);
        // the resource endpoints accept TenantManagement (IdentityTenantAdministrationWritePolicy)
        (await client.PostAsJsonAsync(TenantApiUrl("apiScopes"), new ApiScopeDto { Name = NewName("sx") }, ct)).StatusCode
            .Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Role_RestAndTheMethod_StoreTheSameRole_AndRefuseADuplicateAlike()
    {
        var host = Host();
        using var client = FacadeCaller.User(UserManagement).Client(host);
        var admin = Admin(UserManagement);
        var ct = TestContext.Current.CancellationToken;
        var restName = NewName("Rr");
        var methodName = NewName("Rm");

        (await client.PostAsJsonAsync(TenantApiUrl("roles"), new RoleDto { Name = restName }, ct)).StatusCode.Should()
            .Be(HttpStatusCode.OK);
        var created = await DispatchAsync(host, admin, SystemIdentityCkIds.RoleCreateRoleMethodId,
            IdentityMethodFacade.RoleCkTypeId, null, new RoleCreateRoleParameters { Name = methodName });
        created.Success.Should().BeTrue();

        var restRole = await FindRoleAsync(restName);
        var methodRole = await FindRoleAsync(methodName);
        restRole!.NormalizedName.Should().Be(restName.ToUpperInvariant(), "the role manager derives the normalized name");
        methodRole!.NormalizedName.Should().Be(methodName.ToUpperInvariant());
        JsonSerializer.Deserialize<string>(created.ResultJson!).Should().Be(methodRole.RtId.ToString());

        // duplicate: REST 400 OperationFailedErrorDto with the role manager's code / ROLE_ALREADY_EXISTS
        var duplicate = await client.PostAsJsonAsync(TenantApiUrl("roles"), new RoleDto { Name = methodName }, ct);
        duplicate.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var body = await duplicate.Content.ReadFromJsonAsync<JsonElement>(ct);
        body.GetProperty("details")[0].GetProperty("code").GetString().Should().Be("DuplicateRoleName");
        body.GetProperty("details")[0].GetProperty("description").GetString().Should().Contain(methodName);
        (await DispatchAsync(host, admin, SystemIdentityCkIds.RoleCreateRoleMethodId, IdentityMethodFacade.RoleCkTypeId,
                null, new RoleCreateRoleParameters { Name = restName })).Error!.Code.Should()
            .Be(IdentityCrudErrors.RoleAlreadyExists);

        // rename: REST and the method; a rename onto a taken name is refused alike
        var renamed = NewName("Rn");
        (await client.PutAsJsonAsync(TenantApiUrl($"roles/{restName}"), new RoleDto { Name = renamed }, ct)).StatusCode
            .Should().Be(HttpStatusCode.OK);
        (await FindRoleAsync(renamed))!.RtId.Should().Be(restRole.RtId);
        (await client.PutAsJsonAsync(TenantApiUrl($"roles/{renamed}"), new RoleDto { Name = methodName }, ct)).StatusCode
            .Should().Be(HttpStatusCode.BadRequest);
        (await DispatchAsync(host, admin, SystemIdentityCkIds.RoleUpdateRoleMethodId, IdentityMethodFacade.RoleCkTypeId,
                methodRole.RtId.ToString(), new RoleUpdateRoleParameters { Name = renamed })).Error!.Code.Should()
            .Be(IdentityCrudErrors.RoleAlreadyExists);

        // delete; an unknown name / id is 404 / METHOD_TARGET_NOT_FOUND
        (await client.DeleteAsync(TenantApiUrl($"roles/{renamed}"), ct)).StatusCode.Should().Be(HttpStatusCode.OK);
        (await DispatchAsync(host, admin, SystemIdentityCkIds.RoleDeleteRoleMethodId, IdentityMethodFacade.RoleCkTypeId,
            methodRole.RtId.ToString(), new RoleDeleteRoleParameters())).Success.Should().BeTrue();
        (await FindRoleAsync(renamed)).Should().BeNull();
        (await FindRoleAsync(methodName)).Should().BeNull();
        (await client.DeleteAsync(TenantApiUrl($"roles/{renamed}"), ct)).StatusCode.Should().Be(HttpStatusCode.NotFound);
        (await DispatchAsync(host, admin, SystemIdentityCkIds.RoleDeleteRoleMethodId, IdentityMethodFacade.RoleCkTypeId,
                methodRole.RtId.ToString(), new RoleDeleteRoleParameters())).Error!.Code.Should()
            .Be(CkMethodErrorCodes.MethodTargetNotFound);
    }

    [Fact]
    public async Task ABuiltInRole_CannotBeRenamedOrDeleted_RestAnswersTheAudited409_TheMethodRefusesAlike()
    {
        var host = Host();
        var builtIn = await NewRoleAsync(builtIn: true);
        using var client = FacadeCaller.User(UserManagement).Client(host);
        var admin = Admin(UserManagement);
        var ct = TestContext.Current.CancellationToken;

        var rename = await client.PutAsJsonAsync(TenantApiUrl($"roles/{builtIn.Name}"),
            new RoleDto { Name = NewName("renamed") }, ct);
        var delete = await client.DeleteAsync(TenantApiUrl($"roles/{builtIn.Name}"), ct);

        foreach (var response in new[] { rename, delete })
        {
            response.StatusCode.Should().Be(HttpStatusCode.Conflict);
            (await response.Content.ReadFromJsonAsync<JsonElement>(ct)).GetProperty("code").GetString().Should()
                .Be("built-in-role");
        }

        _audit.For(SystemIdentityCkIds.RoleUpdateRoleMethodId, builtIn.RtId.ToString()).Should().ContainSingle()
            .Which["reason"].Should().Be("built-in-role");
        _audit.For(SystemIdentityCkIds.RoleDeleteRoleMethodId, builtIn.RtId.ToString()).Should().ContainSingle();
        _audit.RefusalCount.Should().Be(2, "the REST refusal record is kept");
        var method = await DispatchAsync(host, admin, SystemIdentityCkIds.RoleDeleteRoleMethodId,
            IdentityMethodFacade.RoleCkTypeId, builtIn.RtId.ToString(), new RoleDeleteRoleParameters());
        method.Error!.Code.Should().Be(CkMethodErrorCodes.MethodForbidden);
        method.Error.Parameters.Should().Contain("reason", "built-in-role");
        (await FindRoleAsync(builtIn.Name!)).Should().NotBeNull();
    }

    [Fact]
    public async Task ARenamedRole_IsUsedAtOnce_WithoutARestart()
    {
        var host = Host();
        var role = await NewRoleAsync();
        var user = await CreateTestUserAsync(NewName("ur"));
        using (var scope = CreateScope())
        {
            var users = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
            (await users.AddToRoleAsync((await users.FindByIdAsync(user.RtId.ToString()))!, role.Name!)).Succeeded
                .Should().BeTrue();
        }

        var renamed = NewName("Rrenamed");
        (await DispatchAsync(host, Admin(UserManagement), SystemIdentityCkIds.RoleUpdateRoleMethodId,
                IdentityMethodFacade.RoleCkTypeId, role.RtId.ToString(), new RoleUpdateRoleParameters { Name = renamed }))
            .Success.Should().BeTrue();

        // the role names of a user as the token claims service reads them for the next token, and the role check
        using var check = host.Services.CreateScope();
        var userManager = check.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
        var stored = (await userManager.FindByIdAsync(user.RtId.ToString()))!;
        (await userManager.GetRolesAsync(stored)).Should().Contain(renamed).And.NotContain(role.Name!);
        (await userManager.IsInRoleAsync(stored, renamed)).Should().BeTrue();
    }

    [Fact]
    public async Task Group_RestAndTheMethod_StoreTheSameGroup_AndRefuseADuplicateAlike()
    {
        var host = Host();
        using var client = FacadeCaller.User(UserManagement).Client(host);
        var admin = Admin(UserManagement);
        var ct = TestContext.Current.CancellationToken;
        var role = await NewRoleAsync();
        var restName = NewName("Gr");
        var methodName = NewName("Gm");

        var rest = await client.PostAsJsonAsync(TenantApiUrl("groups"),
            new CreateGroupDto { GroupName = restName, GroupDescription = "d", RoleIds = [role.RtId.ToString()] }, ct);
        rest.StatusCode.Should().Be(HttpStatusCode.Created);
        var restDto = (await rest.Content.ReadFromJsonAsync<GroupDto>(ct))!;
        restDto.GroupName.Should().Be(restName);
        restDto.RoleIds.Should().Equal(role.RtId.ToString());
        var created = await DispatchAsync(host, admin, SystemIdentityCkIds.GroupCreateGroupMethodId,
            IdentityMethodFacade.GroupCkTypeId, null,
            new GroupCreateGroupParameters { GroupName = methodName, GroupDescription = "d", RoleNames = [role.Name!] });
        created.Success.Should().BeTrue();

        var restGroup = (await WithGroupStoreAsync(s => s.FindByIdAsync(restDto.Id!.Value)))!;
        var methodGroup = (await WithGroupStoreAsync(s =>
            s.FindByIdAsync(OctoObjectId.Parse(JsonSerializer.Deserialize<string>(created.ResultJson!)!))))!;
        restGroup.NormalizedGroupName.Should().Be(restName.ToUpperInvariant());
        methodGroup.NormalizedGroupName.Should().Be(methodName.ToUpperInvariant());
        methodGroup.GroupDescription.Should().Be(restGroup.GroupDescription);
        (await WithGroupStoreAsync(s => s.GetRoleIdsAsync(methodGroup.RtId))).Should()
            .Equal(await WithGroupStoreAsync(s => s.GetRoleIdsAsync(restGroup.RtId)));

        // duplicate name (case-insensitive): REST 409 with the earlier text / GROUP_ALREADY_EXISTS
        var duplicate = await client.PostAsJsonAsync(TenantApiUrl("groups"),
            new CreateGroupDto { GroupName = methodName.ToLowerInvariant() }, ct);
        duplicate.StatusCode.Should().Be(HttpStatusCode.Conflict);
        (await duplicate.Content.ReadAsStringAsync(ct)).Should()
            .Be($"A group with name '{methodName.ToLowerInvariant()}' already exists.");
        (await DispatchAsync(host, admin, SystemIdentityCkIds.GroupCreateGroupMethodId,
                IdentityMethodFacade.GroupCkTypeId, null, new GroupCreateGroupParameters { GroupName = restName }))
            .Error!.Code.Should().Be(IdentityCrudErrors.GroupAlreadyExists);

        // update: same state; a rename onto a taken name is refused alike
        var update = await client.PutAsJsonAsync(TenantApiUrl($"groups/{restGroup.RtId}"),
            new UpdateGroupDto { GroupName = restName + "x", GroupDescription = null }, ct);
        update.StatusCode.Should().Be(HttpStatusCode.OK);
        (await update.Content.ReadFromJsonAsync<GroupDto>(ct))!.GroupName.Should().Be(restName + "x");
        (await DispatchAsync(host, admin, SystemIdentityCkIds.GroupUpdateGroupMethodId,
                IdentityMethodFacade.GroupCkTypeId, methodGroup.RtId.ToString(),
                new GroupUpdateGroupParameters { GroupName = methodName + "x" }))
            .Success.Should().BeTrue();
        var restUpdated = (await WithGroupStoreAsync(s => s.FindByIdAsync(restGroup.RtId)))!;
        var methodUpdated = (await WithGroupStoreAsync(s => s.FindByIdAsync(methodGroup.RtId)))!;
        restUpdated.NormalizedGroupName.Should().Be((restName + "x").ToUpperInvariant());
        methodUpdated.NormalizedGroupName.Should().Be((methodName + "x").ToUpperInvariant());
        restUpdated.GroupDescription.Should().BeNull().And.Be(methodUpdated.GroupDescription);
        (await client.PutAsJsonAsync(TenantApiUrl($"groups/{restGroup.RtId}"),
            new UpdateGroupDto { GroupName = methodName + "x" }, ct)).StatusCode.Should().Be(HttpStatusCode.Conflict);
        (await DispatchAsync(host, admin, SystemIdentityCkIds.GroupUpdateGroupMethodId,
                IdentityMethodFacade.GroupCkTypeId, methodGroup.RtId.ToString(),
                new GroupUpdateGroupParameters { GroupName = restName + "x" }))
            .Error!.Code.Should().Be(IdentityCrudErrors.GroupAlreadyExists);

        // delete; unknown group 404 / METHOD_TARGET_NOT_FOUND
        (await client.DeleteAsync(TenantApiUrl($"groups/{restGroup.RtId}"), ct)).StatusCode.Should().Be(HttpStatusCode.OK);
        (await DispatchAsync(host, admin, SystemIdentityCkIds.GroupDeleteGroupMethodId, IdentityMethodFacade.GroupCkTypeId,
            methodGroup.RtId.ToString(), new GroupDeleteGroupParameters())).Success.Should().BeTrue();
        (await WithGroupStoreAsync(s => s.FindByIdAsync(restGroup.RtId))).Should().BeNull();
        (await WithGroupStoreAsync(s => s.FindByIdAsync(methodGroup.RtId))).Should().BeNull();
        (await client.DeleteAsync(TenantApiUrl($"groups/{restGroup.RtId}"), ct)).StatusCode.Should()
            .Be(HttpStatusCode.NotFound);
        (await client.PutAsJsonAsync(TenantApiUrl($"groups/{restGroup.RtId}"), new UpdateGroupDto { GroupName = "y" },
            ct)).StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task GroupCreate_WithAnInitialBuiltInRoleTheCallerDoesNotHold_IsRefused_AndCreatesNothing()
    {
        var host = Host();
        var builtIn = await NewRoleAsync(builtIn: true);
        using var client = FacadeCaller.User(UserManagement).Client(host);
        var ct = TestContext.Current.CancellationToken;
        var restName = NewName("Gb");
        var methodName = NewName("Gb");

        var rest = await client.PostAsJsonAsync(TenantApiUrl("groups"),
            new CreateGroupDto { GroupName = restName, RoleIds = [builtIn.RtId.ToString()] }, ct);
        var method = await DispatchAsync(host, Admin(UserManagement), SystemIdentityCkIds.GroupCreateGroupMethodId,
            IdentityMethodFacade.GroupCkTypeId, null,
            new GroupCreateGroupParameters { GroupName = methodName, RoleNames = [builtIn.Name!] });

        rest.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await rest.Content.ReadFromJsonAsync<JsonElement>(ct)).GetProperty("code").GetString().Should()
            .Be("role-not-held");
        _audit.RefusalCount.Should().Be(1, "the REST refusal is audited like every other guard refusal");
        method.Error!.Code.Should().Be(CkMethodErrorCodes.MethodForbidden);
        method.Error.Parameters.Should().Contain("reason", "role-not-held");
        (await WithGroupStoreAsync(s => s.FindByNameAsync(restName.ToUpperInvariant()))).Should().BeNull();
        (await WithGroupStoreAsync(s => s.FindByNameAsync(methodName.ToUpperInvariant()))).Should().BeNull();

        // a caller who holds the role may create the group with it
        using var holder = FacadeCaller.User(UserManagement, builtIn.Name!).Client(host);
        (await holder.PostAsJsonAsync(TenantApiUrl("groups"),
                new CreateGroupDto { GroupName = restName, RoleIds = [builtIn.RtId.ToString()] }, ct)).StatusCode
            .Should().Be(HttpStatusCode.Created);
    }

    [Fact]
    public async Task GroupCreate_WithAnUnknownRoleId_Is404_AndCreatesNothing()
    {
        var host = Host();
        using var client = FacadeCaller.User(UserManagement).Client(host);
        var name = NewName("Gu");
        var unknown = OctoObjectId.GenerateNewId().ToString();

        var response = await client.PostAsJsonAsync(TenantApiUrl("groups"),
            new CreateGroupDto { GroupName = name, RoleIds = [unknown] }, TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
        (await WithGroupStoreAsync(s => s.FindByNameAsync(name.ToUpperInvariant()))).Should().BeNull();
        (await DispatchAsync(host, Admin(UserManagement), SystemIdentityCkIds.GroupCreateGroupMethodId,
                IdentityMethodFacade.GroupCkTypeId, null,
                new GroupCreateGroupParameters { GroupName = name, RoleNames = ["no-such-role"] }))
            .Error!.Code.Should().Be(UserRoleMethodErrors.RoleNotFound);
    }

    [Fact]
    public async Task ApiScope_RestAndTheMethod_StoreTheSameScope_AndRefuseADuplicateAlike()
    {
        var host = Host();
        using var client = FacadeCaller.User(TenantManagement).Client(host);
        var admin = Admin(TenantManagement);
        var ct = TestContext.Current.CancellationToken;
        var restName = NewName("sr");
        var methodName = NewName("sm");

        (await client.PostAsJsonAsync(TenantApiUrl("apiScopes"), ScopeDto(restName), ct)).StatusCode.Should()
            .Be(HttpStatusCode.OK);
        (await DispatchAsync(host, admin, SystemIdentityCkIds.ApiScopeCreateApiScopeMethodId,
            IdentityMethodFacade.ApiScopeCkTypeId, null, ScopeParameters(methodName))).Success.Should().BeTrue();
        var restScope = (await WithResourceStoreAsync(s => s.GetApiScopeByNameAsync(restName)))!;
        var methodScope = (await WithResourceStoreAsync(s => s.GetApiScopeByNameAsync(methodName)))!;
        SameScope(restScope, methodScope);

        var duplicate = await client.PostAsJsonAsync(TenantApiUrl("apiScopes"), ScopeDto(methodName), ct);
        duplicate.StatusCode.Should().Be(HttpStatusCode.Conflict);
        (await duplicate.Content.ReadAsStringAsync(ct)).Should().Be($"Scope with name '{methodName}' already exists.");
        (await DispatchAsync(host, admin, SystemIdentityCkIds.ApiScopeCreateApiScopeMethodId,
                IdentityMethodFacade.ApiScopeCkTypeId, null, ScopeParameters(restName)))
            .Error!.Code.Should().Be(IdentityCrudErrors.ApiScopeAlreadyExists);

        // update: the user claims are kept when omitted, as before
        var restUpdate = ScopeDto(restName);
        restUpdate.UserClaims = null;
        restUpdate.DisplayName = "changed";
        (await client.PutAsJsonAsync(TenantApiUrl($"apiScopes/{restName}"), restUpdate, ct)).StatusCode.Should()
            .Be(HttpStatusCode.OK);
        var methodUpdate = ScopeParameters(methodName);
        (await DispatchAsync(host, admin, SystemIdentityCkIds.ApiScopeUpdateApiScopeMethodId,
                IdentityMethodFacade.ApiScopeCkTypeId, methodScope.RtId.ToString(),
                new ApiScopeUpdateApiScopeParameters
                {
                    Name = methodName, DisplayName = "changed", Description = methodUpdate.Description,
                    Enabled = methodUpdate.Enabled, ShowInDiscoveryDocument = methodUpdate.ShowInDiscoveryDocument,
                    Required = methodUpdate.Required, Emphasized = methodUpdate.Emphasized
                }))
            .Success.Should().BeTrue();
        restScope = (await WithResourceStoreAsync(s => s.GetApiScopeByNameAsync(restName)))!;
        methodScope = (await WithResourceStoreAsync(s => s.GetApiScopeByNameAsync(methodName)))!;
        SameScope(restScope, methodScope);
        restScope.DisplayName.Should().Be("changed");
        restScope.Claims.Should().Equal("email", "name");

        // intended change: a rename onto the name of another scope is refused instead of storing a duplicate
        (await client.PutAsJsonAsync(TenantApiUrl($"apiScopes/{restName}"), ScopeDto(methodName), ct)).StatusCode
            .Should().Be(HttpStatusCode.Conflict);
        (await WithResourceStoreAsync(s => s.FindRtApiScopesByNameAsync([methodName]))).Should().ContainSingle();

        (await client.DeleteAsync(TenantApiUrl($"apiScopes/{restName}"), ct)).StatusCode.Should().Be(HttpStatusCode.OK);
        (await DispatchAsync(host, admin, SystemIdentityCkIds.ApiScopeDeleteApiScopeMethodId,
            IdentityMethodFacade.ApiScopeCkTypeId, methodScope.RtId.ToString(), new ApiScopeDeleteApiScopeParameters()))
            .Success.Should().BeTrue();
        (await WithResourceStoreAsync(s => s.GetApiScopeByNameAsync(restName))).Should().BeNull();
        (await WithResourceStoreAsync(s => s.GetApiScopeByNameAsync(methodName))).Should().BeNull();
        (await client.DeleteAsync(TenantApiUrl($"apiScopes/{restName}"), ct)).StatusCode.Should()
            .Be(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task ApiResource_RestAndTheMethod_StoreTheSameResource_AndAnUpdateKeepsTheSecrets()
    {
        var host = Host();
        using var client = FacadeCaller.User(TenantManagement).Client(host);
        var admin = Admin(TenantManagement);
        var ct = TestContext.Current.CancellationToken;
        var restName = NewName("ar");
        var methodName = NewName("am");

        (await client.PostAsJsonAsync(TenantApiUrl("apiResources"), ResourceDto(restName), ct)).StatusCode.Should()
            .Be(HttpStatusCode.OK);
        (await DispatchAsync(host, admin, SystemIdentityCkIds.ApiResourceCreateApiResourceMethodId,
            IdentityMethodFacade.ApiResourceCkTypeId, null, ResourceParameters(methodName))).Success.Should().BeTrue();
        var restResource = (await WithResourceStoreAsync(s => s.GetApiResourceByNameAsync(restName)))!;
        var methodResource = (await WithResourceStoreAsync(s => s.GetApiResourceByNameAsync(methodName)))!;
        SameResource(restResource, methodResource);
        (restResource.ApiSecrets?.Count ?? 0).Should().Be(0, "a create stores no secret");

        var duplicate = await client.PostAsJsonAsync(TenantApiUrl("apiResources"), ResourceDto(methodName), ct);
        duplicate.StatusCode.Should().Be(HttpStatusCode.Conflict);
        (await DispatchAsync(host, admin, SystemIdentityCkIds.ApiResourceCreateApiResourceMethodId,
                IdentityMethodFacade.ApiResourceCkTypeId, null, ResourceParameters(restName)))
            .Error!.Code.Should().Be(IdentityCrudErrors.ApiResourceAlreadyExists);

        // a secret, then an update over REST and over the method: the secret stays
        (await client.PostAsJsonAsync(TenantApiUrl($"apiSecrets/apiResource/{restName}"),
            new { description = "kept" }, ct)).StatusCode.Should().Be(HttpStatusCode.OK);
        var update = ResourceDto(restName);
        update.DisplayName = "changed";
        (await client.PutAsJsonAsync(TenantApiUrl($"apiResources/{restName}"), update, ct)).StatusCode.Should()
            .Be(HttpStatusCode.OK);
        var updated = (await WithResourceStoreAsync(s => s.GetApiResourceByNameAsync(restName)))!;
        updated.DisplayName.Should().Be("changed");
        updated.ApiSecrets.Should().ContainSingle().Which.Description.Should().Be("kept");
        var parameters = ResourceParameters(restName);
        (await DispatchAsync(host, admin, SystemIdentityCkIds.ApiResourceUpdateApiResourceMethodId,
                IdentityMethodFacade.ApiResourceCkTypeId, restResource.RtId.ToString(),
                new ApiResourceUpdateApiResourceParameters
                {
                    Name = restName, DisplayName = "again", Enabled = parameters.Enabled, Scopes = parameters.Scopes,
                    AllowedAccessTokenSigningAlgorithms = parameters.AllowedAccessTokenSigningAlgorithms
                }))
            .Success.Should().BeTrue();
        updated = (await WithResourceStoreAsync(s => s.GetApiResourceByNameAsync(restName)))!;
        updated.DisplayName.Should().Be("again");
        updated.ApiSecrets.Should().ContainSingle();

        // intended change: a rename onto another resource's name is refused
        (await client.PutAsJsonAsync(TenantApiUrl($"apiResources/{restName}"), ResourceDto(methodName), ct)).StatusCode
            .Should().Be(HttpStatusCode.Conflict);

        (await client.DeleteAsync(TenantApiUrl($"apiResources/{restName}"), ct)).StatusCode.Should().Be(HttpStatusCode.OK);
        (await DispatchAsync(host, admin, SystemIdentityCkIds.ApiResourceDeleteApiResourceMethodId,
                IdentityMethodFacade.ApiResourceCkTypeId, methodResource.RtId.ToString(),
                new ApiResourceDeleteApiResourceParameters()))
            .Success.Should().BeTrue();
        (await WithResourceStoreAsync(s => s.GetApiResourceByNameAsync(restName))).Should().BeNull();
        (await WithResourceStoreAsync(s => s.GetApiResourceByNameAsync(methodName))).Should().BeNull();
        (await client.PutAsJsonAsync(TenantApiUrl($"apiResources/{restName}"), ResourceDto(restName), ct)).StatusCode
            .Should().Be(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task ATokenOfAnotherTenant_IsRefused_AndNothingIsCreated()
    {
        var host = Host(enforceTenantGate: true);
        var foreign = new CkMethodPrincipal(Guid.NewGuid().ToString("N"), [UserManagement, TenantManagement], ["octo_api"])
        {
            IsFromAccessToken = true, TokenTenantId = "othertenantcf"
        };
        var roleName = NewName("Rf");
        var scopeName = NewName("sf");

        var role = await DispatchAsync(host, foreign, SystemIdentityCkIds.RoleCreateRoleMethodId,
            IdentityMethodFacade.RoleCkTypeId, null, new RoleCreateRoleParameters { Name = roleName });
        var scope = await DispatchAsync(host, foreign, SystemIdentityCkIds.ApiScopeCreateApiScopeMethodId,
            IdentityMethodFacade.ApiScopeCkTypeId, null, ScopeParameters(scopeName));

        foreach (var refusal in new[] { role, scope })
        {
            refusal.Error!.Code.Should().Be(CkMethodErrorCodes.MethodForbidden);
            refusal.Error.Parameters.Should().Contain("reason", "tenant-not-allowed");
        }

        using var client = (FacadeCaller.User(UserManagement, TenantManagement) with { TokenTenant = "othertenantcf" })
            .Client(host);
        (await client.PostAsJsonAsync(TenantApiUrl("roles"), new RoleDto { Name = roleName },
            TestContext.Current.CancellationToken)).StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await FindRoleAsync(roleName)).Should().BeNull();
        (await WithResourceStoreAsync(s => s.GetApiScopeByNameAsync(scopeName))).Should().BeNull();
    }

    [Fact]
    public async Task ACallerWhoMayNotWriteTheType_IsRefusedOnEveryCreate_AndNothingIsCreated()
    {
        var host = Host(denyReads: true);
        using var client = FacadeCaller.User(UserManagement).Client(host);
        var ct = TestContext.Current.CancellationToken;
        var name = NewName("Dn");

        (await client.PostAsJsonAsync(TenantApiUrl("roles"), new RoleDto { Name = name }, ct)).StatusCode.Should()
            .Be(HttpStatusCode.NotFound);
        (await client.PostAsJsonAsync(TenantApiUrl("groups"), new CreateGroupDto { GroupName = name }, ct)).StatusCode
            .Should().Be(HttpStatusCode.NotFound);
        (await client.PostAsJsonAsync(TenantApiUrl("apiScopes"), ScopeDto(name), ct)).StatusCode.Should()
            .Be(HttpStatusCode.NotFound);
        (await client.PostAsJsonAsync(TenantApiUrl("apiResources"), ResourceDto(name), ct)).StatusCode.Should()
            .Be(HttpStatusCode.NotFound);

        (await FindRoleAsync(name)).Should().BeNull();
        (await WithGroupStoreAsync(s => s.FindByNameAsync(name.ToUpperInvariant()))).Should().BeNull();
        (await WithResourceStoreAsync(s => s.GetApiScopeByNameAsync(name))).Should().BeNull();
        (await WithResourceStoreAsync(s => s.GetApiResourceByNameAsync(name))).Should().BeNull();
        _audit.All.Where(e => e.GetValueOrDefault("outcome") == CkMethodErrorCodes.MethodTargetNotFound).Should()
            .HaveCount(4, "each refusal writes its Identity.Method event");
    }

    [Fact]
    public async Task ACallerWhoMayNotWriteTheTarget_IsRefusedOnUpdateAndDelete_AndNothingChanges()
    {
        var host = Host(denyReads: true);
        var role = await NewRoleAsync();
        var group = await NewGroupAsync();
        using var client = FacadeCaller.User(UserManagement).Client(host);
        var ct = TestContext.Current.CancellationToken;

        (await client.PutAsJsonAsync(TenantApiUrl($"roles/{role.Name}"), new RoleDto { Name = NewName("x") }, ct))
            .StatusCode.Should().Be(HttpStatusCode.NotFound);
        (await client.DeleteAsync(TenantApiUrl($"roles/{role.Name}"), ct)).StatusCode.Should().Be(HttpStatusCode.NotFound);
        (await client.PutAsJsonAsync(TenantApiUrl($"groups/{group.RtId}"), new UpdateGroupDto { GroupName = "x" }, ct))
            .StatusCode.Should().Be(HttpStatusCode.NotFound);
        (await client.DeleteAsync(TenantApiUrl($"groups/{group.RtId}"), ct)).StatusCode.Should()
            .Be(HttpStatusCode.NotFound);

        (await FindRoleAsync(role.Name!)).Should().NotBeNull();
        (await WithGroupStoreAsync(s => s.FindByIdAsync(group.RtId)))!.GroupName.Should().Be(group.GroupName);
    }

    [Fact]
    public void TheCrudMethods_RunInThisProcess()
    {
        var transport = Host().Services.GetRequiredService<ICkInProcessMethodTransport>();

        foreach (var methodId in new[]
                 {
                     SystemIdentityCkIds.RoleCreateRoleMethodId, SystemIdentityCkIds.RoleUpdateRoleMethodId,
                     SystemIdentityCkIds.RoleDeleteRoleMethodId, SystemIdentityCkIds.GroupCreateGroupMethodId,
                     SystemIdentityCkIds.GroupUpdateGroupMethodId, SystemIdentityCkIds.GroupDeleteGroupMethodId,
                     SystemIdentityCkIds.ApiScopeCreateApiScopeMethodId, SystemIdentityCkIds.ApiScopeUpdateApiScopeMethodId,
                     SystemIdentityCkIds.ApiScopeDeleteApiScopeMethodId,
                     SystemIdentityCkIds.ApiResourceCreateApiResourceMethodId,
                     SystemIdentityCkIds.ApiResourceUpdateApiResourceMethodId,
                     SystemIdentityCkIds.ApiResourceDeleteApiResourceMethodId
                 })
        {
            transport.CanHandle(methodId).Should().BeTrue(methodId);
        }
    }

    #region Helpers

    private WebApplicationFactory<Program> Host(bool enforceTenantGate = false, bool denyReads = false)
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
                if (denyReads)
                {
                    services.AddSingleton(DenyEverything());
                }
            });
        });
        _hosts.Add(host);
        return host;
    }

    /// <summary>An enforcing data policy that lets the caller see nothing: no entity and no type.</summary>
    private static IRtDataPermissionEvaluator DenyEverything()
    {
        var evaluator = FacadeDataPolicy.DenyAllReads();
        evaluator.EvaluateTypeAsync(Arg.Any<IRuntimeRepository>(), Arg.Any<RtSecurityContext>(),
                Arg.Any<RtCkId<CkTypeId>>(), Arg.Any<RtDataAction>(), Arg.Any<bool>(), Arg.Any<CancellationToken>())
            .Returns(new RtDataPermissionVerdict(RtDataPermissionDecision.NotVisible, RtDataPermissionReason.NoGrant));
        return evaluator;
    }

    private static CkMethodPrincipal Admin(string role) => new(Guid.NewGuid().ToString("N"), [role], ["octo_api"]);

    private sealed record EndpointCall(HttpResponseMessage Response, string MethodId, HttpStatusCode Expected);

    /// <summary>Calls one of the twelve endpoints with a valid change on fresh entities.</summary>
    private async Task<EndpointCall> CallAsync(HttpClient client, string endpoint)
    {
        var ct = TestContext.Current.CancellationToken;
        switch (endpoint)
        {
            case "createRole":
                return new EndpointCall(await client.PostAsJsonAsync(TenantApiUrl("roles"),
                    new RoleDto { Name = NewName("Rc") }, ct), SystemIdentityCkIds.RoleCreateRoleMethodId, HttpStatusCode.OK);
            case "updateRole":
                return new EndpointCall(await client.PutAsJsonAsync(TenantApiUrl($"roles/{(await NewRoleAsync()).Name}"),
                    new RoleDto { Name = NewName("Ru") }, ct), SystemIdentityCkIds.RoleUpdateRoleMethodId, HttpStatusCode.OK);
            case "deleteRole":
                return new EndpointCall(await client.DeleteAsync(TenantApiUrl($"roles/{(await NewRoleAsync()).Name}"), ct),
                    SystemIdentityCkIds.RoleDeleteRoleMethodId, HttpStatusCode.OK);
            case "createGroup":
                return new EndpointCall(await client.PostAsJsonAsync(TenantApiUrl("groups"),
                        new CreateGroupDto { GroupName = NewName("Gc") }, ct), SystemIdentityCkIds.GroupCreateGroupMethodId,
                    HttpStatusCode.Created);
            case "updateGroup":
                return new EndpointCall(await client.PutAsJsonAsync(TenantApiUrl($"groups/{(await NewGroupAsync()).RtId}"),
                        new UpdateGroupDto { GroupName = NewName("Gu") }, ct), SystemIdentityCkIds.GroupUpdateGroupMethodId,
                    HttpStatusCode.OK);
            case "deleteGroup":
                return new EndpointCall(await client.DeleteAsync(TenantApiUrl($"groups/{(await NewGroupAsync()).RtId}"), ct),
                    SystemIdentityCkIds.GroupDeleteGroupMethodId, HttpStatusCode.OK);
            case "createScope":
                return new EndpointCall(await client.PostAsJsonAsync(TenantApiUrl("apiScopes"), ScopeDto(NewName("sc")), ct),
                    SystemIdentityCkIds.ApiScopeCreateApiScopeMethodId, HttpStatusCode.OK);
            case "updateScope":
            {
                var name = await NewScopeAsync();
                return new EndpointCall(await client.PutAsJsonAsync(TenantApiUrl($"apiScopes/{name}"), ScopeDto(name), ct),
                    SystemIdentityCkIds.ApiScopeUpdateApiScopeMethodId, HttpStatusCode.OK);
            }
            case "deleteScope":
                return new EndpointCall(await client.DeleteAsync(TenantApiUrl($"apiScopes/{await NewScopeAsync()}"), ct),
                    SystemIdentityCkIds.ApiScopeDeleteApiScopeMethodId, HttpStatusCode.OK);
            case "createResource":
                return new EndpointCall(await client.PostAsJsonAsync(TenantApiUrl("apiResources"),
                        ResourceDto(NewName("rc")), ct), SystemIdentityCkIds.ApiResourceCreateApiResourceMethodId,
                    HttpStatusCode.OK);
            case "updateResource":
            {
                var name = await NewResourceAsync();
                return new EndpointCall(await client.PutAsJsonAsync(TenantApiUrl($"apiResources/{name}"),
                    ResourceDto(name), ct), SystemIdentityCkIds.ApiResourceUpdateApiResourceMethodId, HttpStatusCode.OK);
            }
            default:
                return new EndpointCall(await client.DeleteAsync(TenantApiUrl($"apiResources/{await NewResourceAsync()}"),
                    ct), SystemIdentityCkIds.ApiResourceDeleteApiResourceMethodId, HttpStatusCode.OK);
        }
    }

    /// <summary>The method as the GraphQL gateway reaches it: the dispatcher of the identity host, caller in scope.</summary>
    private async Task<CkMethodResponse> DispatchAsync(WebApplicationFactory<Program> host, CkMethodPrincipal caller,
        string methodId, string ckTypeId, string? targetRtId, object parameters)
    {
        var request = new CkMethodRequest(NormalizedSystemTenantId)
        {
            InvocationId = Guid.NewGuid(),
            MethodId = methodId,
            CkTypeId = ckTypeId,
            TargetRtId = targetRtId,
            ParametersJson = JsonSerializer.Serialize(parameters, parameters.GetType(), CkMethodJson.Options),
            DeadlineUtc = TestHostMethodDeadlineFloor.DeadlineFromNow()
        };
        using (CkMethodPrincipalScope.Begin(caller))
        {
            return await host.Services.GetRequiredService<ICkMethodDispatcher>()
                .InvokeAsync(request, TestContext.Current.CancellationToken);
        }
    }

    private static string NewName(string prefix) => $"{prefix}_{Guid.NewGuid():N}";

    private static ApiScopeDto ScopeDto(string name) => new()
    {
        Name = name, DisplayName = "Scope", Description = "A scope", IsEnabled = true, ShowInDiscoveryDocument = true,
        IsRequired = true, IsEmphasize = false, UserClaims = ["email", "name"]
    };

    private static ApiScopeCreateApiScopeParameters ScopeParameters(string name) => new()
    {
        Name = name, DisplayName = "Scope", Description = "A scope", Enabled = true, ShowInDiscoveryDocument = true,
        Required = true, Emphasized = false, UserClaims = ["email", "name"]
    };

    private static ApiResourceDto ResourceDto(string name) => new()
    {
        Name = name, DisplayName = "Resource", Description = "A resource", IsEnabled = true,
        ShowInDiscoveryDocument = true, RequireResourceIndicator = true, UserClaims = ["role"],
        Scopes = ["octo_api"], AllowedAccessTokenSigningAlgorithms = ["RS256"]
    };

    private static ApiResourceCreateApiResourceParameters ResourceParameters(string name) => new()
    {
        Name = name, DisplayName = "Resource", Description = "A resource", Enabled = true,
        ShowInDiscoveryDocument = true, RequireResourceIndicator = true, UserClaims = ["role"], Scopes = ["octo_api"],
        AllowedAccessTokenSigningAlgorithms = ["RS256"]
    };

    private static void SameScope(RtApiScope rest, RtApiScope method)
    {
        method.Enabled.Should().Be(rest.Enabled);
        method.DisplayName.Should().Be(rest.DisplayName);
        method.Description.Should().Be(rest.Description);
        method.ShowInDiscoveryDocument.Should().Be(rest.ShowInDiscoveryDocument);
        method.IsRequired.Should().Be(rest.IsRequired);
        method.IsEmphasized.Should().Be(rest.IsEmphasized);
        method.Claims.Should().Equal(rest.Claims);
    }

    private static void SameResource(RtApiResource rest, RtApiResource method)
    {
        method.Enabled.Should().Be(rest.Enabled);
        method.DisplayName.Should().Be(rest.DisplayName);
        method.Description.Should().Be(rest.Description);
        method.ShowInDiscoveryDocument.Should().Be(rest.ShowInDiscoveryDocument);
        method.RequireResourceIndicator.Should().Be(rest.RequireResourceIndicator);
        method.Claims.Should().Equal(rest.Claims);
        method.Scopes.Should().Equal(rest.Scopes);
        method.AllowedAccessTokenSigningAlgorithms.Should().Equal(rest.AllowedAccessTokenSigningAlgorithms);
    }

    private async Task<RtRole> NewRoleAsync(bool builtIn = false)
    {
        var name = NewName(builtIn ? TestPlatformRoles.Prefix + "bcr" : "cr");
        using var scope = CreateScope();
        var role = new RtRoleBuilder().WithName(name).Build();
        if (builtIn)
        {
            role.RtWellKnownName = name;
        }

        (await scope.ServiceProvider.GetRequiredService<RoleManager<RtRole>>().CreateAsync(role)).Succeeded.Should()
            .BeTrue();
        return role;
    }

    private async Task<RtRole?> FindRoleAsync(string name)
    {
        using var scope = CreateScope();
        return await scope.ServiceProvider.GetRequiredService<RoleManager<RtRole>>().FindByNameAsync(name);
    }

    private async Task<RtGroup> NewGroupAsync()
    {
        var name = NewName("gc");
        var group = new RtGroup
        {
            RtId = OctoObjectId.GenerateNewId(), GroupName = name, NormalizedGroupName = name.ToUpperInvariant()
        };
        await WithGroupStoreAsync(async s =>
        {
            await s.StoreAsync(group);
            return true;
        });
        return group;
    }

    private async Task<string> NewScopeAsync()
    {
        var name = NewName("sn");
        var scope = new RtApiScope { Name = name, Enabled = true };
        await WithResourceStoreAsync(async s =>
        {
            await s.CreateApiScopeAsync(scope);
            return true;
        });
        return name;
    }

    private async Task<string> NewResourceAsync()
    {
        var name = NewName("rn");
        var resource = new RtApiResource();
        ResourceDefinitions.Apply(resource, name, null, null, true, true, false, [], [], []);
        await WithResourceStoreAsync(async s =>
        {
            await s.CreateApiResourceAsync(resource);
            return true;
        });
        return name;
    }

    private async Task<T> WithGroupStoreAsync<T>(Func<IGroupStore, Task<T>> action)
    {
        using var scope = CreateScope();
        return await action(scope.ServiceProvider.GetRequiredService<IGroupStore>());
    }

    private async Task<T> WithResourceStoreAsync<T>(Func<IOctoResourceStore, Task<T>> action)
    {
        using var scope = CreateScope();
        return await action(scope.ServiceProvider.GetRequiredService<IOctoResourceStore>());
    }

    #endregion
}
