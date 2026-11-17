using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using FluentAssertions;
using IdentityServerPersistence.SystemStores;
using IdentityServices.IntegrationTests.Infrastructure;
using Meshmakers.Octo.Backend.IdentityServices.Methods;
using Meshmakers.Octo.Common.DistributionEventHub.Services;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.DataPermissions;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Methods;
using Meshmakers.Octo.Services.Methods;
using Meshmakers.Octo.Services.Methods.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.TenantApi;

/// <summary>
///     Under an enforcing data policy on the <b>target</b> type (group, client, user), every REST facade answers like the method
///     does: a target the caller cannot read is <c>404</c> / <c>METHOD_TARGET_NOT_FOUND</c>, one it may read but not write
///     <c>403</c> / <c>METHOD_FORBIDDEN</c> with <c>reason</c> = <c>data-permission</c>, and nothing changes. The GraphQL gateway
///     refuses such a call before dispatch with the same codes; the REST facade dispatches in-process, so the handler checks
///     the target itself (CWE-863: before, REST wrote a target GraphQL refused). The referenced entities (roles, members) are
///     readable here, so only the target decides.
/// </summary>
public class TargetDataPermissionRestParityTests : IntegrationTestBase, IDisposable
{
    private const string TenantManagement = "TenantManagement";
    private const string UserManagement = "UserManagement";

    private readonly FacadeAuditCapture _audit = new();
    private readonly List<WebApplicationFactory<Program>> _hosts = [];

    public TargetDataPermissionRestParityTests(CustomWebApplicationFactory factory) : base(factory)
    {
    }

    /// <summary>The REST endpoint (label) x what the policy grants on the target type.</summary>
    public static TheoryData<string, RtDataPermissionDecision> Cases()
    {
        var data = new TheoryData<string, RtDataPermissionDecision>();
        foreach (var endpoint in new[]
                 {
                     "group.setRoles", "group.addUser", "group.removeUser", "group.addGroup", "client.addRole",
                     "client.setRoles", "client.removeRole", "client.overlayUris", "user.addRole", "user.setRoles",
                     "user.removeRole", "user.resetPassword"
                 })
        {
            data.Add(endpoint, RtDataPermissionDecision.NotVisible);
            data.Add(endpoint, RtDataPermissionDecision.NotPermitted);
        }

        return data;
    }

    public void Dispose()
    {
        foreach (var host in _hosts)
        {
            host.Dispose();
        }
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public async Task RestAndMethod_GiveTheSameVerdictOnTheTarget_AndNothingChanges(string endpoint,
        RtDataPermissionDecision onTarget)
    {
        var kind = endpoint[..endpoint.IndexOf('.')];
        var host = Host(kind, onTarget);
        using var http = (FacadeCaller.User(TenantManagement, UserManagement) with
        {
            Subject = OctoObjectId.GenerateNewId().ToString()
        }).Client(host);
        var ct = TestContext.Current.CancellationToken;
        var expectedStatus = onTarget == RtDataPermissionDecision.NotVisible
            ? HttpStatusCode.NotFound
            : HttpStatusCode.Forbidden;
        var expectedCode = onTarget == RtDataPermissionDecision.NotVisible
            ? CkMethodErrorCodes.MethodTargetNotFound
            : CkMethodErrorCodes.MethodForbidden;

        var (rest, methodId, target, parameters, assertUnchanged) = await CallAsync(http, endpoint, ct);
        var method = await DispatchAsync(host, methodId, target, parameters);

        rest.StatusCode.Should().Be(expectedStatus, await rest.Content.ReadAsStringAsync(ct));
        method.Error!.Code.Should().Be(expectedCode);
        if (onTarget == RtDataPermissionDecision.NotPermitted)
        {
            method.Error.Parameters.Should().Contain("reason", "data-permission");
        }

        _audit.For(methodId, target).Should().HaveCount(2, "the REST call and the method call each wrote one event")
            .And.OnlyContain(e => e["outcome"] == expectedCode)
            .And.OnlyContain(e => onTarget != RtDataPermissionDecision.NotPermitted ||
                                  e.GetValueOrDefault("reason") == "data-permission");
        await assertUnchanged();
    }

    public static TheoryData<string, RtDataPermissionDecision> StaticMethodCases()
    {
        var data = new TheoryData<string, RtDataPermissionDecision>();
        foreach (var endpoint in new[] { "mapping.create", "mapping.remove", "user.create", "client.cleanOverlayEntries" })
        {
            data.Add(endpoint, RtDataPermissionDecision.NotVisible);
            data.Add(endpoint, RtDataPermissionDecision.NotPermitted);
        }

        return data;
    }

    /// <summary>
    ///     Static methods have no target entity: the gateway checks the caller's <c>Write</c> permission on the declaring type
    ///     before dispatch, and their REST facades must give the same verdict.
    /// </summary>
    [Theory]
    [MemberData(nameof(StaticMethodCases))]
    public async Task StaticMethods_RestAndMethod_GiveTheSameVerdictOnTheType_AndNothingChanges(string endpoint,
        RtDataPermissionDecision onType)
    {
        var host = Host(endpoint[..endpoint.IndexOf('.')], onType);
        using var http = (FacadeCaller.User(TenantManagement, UserManagement) with
        {
            Subject = OctoObjectId.GenerateNewId().ToString()
        }).Client(host);
        var ct = TestContext.Current.CancellationToken;
        var user = await NewUserAsync();
        HttpResponseMessage rest;
        string methodId;
        object parameters;
        RtExternalTenantUserMapping? seeded = null;
        var newUserName = NewName("tdn");
        if (endpoint == "user.create")
        {
            rest = await http.PostAsJsonAsync(TenantApiUrl("users"),
                new { name = newUserName, email = $"{newUserName}@example.invalid", password = "Td-P4ssw0rd!c" }, ct);
            methodId = SystemIdentityCkIds.UserCreateUserMethodId;
            parameters = new UserCreateUserParameters { UserName = newUserName, Email = $"{newUserName}@example.invalid" };
        }
        else if (endpoint == "client.cleanOverlayEntries")
        {
            rest = await http.DeleteAsync(TenantApiUrl("clients/cleanOverlayEntries?overlayName=tdp"), ct);
            methodId = SystemIdentityCkIds.ClientCleanOverlayEntriesMethodId;
            parameters = new ClientCleanOverlayEntriesParameters { OverlayName = "tdp" };
        }
        else if (endpoint == "mapping.create")
        {
            rest = await http.PostAsJsonAsync(TenantApiUrl("ExternalTenantUserMappings"), new
            {
                sourceTenantId = NormalizedSystemTenantId, sourceUserId = user.RtId.ToString(),
                sourceUserName = user.UserName, roleIds = Array.Empty<string>()
            }, ct);
            methodId = SystemIdentityCkIds.ExternalTenantUserMappingCreateMappingMethodId;
            parameters = new ExternalTenantUserMappingCreateMappingParameters
            {
                SourceTenantId = NormalizedSystemTenantId, SourceUserId = user.RtId.ToString(),
                SourceUserName = user.UserName!
            };
        }
        else
        {
            seeded = await SeedMappingAsync(user);
            rest = await http.DeleteAsync(
                TenantApiUrl($"adminProvisioning/{NormalizedSystemTenantId}/{seeded.RtId}"), ct);
            methodId = SystemIdentityCkIds.ExternalTenantUserMappingRemoveAdminProvisioningMethodId;
            parameters = new ExternalTenantUserMappingRemoveAdminProvisioningParameters
            {
                TargetTenantId = NormalizedSystemTenantId, MappingRtId = seeded.RtId.ToString()
            };
        }

        var method = await DispatchAsync(host, methodId, null, parameters);

        rest.StatusCode.Should().Be(onType == RtDataPermissionDecision.NotVisible
            ? HttpStatusCode.NotFound
            : HttpStatusCode.Forbidden, await rest.Content.ReadAsStringAsync(ct));
        var expectedCode = onType == RtDataPermissionDecision.NotVisible
            ? CkMethodErrorCodes.MethodTargetNotFound
            : CkMethodErrorCodes.MethodForbidden;
        method.Error!.Code.Should().Be(expectedCode);
        if (onType == RtDataPermissionDecision.NotPermitted)
        {
            method.Error.Parameters.Should().Contain("reason", "data-permission");
        }

        _audit.For(methodId, null).Should().HaveCount(2, "the REST call and the method call each wrote one event")
            .And.OnlyContain(e => e["outcome"] == expectedCode);
        (await MappingsOfAsync(user)).Should().HaveCount(seeded == null ? 0 : 1, "no mapping was created or deleted");
        using var scope = CreateScope();
        (await scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>().FindByNameAsync(newUserName)).Should()
            .BeNull("no user was created");
    }

    [Fact]
    public async Task WithoutAnEnforcingPolicy_TheRestFacadesStillWrite()
    {
        var host = Host("none", RtDataPermissionDecision.Allowed);
        using var http = (FacadeCaller.User(TenantManagement, UserManagement) with
        {
            Subject = OctoObjectId.GenerateNewId().ToString()
        }).Client(host);
        var group = await NewGroupAsync();

        (await http.PutAsJsonAsync(TenantApiUrl($"groups/{group.RtId}/roles"), new[] { await NewRoleIdAsync() },
            TestContext.Current.CancellationToken)).StatusCode.Should().Be(HttpStatusCode.OK);
        (await GroupRoleIdsAsync(group)).Should().ContainSingle();
    }

    #region Helpers

    private async Task<(HttpResponseMessage Response, string MethodId, string Target, object Parameters,
        Func<Task> AssertUnchanged)> CallAsync(HttpClient http, string endpoint, CancellationToken ct)
    {
        switch (endpoint)
        {
            case "group.setRoles":
            {
                var group = await NewGroupAsync();
                var roleId = await NewRoleIdAsync();
                var role = await RoleNameAsync(roleId);
                return (await http.PutAsJsonAsync(TenantApiUrl($"groups/{group.RtId}/roles"), new[] { roleId }, ct),
                    SystemIdentityCkIds.GroupSetRolesMethodId, group.RtId.ToString(),
                    new GroupSetRolesParameters { RoleNames = [role] },
                    async () => (await GroupRoleIdsAsync(group)).Should().BeEmpty());
            }
            case "group.addUser":
            {
                var group = await NewGroupAsync();
                var user = await NewUserAsync();
                return (await http.PutAsync(TenantApiUrl($"groups/{group.RtId}/members/users/{user.RtId}"), null, ct),
                    SystemIdentityCkIds.GroupAddMemberMethodId, group.RtId.ToString(),
                    new GroupAddMemberParameters { MemberKind = RtGroupMemberKindEnum.User, MemberId = user.RtId.ToString() },
                    async () => (await GroupUserIdsAsync(group)).Should().BeEmpty());
            }
            case "group.removeUser":
            {
                var group = await NewGroupAsync();
                var user = await NewUserAsync();
                await WithGroupStoreAsync(s => s.AddMemberUserAsync(group.RtId, user.RtId.ToString()));
                return (await http.DeleteAsync(TenantApiUrl($"groups/{group.RtId}/members/users/{user.RtId}"), ct),
                    SystemIdentityCkIds.GroupRemoveMemberMethodId, group.RtId.ToString(),
                    new GroupRemoveMemberParameters { MemberKind = RtGroupMemberKindEnum.User, MemberId = user.RtId.ToString() },
                    async () => (await GroupUserIdsAsync(group)).Should().ContainSingle());
            }
            case "group.addGroup":
            {
                var group = await NewGroupAsync();
                var child = await NewGroupAsync();
                // Both are groups: the policy targets the parent only, so the child stays readable and a missing parent
                // check would let the call through instead of failing on the child.
                _targetIds.Add(group.RtId);
                return (await http.PutAsync(TenantApiUrl($"groups/{group.RtId}/members/groups/{child.RtId}"), null, ct),
                    SystemIdentityCkIds.GroupAddChildGroupMethodId, group.RtId.ToString(),
                    new GroupAddChildGroupParameters { ChildGroupId = child.RtId.ToString() },
                    async () => (await ChildGroupIdsAsync(group)).Should().BeEmpty());
            }
            case "client.addRole":
            case "client.setRoles":
            case "client.removeRole":
            {
                var client = await CreateTestClientAsync(NewName("tdc"));
                var roleId = await NewRoleIdAsync();
                var role = await RoleNameAsync(roleId);
                if (endpoint == "client.removeRole")
                {
                    using var scope = CreateScope();
                    await scope.ServiceProvider.GetRequiredService<IClientRoleStore>()
                        .ApplyRoleChangesAsync(client.RtId, [roleId], []);
                }

                var expectedRoles = endpoint == "client.removeRole" ? 1 : 0;
                Func<Task> unchanged = async () => (await ClientRoleIdsAsync(client)).Should().HaveCount(expectedRoles);
                return endpoint switch
                {
                    "client.addRole" => (await http.PutAsync(TenantApiUrl($"clients/{client.ClientId}/roles/{role}"), null, ct),
                        SystemIdentityCkIds.ClientAddRoleMethodId, client.RtId.ToString(),
                        new ClientAddRoleParameters { RoleName = role }, unchanged),
                    "client.setRoles" => (await http.PutAsJsonAsync(TenantApiUrl($"clients/{client.ClientId}/roles"),
                            new[] { roleId }, ct), SystemIdentityCkIds.ClientSetRolesMethodId, client.RtId.ToString(),
                        new ClientSetRolesParameters { RoleNames = [role] }, unchanged),
                    _ => (await http.DeleteAsync(TenantApiUrl($"clients/{client.ClientId}/roles/{role}"), ct),
                        SystemIdentityCkIds.ClientRemoveRoleMethodId, client.RtId.ToString(),
                        new ClientRemoveRoleParameters { RoleName = role }, unchanged)
                };
            }
            case "client.overlayUris":
            {
                var client = await CreateTestClientAsync(NewName("tdo"));
                return (await http.PostAsJsonAsync(TenantApiUrl($"clients/{client.ClientId}/overlayUris"),
                        new { overlayName = "tdp", redirectUris = new[] { "https://tdp.example/" } }, ct),
                    SystemIdentityCkIds.ClientApplyOverlayUrisMethodId, client.RtId.ToString(),
                    new ClientApplyOverlayUrisParameters { OverlayName = "tdp", RedirectUris = ["https://tdp.example/"] },
                    async () => (await LoadClientAsync(client)).RedirectUris.Should()
                        .NotContain(e => e.Uri == "https://tdp.example/"));
            }
            case "user.resetPassword":
            {
                var user = await NewUserAsync();
                var stamp = user.SecurityStamp;
                return (await http.PostAsJsonAsync(TenantApiUrl("users/ResetPassword"),
                        new { userName = user.UserName, password = "Td-P4ssw0rd!x" }, ct),
                    SystemIdentityCkIds.UserResetPasswordMethodId, user.RtId.ToString(),
                    new UserResetPasswordParameters { NewPassword = "Td-P4ssw0rd!y" },
                    async () => (await LoadUserAsync(user)).SecurityStamp.Should().Be(stamp));
            }
            default:
            {
                var user = await NewUserAsync();
                var roleId = await NewRoleIdAsync();
                var role = await RoleNameAsync(roleId);
                if (endpoint == "user.removeRole")
                {
                    using var scope = CreateScope();
                    var manager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
                    (await manager.AddToRoleAsync((await manager.FindByIdAsync(user.RtId.ToString()))!, role)).Succeeded
                        .Should().BeTrue();
                }

                return endpoint switch
                {
                    "user.addRole" => (await http.PutAsync(TenantApiUrl($"users/{user.UserName}/roles/{role}"), null, ct),
                        SystemIdentityCkIds.UserAddRoleMethodId, user.RtId.ToString(),
                        new UserAddRoleParameters { RoleName = role },
                        async () => (await UserRolesAsync(user)).Should().NotContain(role)),
                    "user.setRoles" => (await http.PutAsJsonAsync(TenantApiUrl($"users/{user.UserName}/roles"),
                            new[] { roleId }, ct), SystemIdentityCkIds.UserSetRolesMethodId, user.RtId.ToString(),
                        new UserSetRolesParameters { RoleNames = [role] },
                        async () => (await UserRolesAsync(user)).Should().NotContain(role)),
                    _ => (await http.DeleteAsync(TenantApiUrl($"users/{user.UserName}/roles/{role}"), ct),
                        SystemIdentityCkIds.UserRemoveRoleMethodId, user.RtId.ToString(),
                        new UserRemoveRoleParameters { RoleName = role },
                        async () => (await UserRolesAsync(user)).Should().Contain(role))
                };
            }
        }
    }

    private WebApplicationFactory<Program> Host(string targetKind, RtDataPermissionDecision onTarget)
    {
        var host = Factory.WithWebHostBuilder(b =>
        {
            b.UseSetting("Methods:Identity:EnablePasswordMethods", "false");
            b.ConfigureTestServices(services =>
            {
                // The test host has no broker: drop the bus side of the method host (announcement, heartbeat).
                foreach (var descriptor in services
                             .Where(d => d.ImplementationType?.Name is "CkMethodHandlerStartupService"
                                 or "CkMethodHandlerHeartbeatService").ToList())
                {
                    services.Remove(descriptor);
                }

                services.AddSingleton(_audit.Events);
                services.RemoveAll<IDistributionEventHubService>();
                services.AddSingleton(Substitute.For<IDistributionEventHubService>());
                services.AddSingleton(PolicyOnTarget(targetKind, onTarget, _targetIds));
            });
        });
        _hosts.Add(host);
        return host;
    }

    /// <summary>
    ///     An enforcing policy on the target type only: <see cref="RtDataPermissionDecision.NotVisible" /> for every action, or
    ///     <see cref="RtDataPermissionDecision.NotPermitted" /> = may read, may not write. Every other type is open.
    /// </summary>
    /// <summary>When not empty, the policy applies to exactly these targets instead of every entity of the target type.</summary>
    private readonly HashSet<OctoObjectId> _targetIds = [];

    private static IRtDataPermissionEvaluator PolicyOnTarget(string targetKind, RtDataPermissionDecision onTarget,
        HashSet<OctoObjectId> targetIds)
    {
        var targetType = targetKind switch
        {
            "group" => RtEntityExtensions.GetRtCkTypeId<RtGroup>(),
            "client" => RtEntityExtensions.GetRtCkTypeId<RtClient>(),
            "user" => RtEntityExtensions.GetRtCkTypeId<RtUser>(),
            "mapping" => RtEntityExtensions.GetRtCkTypeId<RtExternalTenantUserMapping>(),
            _ => (RtCkId<CkTypeId>?)null
        };
        var evaluator = Substitute.For<IRtDataPermissionEvaluator>();
        evaluator.EvaluateTypeAsync(Arg.Any<IRuntimeRepository>(), Arg.Any<RtSecurityContext>(),
                Arg.Any<RtCkId<CkTypeId>>(), Arg.Any<RtDataAction>(), Arg.Any<bool>(), Arg.Any<CancellationToken>())
            .Returns(call =>
            {
                var type = call.ArgAt<RtCkId<CkTypeId>>(2);
                var action = call.ArgAt<RtDataAction>(3);
                var decision = targetType != null && type == targetType &&
                               (onTarget == RtDataPermissionDecision.NotVisible || action != RtDataAction.Read)
                    ? onTarget
                    : RtDataPermissionDecision.Allowed;
                return new RtDataPermissionVerdict(decision, RtDataPermissionReason.NoGrant);
            });
        evaluator.EvaluateAsync(Arg.Any<IRuntimeRepository>(), Arg.Any<RtSecurityContext>(), Arg.Any<RtEntityId>(),
                Arg.Any<RtDataAction>(), Arg.Any<bool>(), Arg.Any<CancellationToken>())
            .Returns(call =>
            {
                var entity = call.ArgAt<RtEntityId>(2);
                var action = call.ArgAt<RtDataAction>(3);
                var decision = targetType != null && entity.CkTypeId == targetType &&
                               (targetIds.Count == 0 || targetIds.Contains(entity.RtId)) &&
                               (onTarget == RtDataPermissionDecision.NotVisible || action != RtDataAction.Read)
                    ? onTarget
                    : RtDataPermissionDecision.Allowed;
                return new RtDataPermissionVerdict(decision, RtDataPermissionReason.NoGrant);
            });
        return evaluator;
    }

    /// <summary>The method as the GraphQL gateway hands it to the identity service: the dispatcher, caller in scope.</summary>
    private async Task<CkMethodResponse> DispatchAsync(WebApplicationFactory<Program> host, string methodId,
        string? target, object parameters)
    {
        var request = new CkMethodRequest(NormalizedSystemTenantId)
        {
            InvocationId = Guid.NewGuid(),
            MethodId = methodId,
            CkTypeId = methodId[..methodId.LastIndexOf('.')],
            TargetRtId = target,
            ParametersJson = JsonSerializer.Serialize(parameters, parameters.GetType(), CkMethodJson.Options),
            DeadlineUtc = DateTime.UtcNow.AddSeconds(30)
        };
        var caller = new CkMethodPrincipal(OctoObjectId.GenerateNewId().ToString(), [TenantManagement, UserManagement],
            ["octo_api"]) { TokenTenantId = NormalizedSystemTenantId };
        using (CkMethodPrincipalScope.Begin(caller))
        {
            return await host.Services.GetRequiredService<ICkMethodDispatcher>()
                .InvokeAsync(request, TestContext.Current.CancellationToken);
        }
    }

    private static string NewName(string prefix) => $"{prefix}_{Guid.NewGuid():N}";

    private async Task<RtGroup> NewGroupAsync()
    {
        var name = NewName("tdg");
        var group = new RtGroup
        {
            RtId = OctoObjectId.GenerateNewId(), GroupName = name, NormalizedGroupName = name.ToUpperInvariant()
        };
        await WithGroupStoreAsync(s => s.StoreAsync(group));
        return group;
    }

    private async Task<string> NewRoleIdAsync()
    {
        using var scope = CreateScope();
        var role = new RtRoleBuilder().WithName(NewName("tdr")).Build();
        (await scope.ServiceProvider.GetRequiredService<RoleManager<RtRole>>().CreateAsync(role)).Succeeded.Should()
            .BeTrue();
        return role.RtId.ToString();
    }

    private async Task<string> RoleNameAsync(string roleId)
    {
        using var scope = CreateScope();
        return (await scope.ServiceProvider.GetRequiredService<RoleManager<RtRole>>().FindByIdAsync(roleId))!.Name!;
    }

    private Task<RtUser> NewUserAsync() => CreateTestUserAsync(NewName("tdu"));

    private async Task<ITenantRepository> SystemRepositoryAsync() =>
        (await Factory.Services.GetRequiredService<ISystemContext>().TryFindTenantRepositoryAsync(NormalizedSystemTenantId))!;

    private async Task<RtExternalTenantUserMapping> SeedMappingAsync(RtUser user)
    {
        var repo = await SystemRepositoryAsync();
        using var session = await repo.GetSessionAsync();
        var mapping = new RtExternalTenantUserMapping
        {
            RtId = OctoObjectId.GenerateNewId(),
            SourceTenantId = NormalizedSystemTenantId,
            SourceUserId = user.RtId.ToString(),
            SourceUserName = user.UserName!
        };
        await repo.InsertOneRtEntityAsync(session, mapping);
        return mapping;
    }

    private async Task<IReadOnlyCollection<RtExternalTenantUserMapping>> MappingsOfAsync(RtUser user)
    {
        var repo = await SystemRepositoryAsync();
        using var session = await repo.GetSessionAsync();
        return (await repo.GetRtEntitiesByTypeAsync<RtExternalTenantUserMapping>(session, RtEntityQueryOptions.Create()
                .FieldEquals(nameof(RtExternalTenantUserMapping.SourceUserId), user.RtId.ToString())))
            .Items.ToList();
    }

    private async Task WithGroupStoreAsync(Func<IGroupStore, Task> action)
    {
        using var scope = CreateScope();
        await action(scope.ServiceProvider.GetRequiredService<IGroupStore>());
    }

    private async Task<List<string>> GroupRoleIdsAsync(RtGroup group)
    {
        using var scope = CreateScope();
        return (await scope.ServiceProvider.GetRequiredService<IGroupStore>().GetRoleIdsAsync(group.RtId)).ToList();
    }

    private async Task<List<string>> GroupUserIdsAsync(RtGroup group)
    {
        using var scope = CreateScope();
        return (await scope.ServiceProvider.GetRequiredService<IGroupStore>().GetMemberUserIdsAsync(group.RtId)).ToList();
    }

    private async Task<List<string>> ChildGroupIdsAsync(RtGroup group)
    {
        using var scope = CreateScope();
        return (await scope.ServiceProvider.GetRequiredService<IGroupStore>().GetMemberGroupIdsAsync(group.RtId)).ToList();
    }

    private async Task<List<string>> ClientRoleIdsAsync(RtClient client)
    {
        using var scope = CreateScope();
        return (await scope.ServiceProvider.GetRequiredService<IClientRoleStore>().GetDirectRoleIdsAsync(client.RtId))
            .ToList();
    }

    private async Task<RtClient> LoadClientAsync(RtClient client)
    {
        using var scope = CreateScope();
        return (await scope.ServiceProvider.GetRequiredService<IOctoClientStore>().FindRtClientByIdAsync(client.ClientId!))!;
    }

    private async Task<RtUser> LoadUserAsync(RtUser user)
    {
        using var scope = CreateScope();
        return (await scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>().FindByIdAsync(user.RtId.ToString()))!;
    }

    private async Task<IList<string>> UserRolesAsync(RtUser user)
    {
        using var scope = CreateScope();
        var manager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
        return await manager.GetRolesAsync((await manager.FindByIdAsync(user.RtId.ToString()))!);
    }

    #endregion
}
