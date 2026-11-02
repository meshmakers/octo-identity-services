using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using FluentAssertions;
using IdentityServerPersistence;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using IdentityServices.IntegrationTests.Infrastructure;
using Meshmakers.Octo.Backend.IdentityServices.Controllers.Api;
using Meshmakers.Octo.Backend.IdentityServices.Services;
using Meshmakers.Octo.Communication.Contracts;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.Setup;

/// <summary>
///     AB#7946: the first administrator created by the tenant setup is a member of <c>TenantOwners</c>, so under the role
///     change guard (grant only built-in roles you hold) the administrator can add people to <c>TenantOwners</c>.
///     Real MongoDB, real identity host. The test database holds the built-in roles and a <c>TenantOwners</c> group in
///     the shape of the bootstrap blueprint (all non-secret roles, no SecretManagement); the setup runs through the
///     public <c>setup/create-admin</c> endpoint.
/// </summary>
public class SetupAdminTenantOwnersTests : IntegrationTestBase
{
    private const string AdminEmail = "first-admin@test.com";
    private const string AdminPassword = "SecurePass123!";

    // The roles the setup grants directly (SecretManagement is among them) ...
    private static readonly string[] DirectRoles =
    [
        CommonConstants.TenantManagementRole, CommonConstants.UserManagementRole, CommonConstants.DevelopmentRole,
        CommonConstants.CommunicationManagementRole, CommonConstants.BotManagementRole,
        CommonConstants.AdminPanelManagementRole, CommonConstants.SecretManagementRole,
        CommonConstants.DashboardViewerRole, CommonConstants.DashboardManagementRole,
        CommonConstants.ReportingManagementRole, CommonConstants.ReportingViewerRole,
        IdentityServiceConstants.FileManagementRole, IdentityServiceConstants.FileViewerRole
    ];

    // ... and the roles only TenantOwners carries (the gap this story closes).
    private static readonly string[] OwnersOnlyRoles =
        ["DataModelManagement", "StreamDataAdmin", "StreamDataWriter", "StreamDataReader"];

    public SetupAdminTenantOwnersTests(CustomWebApplicationFactory factory) : base(factory)
    {
    }

    [Fact]
    public async Task Setup_MakesTheFirstAdministratorAMemberOfTenantOwners_AndTheAdministratorCanAddAnotherUser()
    {
        var ct = TestContext.Current.CancellationToken;
        var owners = await ArrangeVirginTenantAsync();

        await RunSetupAsync();

        var admin = await FindAdminAsync();
        (await MembersAsync(owners)).Should().Contain(admin.RtId.ToString());

        var newcomer = await CreateTestUserAsync($"newcomer_{Guid.NewGuid():N}");
        using var client = await AdminClientAsync(admin);
        var response = await client.PutAsync(
            TenantApiUrl($"groups/{owners}/members/users/{newcomer.RtId}"), null, ct);

        response.StatusCode.Should().Be(HttpStatusCode.OK, await response.Content.ReadAsStringAsync(ct));
        (await MembersAsync(owners)).Should().Contain(newcomer.RtId.ToString());
    }

    [Fact]
    public async Task WithoutTheMembership_TheAdministratorCannotAddAnotherUser_TheGapOfTheDirectRolesOnly()
    {
        var ct = TestContext.Current.CancellationToken;
        var owners = await ArrangeVirginTenantAsync();
        await RunSetupAsync();
        var admin = await FindAdminAsync();
        using (var scope = CreateScope())
        {
            await scope.ServiceProvider.GetRequiredService<IGroupStore>()
                .RemoveMemberUserAsync(owners, admin.RtId.ToString());
        }

        var newcomer = await CreateTestUserAsync($"newcomer_{Guid.NewGuid():N}");
        using var client = await AdminClientAsync(admin);
        var response = await client.PutAsync(
            TenantApiUrl($"groups/{owners}/members/users/{newcomer.RtId}"), null, ct);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        var problem = await response.Content.ReadFromJsonAsync<JsonElement>(ct);
        problem.GetProperty("code").GetString().Should().Be("role-not-held");
    }

    [Fact]
    public async Task SetupRerun_IsRefused_AndDoesNotDuplicateTheMembership()
    {
        var ct = TestContext.Current.CancellationToken;
        var owners = await ArrangeVirginTenantAsync();
        await RunSetupAsync();
        var admin = await FindAdminAsync();

        using var anonymous = CreateAnonymousClient();
        var second = await anonymous.PostAsJsonAsync(ApiUrl("setup/create-admin", NormalizedSystemTenantId),
            NewSetupRequest(), ct);

        second.StatusCode.Should().Be(HttpStatusCode.NotFound);
        (await MembersAsync(owners)).Count(id => id == admin.RtId.ToString()).Should().Be(1);
    }

    [Fact]
    public void TheGuard_IsNotTakenByTheSetupService_OrTheGroupStore_SoTheSetupStaysExempt()
    {
        foreach (var type in new[] { typeof(UserManagementService), typeof(GroupStore) })
        {
            type.GetConstructors().SelectMany(c => c.GetParameters())
                .Should().NotContain(p => p.ParameterType.Name == "IRoleChangeGuard", type.Name);
        }
    }

    #region Helpers

    private static SetupAdminRequestDto NewSetupRequest() =>
        new() { Email = AdminEmail, Password = AdminPassword, ConfirmPassword = AdminPassword };

    private async Task RunSetupAsync()
    {
        using var anonymous = CreateAnonymousClient();
        var response = await anonymous.PostAsJsonAsync(ApiUrl("setup/create-admin", NormalizedSystemTenantId),
            NewSetupRequest(), TestContext.Current.CancellationToken);
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var result = await response.Content.ReadFromJsonAsync<SetupResultDto>(TestContext.Current.CancellationToken);
        result!.Success.Should().BeTrue(result.ErrorMessage);
    }

    /// <summary>
    ///     A client that carries the administrator's effective roles (direct and through groups) as the role claims of
    ///     its token, like a token the identity service issues at login; the guard judges the claims the caller holds.
    /// </summary>
    private async Task<HttpClient> AdminClientAsync(RtUser admin)
    {
        using var scope = CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
        var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<RtRole>>();
        var names = new HashSet<string>(await userManager.GetRolesAsync(admin), StringComparer.OrdinalIgnoreCase);
        var groupRoleIds = await scope.ServiceProvider.GetRequiredService<IGroupRoleResolver>()
            .ResolveEffectiveUserRoleIdsAsync(admin.RtId.ToString(), admin.UserName);
        foreach (var roleId in groupRoleIds)
        {
            var role = await roleManager.FindByIdAsync(roleId);
            names.Add(role!.Name!);
        }

        return CreateAuthenticatedClient(admin.RtId.ToString(), admin.UserName!, AdminEmail, roles: names);
    }

    private async Task<RtUser> FindAdminAsync()
    {
        using var scope = CreateScope();
        return (await scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>().FindByNameAsync(AdminEmail))!;
    }

    private async Task<IReadOnlyList<string>> MembersAsync(OctoObjectId group)
    {
        using var scope = CreateScope();
        return await scope.ServiceProvider.GetRequiredService<IGroupStore>().GetMemberUserIdsAsync(group);
    }

    /// <summary>
    ///     No users (the setup endpoint is active), the built-in roles and a TenantOwners group with every role except
    ///     SecretManagement, like the bootstrap blueprint. Returns the group id.
    /// </summary>
    private async Task<OctoObjectId> ArrangeVirginTenantAsync()
    {
        using var scope = CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
        foreach (var user in userManager.Users.ToList())
        {
            await userManager.DeleteAsync(user);
        }

        var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<RtRole>>();
        var ownerRoleIds = new List<string>();
        foreach (var name in DirectRoles.Concat(OwnersOnlyRoles))
        {
            var role = await roleManager.FindByNameAsync(name);
            if (role == null)
            {
                role = new RtRoleBuilder().WithName(name).Build();
                role.RtWellKnownName = name;
                (await roleManager.CreateAsync(role)).Succeeded.Should().BeTrue();
                role = (await roleManager.FindByNameAsync(name))!;
            }

            if (name != CommonConstants.SecretManagementRole)
            {
                ownerRoleIds.Add(role.RtId.ToString());
            }
        }

        var groups = scope.ServiceProvider.GetRequiredService<IGroupStore>();
        var owners = await groups.FindByNameAsync(CommonConstants.TenantOwnersGroup.ToUpperInvariant());
        if (owners == null)
        {
            owners = new RtGroup
            {
                RtId = OctoObjectId.GenerateNewId(),
                GroupName = CommonConstants.TenantOwnersGroup,
                NormalizedGroupName = CommonConstants.TenantOwnersGroup.ToUpperInvariant()
            };
            await groups.StoreAsync(owners);
        }

        await groups.SetRoleIdsAsync(owners.RtId, ownerRoleIds);
        foreach (var member in await groups.GetMemberUserIdsAsync(owners.RtId))
        {
            await groups.RemoveMemberUserAsync(owners.RtId, member);
        }

        return owners.RtId;
    }

    #endregion
}
