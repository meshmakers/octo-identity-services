using System.Net;
using System.Net.Http.Json;
using FluentAssertions;
using IdentityServices.IntegrationTests.Infrastructure;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.TenantApi;

/// <summary>
/// AB#5859: the tenant REST API authorizes administration endpoints by tenant role, not by scope alone.
/// Every request runs through the real pipeline (authentication, tenant gate, authorization policies,
/// controllers) against MongoDB; only the token is simulated by <see cref="TestAuthHandler"/>, which emits
/// roles as the raw JWT <c>role</c> claim like a real access token.
/// </summary>
public class TenantApiRoleAuthorizationTests : IntegrationTestBase
{
    private const string UserManagement = "UserManagement";
    private const string TenantManagement = "TenantManagement";
    private const string CommunicationManagement = "CommunicationManagement";
    private const string NonAdministrativeRole = "DashboardViewer";

    public TenantApiRoleAuthorizationTests(CustomWebApplicationFactory factory) : base(factory)
    {
    }

    private HttpClient ClientWithRoles(params string[] roles)
    {
        var client = CreateAuthenticatedClient(userId: $"caller-{Guid.NewGuid():N}", roles: roles);
        if (roles.Length == 0)
        {
            client.DefaultRequestHeaders.Add(TestAuthHandler.NoRolesHeader, "true");
        }

        return client;
    }

    private HttpClient ServiceClientWithRoles(params string[] roles)
    {
        var client = ClientWithRoles(roles);
        client.DefaultRequestHeaders.Add(TestAuthHandler.ClientCredentialsHeader, $"svc-{Guid.NewGuid():N}");
        return client;
    }

    private async Task<bool> IsInRoleAsync(string userName, string roleName)
    {
        using var scope = CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
        var user = await userManager.FindByNameAsync(userName);
        user.Should().NotBeNull();
        return await userManager.IsInRoleAsync(user!, roleName.ToUpperInvariant());
    }

    // ---------------------------------------------------------------- the reported escalation

    [Theory]
    [InlineData("")]
    [InlineData(NonAdministrativeRole)]
    [InlineData(TenantManagement)]
    public async Task AddUserToRole_WithoutUserManagement_Is403_AndAssignsNothing(string role)
    {
        string[] roles = role.Length == 0 ? [] : [role];
        var userName = $"escalate-{Guid.NewGuid():N}";
        await CreateTestUserAsync(userName);

        var response = await ClientWithRoles(roles)
            .PutAsync(TenantApiUrl($"users/{userName}/roles/{UserManagement}"), null,
                TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await IsInRoleAsync(userName, UserManagement)).Should().BeFalse();
    }

    [Fact]
    public async Task AddUserToRole_WithUserManagement_Succeeds()
    {
        var userName = $"granted-{Guid.NewGuid():N}";
        await CreateTestUserAsync(userName);

        var response = await ClientWithRoles(UserManagement)
            .PutAsync(TenantApiUrl($"users/{userName}/roles/{UserManagement}"), null,
                TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        (await IsInRoleAsync(userName, UserManagement)).Should().BeTrue();
    }

    [Fact]
    public async Task CreateGroup_WithoutUserManagement_Is403()
    {
        var response = await ClientWithRoles(NonAdministrativeRole).PostAsJsonAsync(TenantApiUrl("groups"),
            new { groupName = $"g-{Guid.NewGuid():N}" }, TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task CreateGroup_WithUserManagement_Succeeds()
    {
        var response = await ClientWithRoles(UserManagement).PostAsJsonAsync(TenantApiUrl("groups"),
            new { groupName = $"g-{Guid.NewGuid():N}" }, TestContext.Current.CancellationToken);

        response.IsSuccessStatusCode.Should().BeTrue($"status was {response.StatusCode}");
    }

    [Fact]
    public async Task RelaxIdentityDataPolicy_WithoutUserManagement_Is403()
    {
        // 660…51 = the built-in IdentityAdministrationPolicy seeded by System.Identity.Bootstrap.
        var response = await ClientWithRoles(NonAdministrativeRole).PutAsJsonAsync(
            TenantApiUrl("dataPermissions/policies/660000000000000000000051/enforcementMode"), "AuditOnly",
            TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task ListUsers_WithoutUserManagement_Is403_WithUserManagement_Is200()
    {
        var denied = await ClientWithRoles(NonAdministrativeRole)
            .GetAsync(TenantApiUrl("users"), TestContext.Current.CancellationToken);
        var allowed = await ClientWithRoles(UserManagement)
            .GetAsync(TenantApiUrl("users"), TestContext.Current.CancellationToken);

        denied.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        allowed.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    // ---------------------------------------------------------------- tenant configuration

    [Fact]
    public async Task ListClients_RequiresTenantOrUserManagement()
    {
        var denied = await ClientWithRoles(NonAdministrativeRole)
            .GetAsync(TenantApiUrl("clients"), TestContext.Current.CancellationToken);
        var tenantManager = await ClientWithRoles(TenantManagement)
            .GetAsync(TenantApiUrl("clients"), TestContext.Current.CancellationToken);
        var userManager = await ClientWithRoles(UserManagement)
            .GetAsync(TenantApiUrl("clients"), TestContext.Current.CancellationToken);

        denied.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        tenantManager.StatusCode.Should().Be(HttpStatusCode.OK);
        userManager.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task ListIdentityProviders_WithoutRole_Is403()
    {
        var response = await ClientWithRoles()
            .GetAsync(TenantApiUrl("identityProviders"), TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    // ---------------------------------------------------------------- directory reads

    [Fact]
    public async Task ListRoles_IsReadableForCommunicationManagement_ButNotWithoutRole()
    {
        // The Studio's service-account panels (adapter detail, data-flow editor) read role names with
        // CommunicationManagement; the communication controller forwards that token as well.
        var allowed = await ClientWithRoles(CommunicationManagement)
            .GetAsync(TenantApiUrl("roles"), TestContext.Current.CancellationToken);
        var denied = await ClientWithRoles(NonAdministrativeRole)
            .GetAsync(TenantApiUrl("roles"), TestContext.Current.CancellationToken);

        allowed.StatusCode.Should().Be(HttpStatusCode.OK);
        denied.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task CreateRole_WithCommunicationManagement_Is403()
    {
        // Directory read access never extends to writes.
        var response = await ClientWithRoles(CommunicationManagement).PostAsJsonAsync(TenantApiUrl("roles"),
            new { name = $"r-{Guid.NewGuid():N}" }, TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    // ---------------------------------------------------------------- self-service stays open

    [Fact]
    public async Task OwnDiagnostics_And_PasswordGenerator_StayOpenWithoutRole()
    {
        var client = ClientWithRoles();

        var diagnostics = await client.GetAsync(TenantApiUrl("diagnostics"), TestContext.Current.CancellationToken);
        var password = await client.GetAsync(TenantApiUrl("tools/generatePassword"),
            TestContext.Current.CancellationToken);

        diagnostics.StatusCode.Should().Be(HttpStatusCode.OK);
        password.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task WithoutToken_Is401()
    {
        var response = await CreateAnonymousClient()
            .GetAsync(TenantApiUrl("users"), TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    // ---------------------------------------------------------------- scope still applies

    [Fact]
    public async Task ReadOnlyScope_WithUserManagement_CanReadButNotWrite()
    {
        var client = CreateAuthenticatedClient(userId: $"ro-{Guid.NewGuid():N}", roles: [UserManagement],
            scopes: ["octo_api.read_only"]);
        var userName = $"ro-target-{Guid.NewGuid():N}";
        await CreateTestUserAsync(userName);

        var read = await client.GetAsync(TenantApiUrl("users"), TestContext.Current.CancellationToken);
        var write = await client.PutAsync(TenantApiUrl($"users/{userName}/roles/{UserManagement}"), null,
            TestContext.Current.CancellationToken);

        read.StatusCode.Should().Be(HttpStatusCode.OK);
        write.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    // ---------------------------------------------------------------- service clients

    [Fact]
    public async Task ClientCredentialsToken_IsJudgedByTheClientRoles()
    {
        // Service clients carry their effective client roles (AB#4183) — a provisioning client needs
        // UserManagement assigned to it; a role-less service client is refused like a user.
        var withRole = await ServiceClientWithRoles(UserManagement)
            .GetAsync(TenantApiUrl("users"), TestContext.Current.CancellationToken);
        var withoutRole = await ServiceClientWithRoles()
            .GetAsync(TenantApiUrl("users"), TestContext.Current.CancellationToken);

        withRole.StatusCode.Should().Be(HttpStatusCode.OK);
        withoutRole.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    // ---------------------------------------------------------------- service-wide operations

    [Fact]
    public async Task ReconfigureLogLevel_WithoutTenantManagement_Is403()
    {
        // Only the denial is exercised: a granted call would reconfigure the process-wide NLog
        // configuration, which parallel test hosts share (see CLAUDE.md, AB#5440).
        const string url = "diagnostics/reconfigureLogLevel?minLogLevel=Info&maxLogLevel=Fatal&loggerName=AB5859";

        var denied = await ClientWithRoles(UserManagement)
            .PostAsync(TenantApiUrl(url), null, TestContext.Current.CancellationToken);

        denied.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    // ---------------------------------------------------------------- admin flows unchanged

    [Fact]
    public async Task DefaultAdministratorCaller_KeepsFullAccess()
    {
        // The default test caller holds the TenantOwners roles — the admin flows of the other tests
        // in this project run with it unchanged.
        var users = await Client.GetAsync(TenantApiUrl("users"), TestContext.Current.CancellationToken);
        var clients = await Client.GetAsync(TenantApiUrl("clients"), TestContext.Current.CancellationToken);
        var groups = await Client.GetAsync(TenantApiUrl("groups"), TestContext.Current.CancellationToken);
        var mappings = await Client.GetAsync(TenantApiUrl($"adminProvisioning/{NormalizedSystemTenantId}"),
            TestContext.Current.CancellationToken);

        users.StatusCode.Should().Be(HttpStatusCode.OK);
        clients.StatusCode.Should().Be(HttpStatusCode.OK);
        groups.StatusCode.Should().Be(HttpStatusCode.OK);
        mappings.StatusCode.Should().Be(HttpStatusCode.OK);
    }
}
