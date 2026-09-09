using FluentAssertions;
using IdentityServerPersistence.Services;
using IdentityServices.IntegrationTests.Fixtures;
using Meshmakers.Octo.Backend.Authentication.DynamicAuth;
using Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace IdentityServices.IntegrationTests.Persistence;

/// <summary>
/// End-to-end checks of the admin-provisioning source-user search + role listing (AB#4652) against a
/// real MongoDB (Testcontainers). These endpoints power the Studio's cross-tenant user picker; pin the
/// behaviour every consumer depends on: a target tenant's ancestor users are found by username/email,
/// <c>xt_</c> shadow users are excluded, tenants without a parent yield nothing, and the target's roles
/// are returned.
/// </summary>
public class AdminProvisioningSourceUsersIntegrationTests : IClassFixture<IdentityServicesFixture>
{
    private readonly IdentityServicesFixture _fixture;

    public AdminProvisioningSourceUsersIntegrationTests(
        IdentityServicesFixture fixture, ITestOutputHelper outputHelper)
    {
        _fixture = fixture;
        _fixture.OutputHelper = outputHelper;
    }

    [Fact]
    public async Task GetSourceUsers_FindsParentTenantUser_ByUsernameOrEmail()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        await EnsureSystemSetupAsync();

        var marker = Guid.NewGuid().ToString("N")[..12];
        var userName = $"pick-{marker}@example.io";
        await SeedUserInSystemTenantAsync(userName, userName);

        var childTenantId = await CreateChildTenantWithParentProviderAsync(
            $"child-src-{Guid.NewGuid():N}"[..24], systemContext.TenantId);

        var controller = CreateController(systemContext);

        // Match by username fragment...
        var byName = await OkValue(controller.GetSourceUsers(childTenantId, $"pick-{marker}", 20));
        byName.Should().ContainSingle(u => u.UserName == userName)
            .Which.SourceTenantId.Should().Be(systemContext.TenantId);

        // ...and by email fragment (same user).
        var byEmail = await OkValue(controller.GetSourceUsers(childTenantId, marker, 20));
        byEmail.Should().Contain(u => u.UserName == userName);
    }

    [Fact]
    public async Task GetSourceUsers_ExcludesCrossTenantShadowUsers()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        await EnsureSystemSetupAsync();

        var marker = Guid.NewGuid().ToString("N")[..12];
        var shadowUserName = $"xt_octosystem_shadow-{marker}@example.io";
        await SeedUserInSystemTenantAsync(shadowUserName, shadowUserName);

        var childTenantId = await CreateChildTenantWithParentProviderAsync(
            $"child-xt-{Guid.NewGuid():N}"[..24], systemContext.TenantId);

        var controller = CreateController(systemContext);

        var result = await OkValue(controller.GetSourceUsers(childTenantId, $"shadow-{marker}", 20));
        result.Should().NotContain(u => u.UserName == shadowUserName,
            "cross-tenant shadow users (xt_) must never be offered as provisioning candidates");
    }

    [Fact]
    public async Task GetSourceUsers_TenantWithoutParent_ReturnsEmpty()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        await EnsureSystemSetupAsync();

        // Child created WITHOUT an OctoTenantIdentityProvider → no ancestor chain.
        var childTenantId = await CreateChildTenantAsync($"child-noanc-{Guid.NewGuid():N}"[..24]);

        var controller = CreateController(systemContext);

        var result = await OkValue(controller.GetSourceUsers(childTenantId, "anything", 20));
        result.Should().BeEmpty();
    }

    [Fact]
    public async Task GetSourceUsers_UnknownTenant_ReturnsNotFound()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        await EnsureSystemSetupAsync();

        var controller = CreateController(systemContext);

        var action = await controller.GetSourceUsers($"missing-{Guid.NewGuid():N}"[..20], "x", 20);
        action.Result.Should().BeOfType<NotFoundObjectResult>();
    }

    [Fact]
    public async Task GetRoles_ReturnsTargetTenantRoles()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        await EnsureSystemSetupAsync();

        var childTenantId = await CreateChildTenantAsync($"child-roles-{Guid.NewGuid():N}"[..24]);
        // SetupAsync imports the CK model but does not seed default roles into a child (that happens on
        // the identity-service startup init path). Seed the roles the endpoint is supposed to return.
        await SeedRoleInTenantAsync(childTenantId, "TenantManagement");
        await SeedRoleInTenantAsync(childTenantId, "DashboardViewer");

        var controller = CreateController(systemContext);

        var action = await controller.GetRoles(childTenantId);
        var roles = ((action.Result as OkObjectResult)!.Value as IEnumerable<ProvisioningRoleDto>)!.ToList();

        roles.Should().NotBeEmpty();
        roles.Select(r => r.Name).Should().Contain(new[] { "TenantManagement", "DashboardViewer" });
        roles.Should().OnlyContain(r => !string.IsNullOrEmpty(r.Id) && !string.IsNullOrEmpty(r.Name));
    }

    [Fact]
    public async Task GetGroups_ReturnsTargetTenantGroups()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        await EnsureSystemSetupAsync();

        var childTenantId = await CreateChildTenantAsync($"child-grp-{Guid.NewGuid():N}"[..24]);
        await SeedGroupInTenantAsync(childTenantId, "TenantOwners");
        await SeedGroupInTenantAsync(childTenantId, "Viewers");

        var controller = CreateController(systemContext);

        var action = await controller.GetGroups(childTenantId);
        var groups = ((action.Result as OkObjectResult)!.Value as IEnumerable<ProvisioningGroupDto>)!.ToList();

        groups.Select(g => g.Name).Should().Contain(new[] { "TenantOwners", "Viewers" });
        groups.Should().OnlyContain(g => !string.IsNullOrEmpty(g.Id) && !string.IsNullOrEmpty(g.Name));
    }

    [Fact]
    public async Task CreateWithGroups_MakesMappingAGroupMember()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        await EnsureSystemSetupAsync();

        var childTenantId = await CreateChildTenantAsync($"child-cwg-{Guid.NewGuid():N}"[..24]);
        var groupRtId = await SeedGroupInTenantAsync(childTenantId, "Viewers");

        var marker = Guid.NewGuid().ToString("N")[..12];
        var controller = CreateController(systemContext);

        var action = await controller.CreateWithGroups(childTenantId, new CreateExternalTenantUserGroupMappingDto
        {
            SourceTenantId = systemContext.TenantId,
            SourceUserId = OctoObjectId.GenerateNewId().ToString(),
            SourceUserName = $"cwg-{marker}@example.io",
            GroupIds = [groupRtId]
        });

        var created = (action.Result as CreatedResult)!.Value as ExternalTenantUserMappingDto;
        created.Should().NotBeNull();
        created!.GroupNames.Should().Contain("Viewers");

        // Persisted: GetAll resolves the mapping's group membership via the inbound GroupMember edge.
        var all = ((await controller.GetAll(childTenantId)).Result as OkObjectResult)!
            .Value as IEnumerable<ExternalTenantUserMappingDto>;
        all!.Single(m => m.SourceUserName == $"cwg-{marker}@example.io")
            .GroupNames.Should().Contain("Viewers");
    }

    // ---------- helpers ----------

    private AdminProvisioningController CreateController(ISystemContext systemContext)
        => new(systemContext, new NoOpAuthSchemeService(),
            NullLogger<AdminProvisioningController>.Instance);

    private static async Task<List<ProvisioningSourceUserDto>> OkValue(
        Task<ActionResult<IEnumerable<ProvisioningSourceUserDto>>> action)
    {
        var result = await action;
        return ((result.Result as OkObjectResult)!.Value as IEnumerable<ProvisioningSourceUserDto>)!.ToList();
    }

    private async Task EnsureSystemSetupAsync()
    {
        var setup = _fixture.GetService<IDefaultConfigurationCreatorService>();
        await setup.SetupAsync(_fixture.GetSystemContext().TenantId);
    }

    private async Task<string> CreateChildTenantAsync(string tenantId)
    {
        var systemContext = _fixture.GetSystemContext();
        using var session = await systemContext.GetAdminSessionAsync();
        session.StartTransaction();
        try
        {
            await systemContext.CreateChildTenantAsync(session, tenantId, tenantId);
            await session.CommitTransactionAsync();
        }
        catch
        {
            await session.AbortTransactionAsync();
            throw;
        }

        var setup = _fixture.GetService<IDefaultConfigurationCreatorService>();
        await setup.SetupAsync(tenantId);
        return tenantId;
    }

    private async Task<string> CreateChildTenantWithParentProviderAsync(string tenantId, string parentTenantId)
    {
        await CreateChildTenantAsync(tenantId);

        var systemContext = _fixture.GetSystemContext();
        var childRepo = await systemContext.TryFindTenantRepositoryAsync(tenantId);
        childRepo.Should().NotBeNull();

        using var session = await childRepo!.GetSessionAsync();
        session.StartTransaction();
        try
        {
            // Only add the provider if the tenant setup didn't already create one for this parent.
            var existing = await childRepo.GetRtEntitiesByTypeAsync<RtOctoTenantIdentityProvider>(
                session, RtEntityQueryOptions.Create());
            if (existing.Items.All(p => !string.Equals(p.ParentTenantId, parentTenantId,
                    StringComparison.OrdinalIgnoreCase)))
            {
                await childRepo.InsertOneRtEntityAsync(session, new RtOctoTenantIdentityProvider
                {
                    RtId = OctoObjectId.GenerateNewId(),
                    Name = $"ParentTenant_{parentTenantId}",
                    DisplayName = $"Login via {parentTenantId}",
                    IsEnabled = true,
                    ParentTenantId = parentTenantId
                });
            }

            await session.CommitTransactionAsync();
        }
        catch
        {
            await session.AbortTransactionAsync();
            throw;
        }

        return tenantId;
    }

    private async Task SeedUserInSystemTenantAsync(string userName, string email)
    {
        var repo = _fixture.GetSystemContext().GetSystemTenantRepositoryAsAdmin();
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        try
        {
            await repo.InsertOneRtEntityAsync(session, new RtUser
            {
                RtId = OctoObjectId.GenerateNewId(),
                UserName = userName,
                NormalizedUserName = userName.ToUpperInvariant(),
                Email = email,
                NormalizedEmail = email.ToUpperInvariant(),
                SecurityStamp = Guid.NewGuid().ToString()
            });
            await session.CommitTransactionAsync();
        }
        catch
        {
            await session.AbortTransactionAsync();
            throw;
        }
    }

    private async Task SeedRoleInTenantAsync(string tenantId, string roleName)
    {
        var repo = await _fixture.GetSystemContext().TryFindTenantRepositoryAsync(tenantId);
        repo.Should().NotBeNull();
        using var session = await repo!.GetSessionAsync();
        session.StartTransaction();
        try
        {
            await repo.InsertOneRtEntityAsync(session, new RtRole
            {
                RtId = OctoObjectId.GenerateNewId(),
                Name = roleName,
                NormalizedName = roleName.ToUpperInvariant()
            });
            await session.CommitTransactionAsync();
        }
        catch
        {
            await session.AbortTransactionAsync();
            throw;
        }
    }

    private async Task<string> SeedGroupInTenantAsync(string tenantId, string groupName)
    {
        var repo = await _fixture.GetSystemContext().TryFindTenantRepositoryAsync(tenantId);
        repo.Should().NotBeNull();
        var rtId = OctoObjectId.GenerateNewId();
        using var session = await repo!.GetSessionAsync();
        session.StartTransaction();
        try
        {
            await repo.InsertOneRtEntityAsync(session, new RtGroup
            {
                RtId = rtId,
                GroupName = groupName,
                NormalizedGroupName = groupName.ToUpperInvariant()
            });
            await session.CommitTransactionAsync();
        }
        catch
        {
            await session.AbortTransactionAsync();
            throw;
        }

        return rtId.ToString();
    }

    /// <summary>No-op auth-scheme service; the read-only endpoints under test never reconfigure schemes.</summary>
    private sealed class NoOpAuthSchemeService : IDynamicAuthSchemeService
    {
        public Task ConfigureAsync(string tenantId) => Task.CompletedTask;
    }
}
