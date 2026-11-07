using System.Net;
using System.Net.Http.Json;
using FluentAssertions;
using IdentityServerPersistence.Services;
using IdentityServices.IntegrationTests.Infrastructure;
using Meshmakers.Octo.Backend.IdentityServices.Controllers.Api;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Microsoft.Extensions.DependencyInjection;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.Auth;

/// <summary>
///     AB#8439 — the interactive cross-tenant login and the tenant switch create the shadow user, but never an
///     <see cref="RtExternalTenantUserMapping" />. A mapping is an admin's grant; a bare one written by a login counted
///     as explicit provisioning (<see cref="ICrossTenantUserProvisioningService.IsExplicitlyProvisionedAsync" />) and
///     bypassed <c>AllowSelfRegistration=false</c> on every later login.
/// </summary>
/// <remarks>
///     The source tenant A is the factory's system tenant; each test creates its own child tenant B with an enabled
///     <see cref="RtOctoTenantIdentityProvider" /> pointing to A.
/// </remarks>
public class CrossTenantLoginMappingTests : IntegrationTestBase
{
    public CrossTenantLoginMappingTests(CustomWebApplicationFactory factory) : base(factory)
    {
    }

    private string SourceTenantId => NormalizedSystemTenantId;

    [Fact]
    public async Task PasswordLogin_NewShadowUser_CreatesNoMapping()
    {
        var ct = TestContext.Current.CancellationToken;
        var childTenantId = await CreateChildTenantAsync(allowSelfRegistration: true);
        var userName = NewUserName("pwd");
        await CreateTestUserAsync(userName, password: DefaultPassword);

        var login = await PasswordLoginAsync(CreateCookieClient(), childTenantId, userName, ct);

        login.Success.Should().BeTrue("self-registration is allowed: {0}", login.ErrorMessage);
        (await FindChildUserAsync(childTenantId, ShadowName(userName))).Should().NotBeNull();
        (await GetChildMappingsAsync(childTenantId)).Should().BeEmpty(
            "a login creates the shadow user, never an ExternalTenantUserMapping");
    }

    [Fact]
    public async Task CrossTenantTokenLogin_NewShadowUser_CreatesNoMapping()
    {
        var ct = TestContext.Current.CancellationToken;
        var childTenantId = await CreateChildTenantAsync(allowSelfRegistration: true);
        var userName = NewUserName("tok");
        await CreateTestUserAsync(userName, password: DefaultPassword);
        var sourceSession = (await LoginAndGetAuthenticatedClientAsync(userName, DefaultPassword, ct))!;

        var tokenResponse = await sourceSession.PostAsJsonAsync(AuthApiUrl("cross-tenant-token", SourceTenantId),
            new CrossTenantTokenRequestDto { TargetTenantId = childTenantId }, ct);
        tokenResponse.StatusCode.Should().Be(HttpStatusCode.OK);
        var token = (await tokenResponse.Content.ReadFromJsonAsync<CrossTenantTokenResultDto>(ct))!.Token;

        var response = await CreateCookieClient().PostAsJsonAsync(AuthApiUrl("cross-tenant-login", childTenantId),
            new CrossTenantLoginRequestDto { Token = token }, ct);
        var login = (await response.Content.ReadFromJsonAsync<LoginResultDto>(ct))!;

        login.Success.Should().BeTrue("self-registration is allowed: {0}", login.ErrorMessage);
        (await FindChildUserAsync(childTenantId, ShadowName(userName))).Should().NotBeNull();
        (await GetChildMappingsAsync(childTenantId)).Should().BeEmpty(
            "the cross-tenant login creates the shadow user, never an ExternalTenantUserMapping");
    }

    [Fact]
    public async Task TenantSwitch_CreatesNoMapping()
    {
        var ct = TestContext.Current.CancellationToken;
        var childTenantId = await CreateChildTenantAsync(allowSelfRegistration: true);
        var userName = NewUserName("switch");
        var user = await CreateTestUserAsync(userName, password: DefaultPassword);
        var browser = CreateCookieClient();
        (await PasswordLoginAsync(browser, childTenantId, userName, ct)).Success.Should().BeTrue();

        var response = await browser.PostAsJsonAsync(AuthApiUrl("tenant-switch", childTenantId),
            new TenantSwitchRequestDto { SourceTenantId = SourceTenantId, SourceUserId = user.RtId.ToString() }, ct);
        var result = (await response.Content.ReadFromJsonAsync<TenantSwitchResultDto>(ct))!;

        result.Success.Should().BeTrue("the caller's own source identity may switch: {0}", result.ErrorMessage);
        (await GetChildMappingsAsync(childTenantId)).Should().BeEmpty(
            "neither the login nor the tenant switch writes an ExternalTenantUserMapping");
    }

    [Fact]
    public async Task SelfRegistrationDisabledLater_UserWhoOnlyEverSelfRegistered_IsRefusedAfterTheShadowUserIsGone()
    {
        // The repro of AB#8439: the first login (self-registration allowed) left a bare mapping behind; once the
        // provider disallowed self-registration and the shadow user was removed, that mapping still let the person in.
        var ct = TestContext.Current.CancellationToken;
        var childTenantId = await CreateChildTenantAsync(allowSelfRegistration: true);
        var userName = NewUserName("flip");
        await CreateTestUserAsync(userName, password: DefaultPassword);
        (await PasswordLoginAsync(CreateCookieClient(), childTenantId, userName, ct)).Success.Should().BeTrue();

        await DeleteChildUserAsync(childTenantId, ShadowName(userName));
        await SetAllowSelfRegistrationAsync(childTenantId, false);

        var second = await PasswordLoginAsync(CreateCookieClient(), childTenantId, userName, ct);

        second.Success.Should().BeFalse("nobody provisioned this user; the earlier login must not count as provisioning");
        second.ErrorMessage.Should().Contain("Self-registration");
        (await FindChildUserAsync(childTenantId, ShadowName(userName))).Should().BeNull();
        (await GetChildMappingsAsync(childTenantId)).Should().BeEmpty();
    }

    [Fact]
    public async Task SelfRegistrationDisabled_WithoutAdminMapping_IsRefused()
    {
        var ct = TestContext.Current.CancellationToken;
        var childTenantId = await CreateChildTenantAsync(allowSelfRegistration: false);
        var userName = NewUserName("noreg");
        await CreateTestUserAsync(userName, password: DefaultPassword);

        var login = await PasswordLoginAsync(CreateCookieClient(), childTenantId, userName, ct);

        login.Success.Should().BeFalse();
        login.ErrorMessage.Should().Contain("Self-registration");
        (await FindChildUserAsync(childTenantId, ShadowName(userName))).Should().BeNull();
        (await GetChildMappingsAsync(childTenantId)).Should().BeEmpty();
    }

    [Fact]
    public async Task SelfRegistrationDisabled_WithAdminMapping_SignsInAndKeepsTheMappingUnchanged()
    {
        var ct = TestContext.Current.CancellationToken;
        var childTenantId = await CreateChildTenantAsync(allowSelfRegistration: false);
        var userName = NewUserName("admmap");
        var user = await CreateTestUserAsync(userName, password: DefaultPassword);
        var roleId = await CreateAdminMappingAsync(childTenantId, user);

        var browser = CreateCookieClient();
        var login = await PasswordLoginAsync(browser, childTenantId, userName, ct);

        login.Success.Should().BeTrue("an admin-created mapping is explicit provisioning: {0}", login.ErrorMessage);
        (await FindChildUserAsync(childTenantId, ShadowName(userName))).Should().NotBeNull();
        var mapping = (await GetChildMappingsAsync(childTenantId)).Should().ContainSingle().Subject;
        mapping.SourceUserId.Should().Be(user.RtId.ToString());
        mapping.MappedRoleIds.Should().BeEquivalentTo([roleId]);

        // The tenant switch of the same person also keeps working and writes nothing.
        var response = await browser.PostAsJsonAsync(AuthApiUrl("tenant-switch", childTenantId),
            new TenantSwitchRequestDto { SourceTenantId = SourceTenantId }, ct);
        (await response.Content.ReadFromJsonAsync<TenantSwitchResultDto>(ct))!.Success.Should().BeTrue();
        (await GetChildMappingsAsync(childTenantId)).Should().ContainSingle();
    }

    #region Helpers

    private static string NewUserName(string prefix) => $"xtmap_{prefix}_{Guid.NewGuid():N}"[..28];

    private string ShadowName(string userName) => CrossTenantShadowUserName.Build(SourceTenantId, userName);

    private async Task<LoginResultDto> PasswordLoginAsync(HttpClient browser, string tenantId, string userName,
        CancellationToken ct)
    {
        var response = await browser.PostAsJsonAsync(AuthApiUrl("login", tenantId),
            new LoginRequestDto { Username = userName, Password = DefaultPassword }, ct);
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        return (await response.Content.ReadFromJsonAsync<LoginResultDto>(ct))!;
    }

    private async Task<ITenantRepository> GetChildRepoAsync(string childTenantId)
        => (await Factory.Services.GetRequiredService<ISystemContext>().TryFindTenantRepositoryAsync(childTenantId))!;

    private async Task<IReadOnlyList<RtExternalTenantUserMapping>> GetChildMappingsAsync(string childTenantId)
    {
        var repo = await GetChildRepoAsync(childTenantId);
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        var result = await repo.GetRtEntitiesByTypeAsync<RtExternalTenantUserMapping>(session,
            RtEntityQueryOptions.Create());
        await session.CommitTransactionAsync();
        return result.Items.ToList();
    }

    private async Task<RtUser?> FindChildUserAsync(string childTenantId, string userName)
    {
        var repo = await GetChildRepoAsync(childTenantId);
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        var result = await repo.GetRtEntitiesByTypeAsync<RtUser>(session,
            RtEntityQueryOptions.Create().FieldEquals(nameof(RtUser.UserName), userName));
        await session.CommitTransactionAsync();
        return result.Items.SingleOrDefault();
    }

    private async Task DeleteChildUserAsync(string childTenantId, string userName)
    {
        var user = await FindChildUserAsync(childTenantId, userName);
        user.Should().NotBeNull();
        var repo = await GetChildRepoAsync(childTenantId);
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        await repo.DeleteOneRtEntityByRtIdAsync<RtUser>(session, user!.RtId, DeleteOptions.Erase);
        await session.CommitTransactionAsync();
    }

    private async Task SetAllowSelfRegistrationAsync(string childTenantId, bool allow)
    {
        var repo = await GetChildRepoAsync(childTenantId);
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        var provider = (await repo.GetRtEntitiesByTypeAsync<RtOctoTenantIdentityProvider>(session,
            RtEntityQueryOptions.Create())).Items.Single();
        provider.AllowSelfRegistration = allow;
        await repo.ReplaceOneRtEntityByIdAsync(session, provider.RtId, provider);
        await session.CommitTransactionAsync();
    }

    /// <summary>Explicit provisioning in B, as the mapping API / ProvisionCurrentUser write it: a mapping with a role.</summary>
    private async Task<string> CreateAdminMappingAsync(string childTenantId, RtUser sourceUser)
    {
        var repo = await GetChildRepoAsync(childTenantId);
        var roleName = $"xtmaprole{Guid.NewGuid():N}"[..20];
        var roleId = OctoObjectId.GenerateNewId();
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        await repo.InsertOneRtEntityAsync(session, new RtRole
        {
            RtId = roleId,
            Name = roleName,
            NormalizedName = roleName.ToUpperInvariant()
        });
        await repo.InsertOneRtEntityAsync(session, new RtExternalTenantUserMapping
        {
            RtId = OctoObjectId.GenerateNewId(),
            SourceTenantId = SourceTenantId,
            SourceUserId = sourceUser.RtId.ToString(),
            SourceUserName = sourceUser.UserName!,
            MappedRoleIds = new AttributeStringValueList { roleId.ToString() }
        });
        await session.CommitTransactionAsync();
        return roleId.ToString();
    }

    private async Task<string> CreateChildTenantAsync(bool allowSelfRegistration)
    {
        var childTenantId = $"xtmap{Guid.NewGuid():N}"[..20];
        var systemContext = Factory.Services.GetRequiredService<ISystemContext>();
        using (var session = await systemContext.GetAdminSessionAsync())
        {
            session.StartTransaction();
            await systemContext.CreateChildTenantAsync(session, childTenantId, childTenantId);
            await session.CommitTransactionAsync();
        }

        using (var scope = CreateScope())
        {
            await scope.ServiceProvider.GetRequiredService<IDefaultConfigurationCreatorService>()
                .SetupAsync(childTenantId);
        }

        var childRepo = await GetChildRepoAsync(childTenantId);
        using (var session = await childRepo.GetSessionAsync())
        {
            session.StartTransaction();
            await childRepo.InsertOneRtEntityAsync(session, new RtOctoTenantIdentityProvider
            {
                RtId = OctoObjectId.GenerateNewId(),
                Name = $"ParentTenant_{SourceTenantId}",
                DisplayName = $"Login via {SourceTenantId}",
                IsEnabled = true,
                AllowSelfRegistration = allowSelfRegistration,
                ParentTenantId = SourceTenantId
            });
            await session.CommitTransactionAsync();
        }

        await WaitUntilRegistryKnowsAsync(childTenantId);
        return childTenantId;
    }

    /// <summary>
    ///     The cross-tenant services read tenants through the cached <see cref="ITenantRegistry" />; a tenant created a
    ///     moment ago is invisible for up to <see cref="TenantRegistry.MissRefreshInterval" /> (same wait as
    ///     <see cref="CrossTenantSecondFactorTests" />).
    /// </summary>
    private async Task WaitUntilRegistryKnowsAsync(string tenantId)
    {
        var deadline = DateTimeOffset.UtcNow + TenantRegistry.MissRefreshInterval + TimeSpan.FromSeconds(10);
        while (DateTimeOffset.UtcNow < deadline)
        {
            using var scope = CreateScope();
            if (await scope.ServiceProvider.GetRequiredService<ITenantRegistry>().TryGetRepositoryAsync(tenantId) != null)
            {
                return;
            }

            await Task.Delay(TimeSpan.FromMilliseconds(500), TestContext.Current.CancellationToken);
        }

        throw new InvalidOperationException($"Tenant '{tenantId}' did not appear in the tenant registry");
    }

    #endregion
}
