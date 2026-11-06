using FluentAssertions;
using IdentityServerPersistence.Configuration.Options;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using IdentityServices.IntegrationTests.Fixtures;
using Meshmakers.Octo.Backend.Authentication.DynamicAuth;
using Meshmakers.Octo.Backend.IdentityServices.OpenIddict;
using Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using OpenIddict.Server;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Xunit;

namespace IdentityServices.IntegrationTests.Persistence;

/// <summary>
///     AB#8339 against a real MongoDB: the tenant registry, not the OctoTenant identity providers a tenant's own
///     administrator writes, decides cross-tenant ancestry — for the provisioning source users, the tenant switch (token
///     exchange gate) and the cross-tenant login; and the provisioning writes refuse a non-ancestor source.
/// </summary>
/// <remarks>
///     Registry hierarchy of every test: system (R) → P → T, and system → S (a stranger to T). T's providers point at P
///     (its real parent) and, written by T's admin, at S; P's provider points at R. Users live in R, P and S.
/// </remarks>
public class CrossTenantAncestryIntegrationTests : IClassFixture<IdentityServicesFixture>
{
    private const string Password = "Correct-Horse-8339";

    private readonly IdentityServicesFixture _fixture;

    public CrossTenantAncestryIntegrationTests(IdentityServicesFixture fixture, ITestOutputHelper outputHelper)
    {
        _fixture = fixture;
        _fixture.OutputHelper = outputHelper;
    }

    [Fact]
    public async Task Enforce_StrangerProvider_OpensNeitherSourceUsersNorTheExchangeNorTheLogin()
    {
        var h = await ArrangeAsync();
        var auth = await CreateAuthServiceAsync(CrossTenantAncestryMode.Enforce, h.Target);

        var users = await SourceUsersAsync(CreateController(CrossTenantAncestryMode.Enforce), h.Target, h.StrangerUser.Name);
        users.Should().NotContain(u => u.SourceTenantId == h.Stranger, "the stranger's directory stays closed");

        (await auth.ValidateCrossTenantAccessAsync(h.Target, h.Stranger, h.StrangerUser.Id.ToString()))
            .Should().BeNull("the stranger is no ancestor of the target in the registry");
        (await (await CreateExchangeProcessorAsync(auth, h.Target))
                .ResolveExchangeSourceAsync(h.Target, h.Stranger, h.StrangerUser.Id.ToString()))
            .Should().BeNull("the token exchange from the stranger is refused");
        (await auth.AuthenticateAsync(h.Target, h.StrangerUser.Name, Password))
            .Should().BeNull("the stranger's users cannot log in to the target with their password");
    }

    [Fact]
    public async Task Enforce_RegistryParentAndGrandparent_StillWork()
    {
        var h = await ArrangeAsync();
        var auth = await CreateAuthServiceAsync(CrossTenantAncestryMode.Enforce, h.Target);
        var controller = CreateController(CrossTenantAncestryMode.Enforce);

        (await SourceUsersAsync(controller, h.Target, h.ParentUser.Name))
            .Should().Contain(u => u.SourceTenantId == h.Parent && u.UserName == h.ParentUser.Name);
        (await SourceUsersAsync(controller, h.Target, h.RootUser.Name))
            .Should().Contain(u => u.SourceTenantId == h.Root && u.UserName == h.RootUser.Name);

        (await auth.ValidateCrossTenantAccessAsync(h.Target, h.Parent, h.ParentUser.Id.ToString()))
            .Should().NotBeNull("the registry parent may switch into the target");
        (await auth.ValidateCrossTenantAccessAsync(h.Target, h.Root, h.RootUser.Id.ToString()))
            .Should().NotBeNull("the registry grandparent may switch into the target");

        var login = await auth.AuthenticateAsync(h.Target, h.RootUser.Name, Password);
        login.Should().NotBeNull("the cross-tenant login walks target → parent → grandparent");
        login!.SourceTenantId.Should().Be(h.Root);
    }

    /// <summary>
    ///     Concept step 1a: a shadow user of a registry ancestor's user, held by a sibling of the target, exchanges into the
    ///     target as its home identity — the sibling itself is no ancestor and must not need to be one.
    /// </summary>
    [Fact]
    public async Task Enforce_ShadowOfAnAncestorUserInASiblingTenant_StillExchangesAsTheHomeIdentity()
    {
        var h = await ArrangeAsync();
        var systemContext = _fixture.GetSystemContext();
        var sibling = await CreateChildAsync((await systemContext.TryFindTenantContextAsync(h.Parent))!, NewId("sib"));
        var shadow = await CreateUserAsync(sibling, CrossTenantShadowUserName.Build(h.Parent, h.ParentUser.Name));
        var auth = await CreateAuthServiceAsync(CrossTenantAncestryMode.Enforce, h.Target);

        var result = await (await CreateExchangeProcessorAsync(auth, h.Target))
            .ResolveExchangeSourceAsync(h.Target, sibling, shadow.Id.ToString());

        result.Should().NotBeNull();
        result!.SourceTenantId.Should().Be(h.Parent);
        result.SourceUserId.Should().Be(h.ParentUser.Id.ToString());
    }

    [Fact]
    public async Task Warn_StrangerProvider_BehavesAsBefore_AndLogsBothTenantIds()
    {
        var h = await ArrangeAsync();
        var log = new CapturingLogger<CrossTenantAncestryGuard>();
        var auth = await CreateAuthServiceAsync(CrossTenantAncestryMode.Warn, h.Target, log);

        var users = await SourceUsersAsync(CreateController(CrossTenantAncestryMode.Warn, log), h.Target,
            h.StrangerUser.Name);
        users.Should().Contain(u => u.SourceTenantId == h.Stranger, "Warn keeps the behaviour before AB#8339");
        (await auth.ValidateCrossTenantAccessAsync(h.Target, h.Stranger, h.StrangerUser.Id.ToString()))
            .Should().NotBeNull("Warn keeps the behaviour before AB#8339");
        (await auth.AuthenticateAsync(h.Target, h.StrangerUser.Name, Password))
            .Should().NotBeNull("Warn keeps the behaviour before AB#8339");

        var warnings = log.Warnings.Where(w => w.Contains("CrossTenantAncestry=Warn")).ToList();
        warnings.Should().Contain(w => w.Contains("provisioning source users"));
        warnings.Should().Contain(w => w.Contains("tenant switch"));
        warnings.Should().Contain(w => w.Contains("cross-tenant login"));
        warnings.Should().OnlyContain(w => w.Contains(h.Stranger) && w.Contains(h.Target));
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Enforce_ProvisioningWrite_NonAncestorSource_Is403WithProblemCode_AndWritesNothing(bool withGroups)
    {
        var h = await ArrangeAsync();
        var controller = CreateController(CrossTenantAncestryMode.Enforce);

        var result = await CreateMappingAsync(controller, withGroups, h.Target, h.Stranger, h.StrangerUser);

        var problem = result.Should().BeOfType<ObjectResult>().Subject;
        problem.StatusCode.Should().Be(StatusCodes.Status403Forbidden);
        problem.Value.Should().BeOfType<ProblemDetails>()
            .Which.Extensions["code"].Should().Be(CrossTenantAncestryProblems.SourceTenantNotAncestorCode);
        var targetRepo = (await _fixture.GetSystemContext().TryFindTenantRepositoryAsync(h.Target))!;
        (await CountAsync<RtExternalTenantUserMapping>(targetRepo)).Should().Be(0);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Enforce_ProvisioningWrite_RegistryParentSource_IsCreated(bool withGroups)
    {
        var h = await ArrangeAsync();
        var controller = CreateController(CrossTenantAncestryMode.Enforce);

        var result = await CreateMappingAsync(controller, withGroups, h.Target, h.Parent, h.ParentUser);

        result.Should().BeOfType<CreatedResult>();
    }

    [Fact]
    public async Task Warn_ProvisioningWrite_NonAncestorSource_IsCreatedAsBefore_AndLogged()
    {
        var h = await ArrangeAsync();
        var log = new CapturingLogger<CrossTenantAncestryGuard>();

        var result = await CreateMappingAsync(CreateController(CrossTenantAncestryMode.Warn, log), false, h.Target,
            h.Stranger, h.StrangerUser);

        result.Should().BeOfType<CreatedResult>();
        log.Warnings.Should().Contain(w => w.Contains("CrossTenantAncestry=Warn") &&
                                           w.Contains("admin provisioning mapping") && w.Contains(h.Stranger));
    }

    /// <summary>AB#8367: the login page does not offer a parent the tenant switch is always refused for.</summary>
    [Fact]
    public async Task Enforce_LoginPage_OffersOnlyTheRegistryParent()
    {
        var h = await ArrangeAsync();

        var offered = await (await CreateLoginProvidersAsync(CrossTenantAncestryMode.Enforce, h.Target)).GetOfferedAsync();

        offered.Select(p => p.ParentTenantId).Should().BeEquivalentTo([h.Parent],
            "the stranger named by the target's administrator is no registry ancestor");
    }

    /// <summary>AB#8367: under Warn the login page keeps every enabled parent, and the guard logs the stranger.</summary>
    [Fact]
    public async Task Warn_LoginPage_OffersEveryParent_AndLogsTheStranger()
    {
        var h = await ArrangeAsync();
        var log = new CapturingLogger<CrossTenantAncestryGuard>();

        var offered = await (await CreateLoginProvidersAsync(CrossTenantAncestryMode.Warn, h.Target, log))
            .GetOfferedAsync();

        offered.Select(p => p.ParentTenantId).Should().BeEquivalentTo([h.Parent, h.Stranger]);
        log.Warnings.Should().ContainSingle(w => w.Contains("CrossTenantAncestry=Warn") &&
                                                 w.Contains(OctoTenantLoginProviders.Operation) &&
                                                 w.Contains(h.Stranger) && w.Contains(h.Target));
    }

    // ---------- arrangement ----------

    private sealed record TestUser(OctoObjectId Id, string Name);

    private sealed record Hierarchy(string Root, string Parent, string Target, string Stranger,
        TestUser RootUser, TestUser ParentUser, TestUser StrangerUser);

    private async Task<Hierarchy> ArrangeAsync()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        var root = systemContext.TenantId;
        await SetupAsync(root);

        var parent = await CreateChildAsync(systemContext, NewId("par"));
        var target = await CreateChildAsync((await systemContext.TryFindTenantContextAsync(parent))!, NewId("tgt"));
        var stranger = await CreateChildAsync(systemContext, NewId("str"));

        await AddOctoTenantProviderAsync(parent, root);
        await AddOctoTenantProviderAsync(target, parent);
        // Written by the target's administrator: the stranger as an additional "login parent".
        await AddOctoTenantProviderAsync(target, stranger);

        return new Hierarchy(root, parent, target, stranger,
            await CreateUserAsync(root, NewId("rootu")),
            await CreateUserAsync(parent, NewId("paru")),
            await CreateUserAsync(stranger, NewId("stru")));
    }

    private static string NewId(string prefix) => $"{prefix}-{Guid.NewGuid():N}"[..20];

    private async Task SetupAsync(string tenantId)
        => await _fixture.GetService<IDefaultConfigurationCreatorService>().SetupAsync(tenantId);

    private async Task<string> CreateChildAsync(ITenantContext parent, string tenantId)
    {
        using (var session = await parent.GetAdminSessionAsync())
        {
            session.StartTransaction();
            try
            {
                await parent.CreateChildTenantAsync(session, tenantId, tenantId);
                await session.CommitTransactionAsync();
            }
            catch
            {
                await session.AbortTransactionAsync();
                throw;
            }
        }

        await SetupAsync(tenantId);
        return tenantId;
    }

    private async Task<ITenantRepository> RepositoryAsync(string tenantId)
    {
        var systemContext = _fixture.GetSystemContext();
        return tenantId == systemContext.TenantId
            ? systemContext.GetSystemTenantRepositoryAsAdmin()
            : (await systemContext.TryFindTenantRepositoryAsync(tenantId))!;
    }

    private async Task AddOctoTenantProviderAsync(string tenantId, string parentTenantId)
    {
        var repo = await RepositoryAsync(tenantId);
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        await repo.InsertOneRtEntityAsync(session, new RtOctoTenantIdentityProvider
        {
            RtId = OctoObjectId.GenerateNewId(),
            Name = $"ParentTenant_{parentTenantId}",
            DisplayName = $"Login via {parentTenantId}",
            IsEnabled = true,
            ParentTenantId = parentTenantId
        });
        await session.CommitTransactionAsync();
    }

    private async Task<TestUser> CreateUserAsync(string tenantId, string userName)
    {
        var repo = await RepositoryAsync(tenantId);
        var user = new RtUser
        {
            RtId = OctoObjectId.GenerateNewId(),
            UserName = userName,
            NormalizedUserName = userName.ToUpperInvariant(),
            Email = $"{userName}@example.com",
            NormalizedEmail = $"{userName}@example.com".ToUpperInvariant(),
            EmailConfirmed = true,
            SecurityStamp = Guid.NewGuid().ToString()
        };
        user.PasswordHash = new PasswordHasher<RtUser>().HashPassword(user, Password);
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        await repo.InsertOneRtEntityAsync(session, user);
        await session.CommitTransactionAsync();
        return new TestUser(user.RtId, userName);
    }

    private static async Task<long> CountAsync<T>(ITenantRepository repo) where T : Meshmakers.Octo.Runtime.Contracts.RepositoryEntities.RtEntity, new()
    {
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        var result = await repo.GetRtEntitiesByTypeAsync<T>(session, RtEntityQueryOptions.Create());
        await session.CommitTransactionAsync();
        return result.Items.Count();
    }

    // ---------- system under test ----------

    private AdminProvisioningController CreateController(CrossTenantAncestryMode mode,
        ILogger<CrossTenantAncestryGuard>? log = null)
    {
        var systemContext = _fixture.GetSystemContext();
        return new AdminProvisioningController(systemContext, new NoOpAuthSchemeService(),
            new CrossTenantShadowUserChainResolver(systemContext), TestAncestryGuards.Create(systemContext, mode, log),
            NullLogger<AdminProvisioningController>.Instance);
    }

    private static async Task<List<ProvisioningSourceUserDto>> SourceUsersAsync(AdminProvisioningController controller,
        string targetTenantId, string search)
        => (((await controller.GetSourceUsers(targetTenantId, search, 100)).Result as OkObjectResult)!
            .Value as IEnumerable<ProvisioningSourceUserDto>)!.ToList();

    private static async Task<IActionResult?> CreateMappingAsync(AdminProvisioningController controller,
        bool withGroups, string targetTenantId, string sourceTenantId, TestUser sourceUser)
        => withGroups
            ? (await controller.CreateWithGroups(targetTenantId, new CreateExternalTenantUserGroupMappingDto
            {
                SourceTenantId = sourceTenantId, SourceUserId = sourceUser.Id.ToString(),
                SourceUserName = sourceUser.Name, GroupIds = []
            })).Result
            : (await controller.Create(targetTenantId, new CreateExternalTenantUserMappingDto
            {
                SourceTenantId = sourceTenantId, SourceUserId = sourceUser.Id.ToString(),
                SourceUserName = sourceUser.Name, RoleIds = []
            })).Result;

    /// <summary>
    ///     The service as the target's login and exchange use it: the identity-provider store is bound to the target
    ///     tenant, the ancestry guard runs in <paramref name="mode" />.
    /// </summary>
    private async Task<CrossTenantAuthenticationService> CreateAuthServiceAsync(CrossTenantAncestryMode mode,
        string targetTenantId, ILogger<CrossTenantAncestryGuard>? log = null)
    {
        var systemContext = _fixture.GetSystemContext();
        var targetRepo = (await systemContext.TryFindTenantRepositoryAsync(targetTenantId))!;
        return new CrossTenantAuthenticationService(
            new TenantRegistry(systemContext, new Microsoft.Extensions.Caching.Memory.MemoryCache(
                new Microsoft.Extensions.Caching.Memory.MemoryCacheOptions())),
            new IdentityProviderStore(new FixedTenantResolver(targetRepo)),
            new PasswordHasher<RtUser>(),
            new CrossTenantShadowUserChainResolver(systemContext),
            TestAncestryGuards.Create(systemContext, mode, log),
            Options.Create(new IdentityOptions()),
            NullLogger<CrossTenantAuthenticationService>.Instance);
    }

    private async Task<OctoTenantLoginProviders> CreateLoginProvidersAsync(CrossTenantAncestryMode mode,
        string tenantId, ILogger<CrossTenantAncestryGuard>? log = null)
    {
        var systemContext = _fixture.GetSystemContext();
        var repo = (await systemContext.TryFindTenantRepositoryAsync(tenantId))!;
        return new OctoTenantLoginProviders(new IdentityProviderStore(new FixedTenantResolver(repo)),
            TestAncestryGuards.Create(systemContext, mode, log));
    }

    private async Task<TenantExchangeProcessor> CreateExchangeProcessorAsync(
        CrossTenantAuthenticationService auth, string targetTenantId)
    {
        var systemContext = _fixture.GetSystemContext();
        var targetRepo = (await systemContext.TryFindTenantRepositoryAsync(targetTenantId))!;
        var resolver = new FixedTenantResolver(targetRepo);
        var chainResolver = new CrossTenantShadowUserChainResolver(systemContext);
        var mappingStore = new ExternalTenantUserMappingStore(resolver);
        var userManager = BuildUserManager(resolver, chainResolver);
        return new TenantExchangeProcessor(
            Substitute.For<IOptionsMonitor<OpenIddictServerOptions>>(),
            Options.Create(new OctoIdentityServicesOptions { AuthorityUrl = "https://identity.example.com/" }),
            auth,
            new CrossTenantUserProvisioningService(userManager, mappingStore, resolver, chainResolver,
                NullLogger<CrossTenantUserProvisioningService>.Instance),
            chainResolver,
            mappingStore,
            userManager,
            Substitute.For<IHttpContextAccessor>(),
            Substitute.For<IIdentityAuditService>(),
            NullLogger<TenantExchangeProcessor>.Instance);
    }

    private static UserManager<RtUser> BuildUserManager(FixedTenantResolver resolver,
        CrossTenantShadowUserChainResolver chainResolver)
    {
        var groupRoleResolver = new GroupRoleResolver(new GroupStore(resolver),
            new ExternalTenantUserMappingStore(resolver), chainResolver);
        return new UserManager<RtUser>(
            new OctoUserStore(resolver, groupRoleResolver, null),
            Options.Create(new IdentityOptions()),
            new PasswordHasher<RtUser>(),
            Array.Empty<IUserValidator<RtUser>>(),
            Array.Empty<IPasswordValidator<RtUser>>(),
            new UpperInvariantLookupNormalizer(),
            new IdentityErrorDescriber(),
            services: null!,
            NullLogger<UserManager<RtUser>>.Instance);
    }

    private sealed class NoOpAuthSchemeService : IDynamicAuthSchemeService
    {
        public Task ConfigureAsync(string tenantId) => Task.CompletedTask;
    }

    private sealed class CapturingLogger<T> : ILogger<T>
    {
        private readonly List<string> _warnings = [];

        public IReadOnlyList<string> Warnings
        {
            get
            {
                lock (_warnings)
                {
                    return _warnings.ToList();
                }
            }
        }

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (logLevel == LogLevel.Warning)
            {
                lock (_warnings)
                {
                    _warnings.Add(formatter(state, exception));
                }
            }
        }
    }
}
