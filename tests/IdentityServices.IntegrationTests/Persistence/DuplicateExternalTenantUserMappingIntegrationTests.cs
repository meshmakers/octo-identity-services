using FluentAssertions;
using IdentityServerPersistence;
using IdentityServerPersistence.Configuration.Options;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using IdentityServices.IntegrationTests.Fixtures;
using Meshmakers.Octo.Backend.Authentication.DynamicAuth;
using Meshmakers.Octo.Backend.IdentityServices.OpenIddict;
using Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using OpenIddict.Server;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace IdentityServices.IntegrationTests.Persistence;

/// <summary>
///     AB#6975 against a real MongoDB (Testcontainers): two <c>ExternalTenantUserMapping</c> rows for the same
///     (source tenant, source user) used to make <c>SingleOrDefault</c> throw in the store ("Sequence contains
///     more than one element"), so the cross-tenant login answered 500 and the token exchange failed.
///     The lookup now tolerates duplicates (oldest RtId wins) and both create paths answer 409.
/// </summary>
public class DuplicateExternalTenantUserMappingIntegrationTests : IClassFixture<IdentityServicesFixture>
{
    private readonly IdentityServicesFixture _fixture;

    public DuplicateExternalTenantUserMappingIntegrationTests(
        IdentityServicesFixture fixture, ITestOutputHelper outputHelper)
    {
        _fixture = fixture;
        _fixture.OutputHelper = outputHelper;
    }

    [Fact]
    public async Task Store_LookupWithTwoMappings_DoesNotThrow_AndPicksTheOldest()
    {
        var ctx = await ArrangeWithDuplicateAsync();

        var found = await ctx.Store.FindBySourceUserAsync(ctx.Login.SourceTenantId, ctx.Login.SourceUserId);

        found.Should().NotBeNull();
        found!.RtId.Should().Be(ctx.OldestId, "the oldest mapping (smallest RtId) wins, deterministically");
        // Repeatable: no dependence on the database's return order.
        (await ctx.Store.FindBySourceUserAsync(ctx.Login.SourceTenantId, ctx.Login.SourceUserId))!
            .RtId.Should().Be(ctx.OldestId);
    }

    [Fact]
    public async Task Store_TwoLookupsOfTheSameDuplicateSetInOneScope_LogTheWarningOnce()
    {
        var ctx = await ArrangeWithDuplicateAsync();
        var logger = new CapturingLogger<ExternalTenantUserMappingStore>();
        // One store instance = one request scope (the store is registered scoped).
        var store = new ExternalTenantUserMappingStore(new FixedTenantResolver(ctx.ChildRepo), logger);

        // A login and a token exchange both look the mapping up twice.
        await store.FindBySourceUserAsync(ctx.Login.SourceTenantId, ctx.Login.SourceUserId);
        await store.FindBySourceUserAsync(ctx.Login.SourceTenantId, ctx.Login.SourceUserId);

        logger.Levels.Count(l => l == LogLevel.Warning).Should().Be(1);
        logger.Levels.Count(l => l == LogLevel.Debug).Should().Be(1);
    }

    [Fact]
    public async Task Store_FindBySourceUserNames_ReturnsBothMappings_SoTheRolesCanBeUnited()
    {
        var ctx = await ArrangeWithDuplicateAsync();

        var rows = await ctx.Store.FindBySourceUserNamesAsync(
            [(ctx.Login.SourceTenantId, ctx.Login.SourceUserName)]);

        rows.Should().HaveCount(2, "the oldest-wins pick only applies to the lookup that finds the user");
    }

    [Fact]
    public async Task IsExplicitlyProvisioned_WithTwoMappings_IsTrue()
    {
        var ctx = await ArrangeWithDuplicateAsync();

        var result = await ctx.Provisioning.IsExplicitlyProvisionedAsync(ctx.Login);

        result.Should().BeTrue();
    }

    [Fact]
    public async Task CrossTenantLogin_WithTwoMappings_FindsOrCreatesTheShadowUser()
    {
        var ctx = await ArrangeWithDuplicateAsync();

        var user = await ctx.Provisioning.FindOrCreateCrossTenantUserAsync(ctx.Login, ctx.ChildTenantId);

        user.Should().NotBeNull("the login must not answer 500 for a user with two mappings");
        // A second login (the shadow user exists now) keeps working as well.
        (await ctx.Provisioning.FindOrCreateCrossTenantUserAsync(ctx.Login, ctx.ChildTenantId))!
            .RtId.Should().Be(user!.RtId);
    }

    [Fact]
    public async Task TokenExchange_WithTwoMappings_ResolvesTheSource()
    {
        var ctx = await ArrangeWithDuplicateAsync();

        var crossTenantAuth = Substitute.For<ICrossTenantAuthenticationService>();
        crossTenantAuth.FindUserNameByIdInTenantAsync(ctx.Login.SourceTenantId, ctx.Login.SourceUserId)
            .Returns(ctx.Login.SourceUserName);
        crossTenantAuth.ValidateCrossTenantAccessAsync(ctx.ChildTenantId, ctx.Login.SourceTenantId, ctx.Login.SourceUserId)
            .Returns(ctx.Login);
        var processor = new TenantExchangeProcessor(
            Substitute.For<IOptionsMonitor<OpenIddictServerOptions>>(),
            Options.Create(new OctoIdentityServicesOptions { AuthorityUrl = "https://identity.example.com/" }),
            crossTenantAuth,
            ctx.Provisioning,
            new CrossTenantShadowUserChainResolver(_fixture.GetSystemContext()),
            ctx.Store,
            Substitute.For<UserManager<RtUser>>(
                Substitute.For<IUserStore<RtUser>>(),
                Substitute.For<IOptions<IdentityOptions>>(),
                Substitute.For<IPasswordHasher<RtUser>>(),
                Array.Empty<IUserValidator<RtUser>>(),
                Array.Empty<IPasswordValidator<RtUser>>(),
                Substitute.For<ILookupNormalizer>(),
                Substitute.For<IdentityErrorDescriber>(),
                Substitute.For<IServiceProvider>(),
                Substitute.For<ILogger<UserManager<RtUser>>>()),
            Substitute.For<IHttpContextAccessor>(),
            Substitute.For<IIdentityAuditService>(),
            NullLogger<TenantExchangeProcessor>.Instance);

        var source = await processor.ResolveExchangeSourceAsync(
            ctx.ChildTenantId, ctx.Login.SourceTenantId, ctx.Login.SourceUserId);

        source.Should().NotBeNull();
        source!.SourceUserId.Should().Be(ctx.Login.SourceUserId);
    }

    [Fact]
    public async Task ExternalTenantUserMappingsController_CreateForExistingPair_Returns409Problem_AndInsertsNothing()
    {
        var ctx = await ArrangeWithDuplicateAsync(duplicate: false);
        var controller = new ExternalTenantUserMappingsController(ctx.Store, Substitute.For<IGroupStore>());

        var result = await controller.Create(new CreateExternalTenantUserMappingDto
        {
            SourceTenantId = ctx.Login.SourceTenantId,
            SourceUserId = ctx.Login.SourceUserId,
            SourceUserName = ctx.Login.SourceUserName,
            RoleIds = []
        });

        AssertConflict(result.Result, ctx.OldestId);
        (await CountMappingsAsync(ctx)).Should().Be(1);
    }

    [Fact]
    public async Task AdminProvisioningController_CreateForExistingPair_Returns409Problem_AndInsertsNothing()
    {
        var ctx = await ArrangeWithDuplicateAsync(duplicate: false);
        var controller = new AdminProvisioningController(
            _fixture.GetSystemContext(), new NoOpAuthSchemeService(),
            NullLogger<AdminProvisioningController>.Instance);

        var result = await controller.Create(ctx.ChildTenantId, new CreateExternalTenantUserMappingDto
        {
            SourceTenantId = ctx.Login.SourceTenantId,
            SourceUserId = ctx.Login.SourceUserId,
            SourceUserName = ctx.Login.SourceUserName,
            RoleIds = []
        });

        AssertConflict(result.Result, ctx.OldestId);
        (await CountMappingsAsync(ctx)).Should().Be(1);
    }

    [Fact]
    public async Task AdminProvisioningController_CreateWithGroupsForExistingPair_Returns409Problem_AndInsertsNothing()
    {
        var ctx = await ArrangeWithDuplicateAsync(duplicate: false);
        var controller = new AdminProvisioningController(
            _fixture.GetSystemContext(), new NoOpAuthSchemeService(),
            NullLogger<AdminProvisioningController>.Instance);

        var result = await controller.CreateWithGroups(ctx.ChildTenantId, new CreateExternalTenantUserGroupMappingDto
        {
            SourceTenantId = ctx.Login.SourceTenantId,
            SourceUserId = ctx.Login.SourceUserId,
            SourceUserName = ctx.Login.SourceUserName,
            GroupIds = []
        });

        AssertConflict(result.Result, ctx.OldestId);
        (await CountMappingsAsync(ctx)).Should().Be(1);
    }

    [Fact]
    public async Task AdminProvisioningController_CreateForNewPair_StillCreates()
    {
        var ctx = await ArrangeWithDuplicateAsync(duplicate: false);
        var controller = new AdminProvisioningController(
            _fixture.GetSystemContext(), new NoOpAuthSchemeService(),
            NullLogger<AdminProvisioningController>.Instance);

        var result = await controller.Create(ctx.ChildTenantId, new CreateExternalTenantUserMappingDto
        {
            SourceTenantId = ctx.Login.SourceTenantId,
            SourceUserId = OctoObjectId.GenerateNewId().ToString(),
            SourceUserName = NewId("other"),
            RoleIds = []
        });

        result.Result.Should().BeOfType<CreatedResult>();
        (await CountMappingsAsync(ctx)).Should().Be(2);
    }

    // ---------- helpers ----------

    private static void AssertConflict(IActionResult? result, OctoObjectId existingId)
    {
        var objectResult = result.Should().BeOfType<ObjectResult>().Subject;
        objectResult.StatusCode.Should().Be(StatusCodes.Status409Conflict);
        objectResult.ContentTypes.Should().Contain("application/problem+json");
        var problem = objectResult.Value.Should().BeOfType<ProblemDetails>().Subject;
        problem.Extensions["code"].Should().Be(ExternalTenantUserMappingProblems.AlreadyExistsCode);
        problem.Extensions["existingMappingId"].Should().Be(existingId.ToString());
        problem.Detail.Should().Contain(existingId.ToString());
    }

    private sealed record Context(
        string ChildTenantId,
        ITenantRepository ChildRepo,
        ExternalTenantUserMappingStore Store,
        CrossTenantUserProvisioningService Provisioning,
        CrossTenantAuthResult Login,
        OctoObjectId OldestId);

    private async Task<Context> ArrangeWithDuplicateAsync(bool duplicate = true)
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        await _fixture.GetService<IDefaultConfigurationCreatorService>().SetupAsync(systemContext.TenantId);

        var childTenantId = NewId("dup");
        using (var session = await systemContext.GetAdminSessionAsync())
        {
            session.StartTransaction();
            await systemContext.CreateChildTenantAsync(session, childTenantId, childTenantId);
            await session.CommitTransactionAsync();
        }

        await _fixture.GetService<IDefaultConfigurationCreatorService>().SetupAsync(childTenantId);
        var childRepo = (await systemContext.TryFindTenantRepositoryAsync(childTenantId))!;
        var resolver = new FixedTenantResolver(childRepo);
        var store = new ExternalTenantUserMappingStore(resolver);

        var login = new CrossTenantAuthResult
        {
            SourceTenantId = systemContext.TenantId,
            SourceUserId = OctoObjectId.GenerateNewId().ToString(),
            SourceUserName = NewId("user"),
            Email = "dup@example.com"
        };

        // ObjectIds generated one after the other are ordered; store the NEWER one first so that the
        // database's natural order is not the creation order.
        var oldest = NewMapping(login);
        var newer = NewMapping(login);
        if (duplicate)
        {
            await store.StoreAsync(newer);
        }

        await store.StoreAsync(oldest);

        var userManager = new UserManager<RtUser>(
            new OctoUserStore(
                resolver,
                new GroupRoleResolver(new GroupStore(resolver), store, new CrossTenantShadowUserChainResolver(systemContext)),
                null),
            Options.Create(new IdentityOptions()),
            new PasswordHasher<RtUser>(),
            Array.Empty<IUserValidator<RtUser>>(),
            Array.Empty<IPasswordValidator<RtUser>>(),
            new UpperInvariantLookupNormalizer(),
            new IdentityErrorDescriber(),
            services: null!,
            NullLogger<UserManager<RtUser>>.Instance);
        var provisioning = new CrossTenantUserProvisioningService(
            userManager, store, resolver, new CrossTenantShadowUserChainResolver(systemContext),
            NullLogger<CrossTenantUserProvisioningService>.Instance);

        return new Context(childTenantId, childRepo, store, provisioning, login, oldest.RtId);
    }

    private static RtExternalTenantUserMapping NewMapping(CrossTenantAuthResult login) => new()
    {
        RtId = OctoObjectId.GenerateNewId(),
        SourceTenantId = login.SourceTenantId,
        SourceUserId = login.SourceUserId,
        SourceUserName = login.SourceUserName
    };

    private static async Task<int> CountMappingsAsync(Context ctx)
    {
        using var session = await ctx.ChildRepo.GetSessionAsync();
        session.StartTransaction();
        var result = await ctx.ChildRepo.GetRtEntitiesByTypeAsync<RtExternalTenantUserMapping>(
            session,
            RtEntityQueryOptions.Create()
                .FieldEquals(nameof(RtExternalTenantUserMapping.SourceTenantId), ctx.Login.SourceTenantId));
        await session.CommitTransactionAsync();
        return result.Items.Count();
    }

    private static string NewId(string prefix) => $"{prefix}-{Guid.NewGuid():N}"[..20];

    private sealed class NoOpAuthSchemeService : IDynamicAuthSchemeService
    {
        public Task ConfigureAsync(string tenantId) => Task.CompletedTask;
    }

    private sealed class CapturingLogger<T> : ILogger<T>
    {
        private readonly List<LogLevel> _levels = [];

        public IReadOnlyList<LogLevel> Levels => _levels;

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter) => _levels.Add(logLevel);
    }
}
