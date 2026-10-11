using FluentAssertions;
using IdentityServerPersistence.Services;
using IdentityServices.IntegrationTests.Fixtures;
using Meshmakers.Octo.Backend.IdentityServices.Consumers;
using Meshmakers.Octo.Common.DistributionEventHub.Consumers;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Commands;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Commands.Payloads;
using Meshmakers.Octo.Services.Infrastructure.Services;
using MongoDB.Bson;
using MongoDB.Driver;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Shared.TestUtilities.Fakes;
using Xunit;

namespace IdentityServices.IntegrationTests.Persistence;

/// <summary>
///     CK v2 Phase 1 G-H2: with the engine's downgrade guard a tenant may keep a NEWER System.Identity than this
///     service embeds. Identity's existence checks must accept "embedded or newer" by name. A higher major means the
///     service is too old for the tenant: platform rule R-L4 — skip the import, WARN, keep running.
/// </summary>
/// <remarks>
///     A newer installed version is simulated by re-keying the tenant's <c>CkModel</c> row of System.Identity to a
///     higher version id (only the model row; the types stay those of the embedded version, which is exactly what a
///     by-name check sees). Each test uses its own GUID-suffixed child tenant.
/// </remarks>
[Collection("Sequential")]
public class CkModelCompatibilityIntegrationTests : IClassFixture<IdentityServicesFixture>
{
    private readonly IdentityServicesFixture _fixture;

    public CkModelCompatibilityIntegrationTests(IdentityServicesFixture fixture, ITestOutputHelper outputHelper)
    {
        _fixture = fixture;
        _fixture.OutputHelper = outputHelper;
    }

    [Fact]
    public async Task NewerMinorIdentityModel_IdentityDataCreationWorks()
    {
        var tenantId = await CreateTenantAsync();
        var newer = NewerVersion(SystemIdentityCkIds.CkModelId, majorBump: false);
        await AddFakeInstalledVersionAsync(tenantId, newer);

        var (response, logger) = await ConsumeAsync(tenantId);

        response.Response.Should().NotBe(CreateIdentityDataResult.FailedTenantHasNoIdentityCk,
            "a newer System.Identity of the same major satisfies the embedded one");
        response.Response.Should().BeOneOf(CreateIdentityDataResult.Success,
            CreateIdentityDataResult.SuccessIdentityDataSeedPending);
        logger.AllText.Should().NotContain("too old");
    }

    [Fact]
    public async Task NewerMajorIdentityModel_IdentityDataCreationProceeds_WithAWarning()
    {
        var tenantId = await CreateTenantAsync();
        var newerMajor = NewerVersion(SystemIdentityCkIds.CkModelId, majorBump: true);
        await AddFakeInstalledVersionAsync(tenantId, newerMajor);

        var (response, logger) = await ConsumeAsync(tenantId);

        response.Response.Should().BeOneOf(CreateIdentityDataResult.Success,
            CreateIdentityDataResult.SuccessIdentityDataSeedPending);
        logger.Messages.Should().Contain(m => m.StartsWith("[Warning]") && m.Contains("too old") &&
                                              m.Contains(newerMajor.ToString()) &&
                                              m.Contains(SystemIdentityCkIds.CkModelId.ToString()));
    }

    /// <summary>
    ///     R-L4: a tenant with a higher major is neither downgraded nor a setup failure (for the system tenant that
    ///     would be a host-startup failure).
    /// </summary>
    [Fact]
    public async Task TenantSetup_WithNewerMajorIdentityModel_DoesNotFailAndKeepsTheNewerModel()
    {
        var tenantId = await CreateTenantAsync();
        var newerMajor = NewerVersion(SystemIdentityCkIds.CkModelId, majorBump: true);
        await AddFakeInstalledVersionAsync(tenantId, newerMajor);

        var setup = _fixture.GetService<IDefaultConfigurationCreatorService>();
        var act = () => setup.SetupAsync(tenantId);
        await act.Should().NotThrowAsync();

        var tenantContext = await _fixture.GetSystemContext().GetChildTenantContextAsync(tenantId);
        var compatibility = await CkModelCompatibility.GetAsync(tenantContext, SystemIdentityCkIds.CkModelId);
        compatibility.Installed.Should().Be(newerMajor, "the newer major must not be downgraded");
        compatibility.State.Should().Be(CkModelCompatibilityState.NewerMajor);
    }

    /// <summary>
    ///     Tenant setup with a newer System.Identity of the same major must not import the embedded version
    ///     (which, without the engine's guard, would replace — i.e. downgrade — the newer row).
    /// </summary>
    [Fact]
    public async Task TenantSetup_WithNewerMinorIdentityModel_DoesNotReimportTheEmbeddedVersion()
    {
        var tenantId = await CreateTenantAsync();
        var newer = NewerVersion(SystemIdentityCkIds.CkModelId, majorBump: false);
        await AddFakeInstalledVersionAsync(tenantId, newer);

        var setup = _fixture.GetService<IDefaultConfigurationCreatorService>();
        await setup.SetupAsync(tenantId);

        var tenantContext = await _fixture.GetSystemContext().GetChildTenantContextAsync(tenantId);
        var compatibility = await CkModelCompatibility.GetAsync(tenantContext, SystemIdentityCkIds.CkModelId);
        compatibility.Installed.Should().Be(newer, "the newer installed model must survive the setup");
        compatibility.State.Should().Be(CkModelCompatibilityState.NewerSameMajor);
    }

    // ---------- helpers ----------

    private static CkModelId NewerVersion(CkModelId embedded, bool majorBump) =>
        majorBump
            ? new CkModelId(embedded.Name, $"{embedded.Version.Major + 1}.0.0")
            : new CkModelId(embedded.Name, $"{embedded.Version.Major}.{embedded.Version.Minor + 50}.0");

    private async Task<string> CreateTenantAsync()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        var setup = _fixture.GetService<IDefaultConfigurationCreatorService>();
        await setup.SetupAsync(systemContext.TenantId);

        var tenantId = $"ckcompat-{Guid.NewGuid():N}"[..20];
        using (var session = await systemContext.GetAdminSessionAsync())
        {
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
        }

        await setup.SetupAsync(tenantId);
        return tenantId;
    }

    /// <summary>Clones the tenant's System.Identity <c>CkModel</c> row under <paramref name="version" />.</summary>
    private async Task AddFakeInstalledVersionAsync(string tenantId, CkModelId version)
    {
        var tenantContext = await _fixture.GetSystemContext().GetChildTenantContextAsync(tenantId);
        var database = new MongoClient(_fixture.GetConnectionString()).GetDatabase(tenantContext.DatabaseName);
        var collection = database.GetCollection<BsonDocument>("CkModel");

        var original = await collection
            .Find(Builders<BsonDocument>.Filter.Eq("_id", SystemIdentityCkIds.CkModelId.ToString()))
            .FirstOrDefaultAsync(TestContext.Current.CancellationToken);
        original.Should().NotBeNull("the tenant setup imported the embedded System.Identity model");

        // Replace (not add): after a guarded rollout the tenant has ONLY the newer row, so an exact-version
        // check for the embedded id finds nothing — the case that broke before G-H2.
        var clone = original!.DeepClone().AsBsonDocument;
        clone["_id"] = version.ToString();
        await collection.InsertOneAsync(clone, cancellationToken: TestContext.Current.CancellationToken);
        await collection.DeleteOneAsync(Builders<BsonDocument>.Filter.Eq("_id", SystemIdentityCkIds.CkModelId.ToString()),
            TestContext.Current.CancellationToken);
        (await tenantContext.IsCkModelExistingAsync(SystemIdentityCkIds.CkModelId)).Should()
            .BeFalse("the exact embedded version is gone; only a by-name check can see the newer one");

        var check = await CkModelCompatibility.GetAsync(tenantContext, SystemIdentityCkIds.CkModelId);
        check.Installed.Should().Be(version, "the fake row must be what a by-name lookup sees");
    }

    private async Task<(EnumCommandResponse<CreateIdentityDataResult> Response,
        CapturingLogger<CreateIdentityDataCommandRequestConsumer> Logger)> ConsumeAsync(string tenantId)
    {
        var logger = new CapturingLogger<CreateIdentityDataCommandRequestConsumer>();
        var consumer = new CreateIdentityDataCommandRequestConsumer(logger, _fixture.GetSystemContext());
        var context = new RecordingContext(new CreateIdentityDataCommandRequest(tenantId)
        {
            ApiScopes = [new DistApiScopeDto($"ckcompat-scope-{Guid.NewGuid():N}", "CK compatibility test scope")]
        });

        await consumer.ConsumeAsync(context);

        context.Response.Should().BeOfType<EnumCommandResponse<CreateIdentityDataResult>>();
        return ((EnumCommandResponse<CreateIdentityDataResult>)context.Response!, logger);
    }

    private sealed class RecordingContext(CreateIdentityDataCommandRequest message)
        : IDistributedContext<CreateIdentityDataCommandRequest>
    {
        public CreateIdentityDataCommandRequest Message { get; } = message;

        public object? Response { get; private set; }

        public Task RespondAsync<T>(T responseMessage) where T : class
        {
            Response = responseMessage;
            return Task.CompletedTask;
        }

        public Task PublishAsync<T>(T publishedMessage) where T : class => Task.CompletedTask;
    }
}
