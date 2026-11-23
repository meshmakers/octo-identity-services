using FluentAssertions;
using IdentityServerPersistence;
using IdentityServices.IntegrationTests.Fixtures;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.Exchange;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Xunit;

namespace IdentityServices.IntegrationTests.Persistence;

/// <summary>
///     Upgrade of <c>System.Identity.Bootstrap</c> from 1.9.0 to the version that registers the LLM gateway scope
///     <c>ai.llm.invoke</c>, against a real MongoDB (Testcontainers). A child tenant on 1.9.0 is built from FROZEN copies of
///     that version's API scope and API resource seeds (<c>BootstrapSnapshots/1.9.0/</c>, taken from git), then upgraded
///     the way the blueprint apply does it: the shipped seed files are imported with the Upsert strategy. The blueprint
///     applies the same seed to the system tenant and every child tenant.
/// </summary>
[Collection("Sequential")]
public class BootstrapLlmInvokeScopeUpgradeIntegrationTests : IClassFixture<IdentityServicesFixture>
{
    private const string LlmScope = "ai.llm.invoke";
    private static readonly OctoObjectId LlmScopeRtId = new("660000000000000000000017");
    private static readonly OctoObjectId OctoApiRtId = new("660000000000000000000020");
    private static readonly OctoObjectId McpApiRtId = new("660000000000000000000021");

    private static readonly string[] PlatformScopes =
        ["octo_api", "octo_api.read_only", "octo_api.data_model_management"];

    private static readonly string[] SeedFiles = ["api-scopes.yaml", "api-resources.yaml"];

    private readonly IdentityServicesFixture _fixture;

    public BootstrapLlmInvokeScopeUpgradeIntegrationTests(IdentityServicesFixture fixture,
        ITestOutputHelper outputHelper)
    {
        _fixture = fixture;
        _fixture.OutputHelper = outputHelper;
    }

    [Fact]
    public async Task UpgradeFrom190_AddsTheEnabledScope_AndAttachesItToOctoApiOnly()
    {
        var repo = await CreateChildTenantAsync();
        await ImportSeedsAsync(repo, SnapshotPath("1.9.0"));
        var before = await CaptureAsync(repo);
        before.Scopes.Should().NotContainKey(LlmScopeRtId, "1.9.0 did not register the gateway scope");

        await ImportSeedsAsync(repo, SeedPath());

        var after = await CaptureAsync(repo);
        after.Scopes.Should().ContainKey(LlmScopeRtId);
        after.Scopes[LlmScopeRtId].Should().Be($"{LlmScope}|enabled");
        after.ResourceScopes[OctoApiRtId].Should().BeEquivalentTo([..PlatformScopes, LlmScope]);
        after.ResourceScopes[McpApiRtId].Should().BeEquivalentTo(PlatformScopes,
            "the MCP resource indicator serves interactive clients and does not carry the gateway scope");
        after.Scopes.Where(s => s.Key != LlmScopeRtId).Should().BeEquivalentTo(before.Scopes,
            "the platform scopes are unchanged");
    }

    [Fact]
    public async Task ReapplyingTheShippedSeed_IsIdempotent()
    {
        var repo = await CreateChildTenantAsync();
        await ImportSeedsAsync(repo, SnapshotPath("1.9.0"));
        await ImportSeedsAsync(repo, SeedPath());
        var first = await CaptureAsync(repo);

        await ImportSeedsAsync(repo, SeedPath());

        var second = await CaptureAsync(repo);
        second.Scopes.Should().BeEquivalentTo(first.Scopes);
        second.ResourceScopes.Should().BeEquivalentTo(first.ResourceScopes);
        second.Scopes.Values.Count(v => v.StartsWith(LlmScope + "|", StringComparison.Ordinal)).Should().Be(1,
            "a re-run must not create a second scope of the same name");
    }

    private async Task ImportSeedsAsync(ITenantRepository repo, string directory)
    {
        var import = _fixture.GetService<IImportRtModelCommand>();
        foreach (var file in SeedFiles)
        {
            var yaml = await File.ReadAllTextAsync(Path.Combine(directory, file), TestContext.Current.CancellationToken);
            await import.ImportTextAsync(repo, yaml, ImportStrategy.Upsert);
        }
    }

    /// <summary>Scopes by rtId (<c>name|enabled</c>) and the scope list of each API resource by rtId.</summary>
    private sealed record TenantState(
        Dictionary<OctoObjectId, string> Scopes,
        Dictionary<OctoObjectId, List<string>> ResourceScopes);

    private static async Task<TenantState> CaptureAsync(ITenantRepository repo)
    {
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        var scopes = await repo.GetRtEntitiesByTypeAsync<RtApiScope>(session, RtEntityQueryOptions.Create());
        var resources = await repo.GetRtEntitiesByTypeAsync<RtApiResource>(session, RtEntityQueryOptions.Create());
        await session.CommitTransactionAsync();

        return new TenantState(
            scopes.Items.ToDictionary(s => s.RtId, s => $"{s.Name}|{(s.Enabled ? "enabled" : "disabled")}"),
            resources.Items.ToDictionary(r => r.RtId, r => r.Scopes?.ToList() ?? []));
    }

    private async Task<ITenantRepository> CreateChildTenantAsync()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        var setup = _fixture.GetService<IDefaultConfigurationCreatorService>();
        await setup.SetupAsync(systemContext.TenantId);

        var tenantId = $"llmsc-{Guid.NewGuid():N}"[..24];
        using (var session = await systemContext.GetAdminSessionAsync())
        {
            session.StartTransaction();
            await systemContext.CreateChildTenantAsync(session, tenantId, tenantId);
            await session.CommitTransactionAsync();
        }

        // Imports the Identity CK model; no blueprint catalog is registered, so no seed scope exists yet.
        await setup.SetupAsync(tenantId);

        var tenantContext = await systemContext.GetChildTenantContextAsync(tenantId);
        return tenantContext.GetTenantRepositoryAsAdmin();
    }

    private static string SnapshotPath(string version) =>
        FindRepoFile($"tests/IdentityServices.IntegrationTests/BootstrapSnapshots/{version}");

    private static string SeedPath() =>
        FindRepoFile("src/Persistence.IdentityCkModel/Blueprints/System.Identity.Bootstrap/seed-data");

    private static string FindRepoFile(string relativePath)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !File.Exists(Path.Combine(dir.FullName, "Octo.Identity.sln")))
        {
            dir = dir.Parent;
        }

        return dir == null
            ? throw new FileNotFoundException("Octo.Identity.sln not found above the test binaries.")
            : Path.Combine(dir.FullName, relativePath);
    }
}
