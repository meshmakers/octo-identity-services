using System.Xml.Linq;
using FluentAssertions;
using IdentityServerPersistence.Configuration.Options;
using IdentityServerPersistence.SystemStores;
using IdentityServices.IntegrationTests.Fixtures;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace IdentityServices.IntegrationTests.Persistence;

/// <summary>
/// Isolated test class for <see cref="DataProtectionKeyStore.TrySeedFromLegacyFilesAsync"/>:
/// verifies the zero-logout migration path where an EMPTY Mongo store imports key-*.xml files
/// from the legacy file-system path on the first <c>GetAllElements()</c> call.
/// <para>
/// Isolation rationale: xUnit creates one <see cref="IClassFixture{T}"/> instance per test
/// CLASS, so this class gets its own <see cref="IdentityServicesFixture"/> with a fresh Mongo
/// container and a guaranteed-empty DataProtectionKey collection — the seed fires exactly once.
/// </para>
/// </summary>
[Collection("Sequential")]
public class DataProtectionKeySeedIntegrationTests : IClassFixture<IdentityServicesFixture>
{
    private readonly IdentityServicesFixture _fixture;

    public DataProtectionKeySeedIntegrationTests(IdentityServicesFixture fixture, ITestOutputHelper outputHelper)
    {
        _fixture = fixture;
        _fixture.OutputHelper = outputHelper;
    }

    private async Task EnsureSystemSetupAsync()
    {
        var setup = _fixture.GetService<IDefaultConfigurationCreatorService>();
        var systemTenantId = _fixture.GetSystemContext().TenantId;
        await setup.SetupAsync(systemTenantId);
    }

    /// <summary>
    /// Verifies the seed-import code path end-to-end:
    /// <list type="number">
    ///   <item>Act 1 — <c>GetAllElements()</c> on an EMPTY store with a <c>DataProtectionKeysPath</c>
    ///   pointing at a temp dir that contains <c>key-seed-aaaa.xml</c> and <c>key-seed-bbbb.xml</c>.
    ///   <c>TrySeedFromLegacyFilesAsync</c> MUST fire and import both files into Mongo.</item>
    ///   <item>Assert 1 — the returned collection contains both elements (matched by <c>id</c>
    ///   attribute values <c>seed-aaaa</c> / <c>seed-bbbb</c>).</item>
    ///   <item>Act 2 — delete the temp dir; build a second store instance with
    ///   <c>DataProtectionKeysPath = null</c>; call <c>GetAllElements()</c>.</item>
    ///   <item>Assert 2 — both elements are still returned (persisted in Mongo, NOT re-read from disk).</item>
    /// </list>
    /// </summary>
    [Fact]
    public async Task GetAllElements_EmptyStore_SeedsFromLegacyPath()
    {
        await _fixture.InitializeAsync();
        await EnsureSystemSetupAsync();

        // Fixed, recognisable IDs — matched by attribute value in the assertions.
        const string idAaaa = "seed-aaaa";
        const string idBbbb = "seed-bbbb";
        const string xmlA = $"<key id=\"{idAaaa}\" version=\"1\"><creationDate>2026-01-01T00:00:00Z</creationDate></key>";
        const string xmlB = $"<key id=\"{idBbbb}\" version=\"1\"><creationDate>2026-01-02T00:00:00Z</creationDate></key>";

        var ct = TestContext.Current.CancellationToken;
        var tempDir = Path.Combine(Path.GetTempPath(), $"dp-seed-isolated-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        try
        {
            // Write the two legacy key files that the seed logic looks for (pattern: key-*.xml).
            await File.WriteAllTextAsync(Path.Combine(tempDir, "key-seed-aaaa.xml"), xmlA, ct);
            await File.WriteAllTextAsync(Path.Combine(tempDir, "key-seed-bbbb.xml"), xmlB, ct);

            // ---- Act 1 --------------------------------------------------------
            // store1 sees an EMPTY DataProtectionKey collection (this class's own fresh
            // fixture guarantees emptiness — no StoreElement has been called here).
            // GetAllElements() must trigger TrySeedFromLegacyFilesAsync, import both
            // files, and return them.
            var store1 = new DataProtectionKeyStore(
                _fixture.Provider!.GetRequiredService<IServiceScopeFactory>(),
                Options.Create(new OctoIdentityServicesOptions
                {
                    IdentityServerLicenseKey = "test",
                    AutoMapperLicenseKey = "test",
                    DataProtectionKeysPath = tempDir
                }));

            var elements1 = store1.GetAllElements();

            // ---- Assert 1 -------------------------------------------------------
            // Use ToString-based matching (avoids null-propagation in expression trees).
            elements1.Should().Contain(
                e => e.ToString(SaveOptions.DisableFormatting).Contains($"id=\"{idAaaa}\""),
                $"seed file 'key-seed-aaaa.xml' must be imported by TrySeedFromLegacyFilesAsync");
            elements1.Should().Contain(
                e => e.ToString(SaveOptions.DisableFormatting).Contains($"id=\"{idBbbb}\""),
                $"seed file 'key-seed-bbbb.xml' must be imported by TrySeedFromLegacyFilesAsync");

            // ---- Act 2 -----------------------------------------------------------
            // Remove the legacy directory to simulate the PVC being decommissioned
            // after the zero-logout migration.
            Directory.Delete(tempDir, recursive: true);

            // A brand-new store instance with no legacy path — elements must come from
            // Mongo alone (seeded by store1 above).
            var store2 = new DataProtectionKeyStore(
                _fixture.Provider!.GetRequiredService<IServiceScopeFactory>(),
                Options.Create(new OctoIdentityServicesOptions
                {
                    IdentityServerLicenseKey = "test",
                    AutoMapperLicenseKey = "test",
                    DataProtectionKeysPath = null
                }));

            var elements2 = store2.GetAllElements();

            // ---- Assert 2 -------------------------------------------------------
            elements2.Should().Contain(
                e => e.ToString(SaveOptions.DisableFormatting).Contains($"id=\"{idAaaa}\""),
                $"seeded element '{idAaaa}' must survive in MongoDB after legacy dir removed");
            elements2.Should().Contain(
                e => e.ToString(SaveOptions.DisableFormatting).Contains($"id=\"{idBbbb}\""),
                $"seeded element '{idBbbb}' must survive in MongoDB after legacy dir removed");
        }
        finally
        {
            if (Directory.Exists(tempDir))
            {
                Directory.Delete(tempDir, recursive: true);
            }
        }
    }
}
