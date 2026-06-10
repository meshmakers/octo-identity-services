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
/// Real-Mongo tests for <see cref="DataProtectionKeyStore"/>: persistence, idempotency,
/// and seed-once import from a legacy file-system path.
/// </summary>
[Collection("Sequential")]
public class DataProtectionKeyStoreIntegrationTests : IClassFixture<IdentityServicesFixture>
{
    private readonly IdentityServicesFixture _fixture;

    public DataProtectionKeyStoreIntegrationTests(IdentityServicesFixture fixture, ITestOutputHelper outputHelper)
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

    private DataProtectionKeyStore CreateStore(string? keysPath = null)
    {
        return new DataProtectionKeyStore(
            _fixture.Provider!.GetRequiredService<IServiceScopeFactory>(),
            Options.Create(new OctoIdentityServicesOptions
            {
                IdentityServerLicenseKey = "test",
                AutoMapperLicenseKey = "test",
                DataProtectionKeysPath = keysPath
            }));
    }

    [Fact]
    public async Task StoreAndGetAll_RoundTripsXml()
    {
        await _fixture.InitializeAsync();
        await EnsureSystemSetupAsync();

        var uniqueContent = Guid.NewGuid().ToString("N");
        var friendlyName = $"key-roundtrip-{Guid.NewGuid():N}";
        var element = XElement.Parse($"<key id=\"k1-{uniqueContent}\"><payload>test-data</payload></key>");

        var store = CreateStore();
        store.StoreElement(element, friendlyName);

        var allElements = store.GetAllElements();

        allElements.Should().NotBeNull();
        allElements.Should().Contain(
            e => e.ToString(SaveOptions.DisableFormatting) ==
                 element.ToString(SaveOptions.DisableFormatting),
            "stored element must be retrievable with identical XML content");
    }

    [Fact]
    public async Task StoreElement_SameFriendlyName_Twice_IsIdempotent()
    {
        await _fixture.InitializeAsync();
        await EnsureSystemSetupAsync();

        var uniqueContent = Guid.NewGuid().ToString("N");
        var friendlyName = $"key-idem-{Guid.NewGuid():N}";
        var element = XElement.Parse($"<key id=\"idem-{uniqueContent}\"><data>idempotent</data></key>");

        var store = CreateStore();
        store.StoreElement(element, friendlyName);
        store.StoreElement(element, friendlyName); // second call with same name — must be no-op

        var allElements = store.GetAllElements();

        var matchingContent = allElements
            .Where(e => e.ToString(SaveOptions.DisableFormatting) ==
                        element.ToString(SaveOptions.DisableFormatting))
            .ToList();

        matchingContent.Should().HaveCount(1,
            "storing the same friendlyName twice must not create duplicate documents");
    }

    /// <summary>
    /// Verifies that keys stored via <c>StoreElement</c> by one store instance are visible to a
    /// second, independent store instance — confirming that MongoDB is the authoritative backing
    /// store and that no instance-level caching causes isolation.
    /// </summary>
    /// <remarks>
    /// The seed-import (zero-logout migration) code path is covered in isolation by
    /// <see cref="DataProtectionKeySeedIntegrationTests.GetAllElements_EmptyStore_SeedsFromLegacyPath"/>,
    /// which runs against a guaranteed-empty collection in its own class fixture.
    /// </remarks>
    [Fact]
    public async Task StoredKeys_SurviveAcrossStoreInstances()
    {
        var ct = TestContext.Current.CancellationToken;
        await _fixture.InitializeAsync();
        await EnsureSystemSetupAsync();

        // Use unique, recognisable IDs — asserted with 'contains' semantics.
        var idAaaa = $"seed-aaaa-{Guid.NewGuid():N}";
        var idBbbb = $"seed-bbbb-{Guid.NewGuid():N}";
        var friendlyNameA = $"key-{idAaaa}";
        var friendlyNameB = $"key-{idBbbb}";
        var xmlA = $"<key id=\"{idAaaa}\" version=\"1\"><creationDate>2026-01-01</creationDate></key>";
        var xmlB = $"<key id=\"{idBbbb}\" version=\"1\"><creationDate>2026-01-02</creationDate></key>";

        var tempDir = Path.Combine(Path.GetTempPath(), $"dp-seed-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        try
        {
            await File.WriteAllTextAsync(Path.Combine(tempDir, $"{friendlyNameA}.xml"), xmlA, ct);
            await File.WriteAllTextAsync(Path.Combine(tempDir, $"{friendlyNameB}.xml"), xmlB, ct);

            // store1: if the DataProtectionKey collection is currently empty, the seed path
            // fires and imports both files. If not empty, the seed is skipped, but the SECOND
            // store instance below (with the same path) will have _seedAttempted=false and will
            // attempt the seed on its first call, which again only fires when the collection is
            // truly empty (idempotent design). Either way, we ensure the elements are in MongoDB
            // via the explicit StoreElement calls below so the persistence-across-instances
            // assertion is always meaningful.
            var store1 = CreateStore(keysPath: tempDir);

            // Explicitly ensure both keys are in the DB regardless of seed-fire status.
            // StoreElement is idempotent (unique index on FriendlyName), so double-storing is safe.
            store1.StoreElement(XElement.Parse(xmlA), friendlyNameA);
            store1.StoreElement(XElement.Parse(xmlB), friendlyNameB);

            var elements1 = store1.GetAllElements();

            elements1.Should().Contain(
                e => e.ToString(SaveOptions.DisableFormatting).Contains(idAaaa),
                $"seeded element '{friendlyNameA}' must be present after StoreElement + GetAllElements");
            elements1.Should().Contain(
                e => e.ToString(SaveOptions.DisableFormatting).Contains(idBbbb),
                $"seeded element '{friendlyNameB}' must be present after StoreElement + GetAllElements");

            // Delete the temp dir to simulate the PVC being removed post-migration.
            Directory.Delete(tempDir, recursive: true);

            // store2: DIFFERENT instance, no legacy path — elements must come from MongoDB alone.
            // This is the core assertion: elements persisted by store1 survive across instances.
            var store2 = CreateStore(keysPath: null);
            var elements2 = store2.GetAllElements();

            elements2.Should().Contain(
                e => e.ToString(SaveOptions.DisableFormatting).Contains(idAaaa),
                $"seeded element '{friendlyNameA}' must survive in MongoDB after temp dir deleted");
            elements2.Should().Contain(
                e => e.ToString(SaveOptions.DisableFormatting).Contains(idBbbb),
                $"seeded element '{friendlyNameB}' must survive in MongoDB after temp dir deleted");
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
