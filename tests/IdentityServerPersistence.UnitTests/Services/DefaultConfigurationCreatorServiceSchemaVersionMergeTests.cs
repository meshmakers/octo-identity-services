using FluentAssertions;
using IdentityServerPersistence.Services;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Services;

/// <summary>
///     CK v2 D8 (AB#5902): after the engine has imported (and migrated) a new model version during tenant setup,
///     the identity's own data-migration run must not be handed the stale pre-import version — otherwise
///     the upgrade service reads "schema older than MigrationHistory", assumes a manual downgrade and runs
///     the same migration a second time.
/// </summary>
public class DefaultConfigurationCreatorServiceSchemaVersionMergeTests
{
    [Fact]
    public void ModelUpdatedByTheImport_ContributesItsPostImportVersion()
    {
        var merged = DefaultConfigurationCreatorService.MergeSchemaVersionsAfterImport(
            new Dictionary<string, string> { ["System.Identity"] = "2.22.0", ["System"] = "2.5.0" },
            new Dictionary<string, string> { ["System.Identity"] = "2.23.0", ["System"] = "2.5.0" },
            new Dictionary<string, string> { ["System.Identity"] = "2.23.0", ["System"] = "2.5.0" });

        merged["System.Identity"].Should().Be("2.23.0");
    }

    [Fact]
    public void ModelNotTouchedByTheImport_KeepsItsPreImportVersion()
    {
        var merged = DefaultConfigurationCreatorService.MergeSchemaVersionsAfterImport(
            new Dictionary<string, string> { ["System.Notification"] = "2.1.0" },
            new Dictionary<string, string> { ["System.Notification"] = "2.1.0" },
            new Dictionary<string, string>());

        merged["System.Notification"].Should().Be("2.1.0");
    }

    [Fact]
    public void ModelMissingAfterTheImport_KeepsItsPreImportVersion()
    {
        // GetSchemaVersionsAsync only lists Available models; a model that is mid-import or failed must not
        // vanish from the map, or its pending data migration would be skipped.
        var merged = DefaultConfigurationCreatorService.MergeSchemaVersionsAfterImport(
            new Dictionary<string, string> { ["System.Identity"] = "2.22.0" },
            new Dictionary<string, string>(),
            new Dictionary<string, string>());

        merged["System.Identity"].Should().Be("2.22.0");
    }

    [Fact]
    public void ModelsOnlyPresentAfterTheImport_AreNotAdded()
    {
        var merged = DefaultConfigurationCreatorService.MergeSchemaVersionsAfterImport(
            new Dictionary<string, string> { ["System"] = "2.5.0" },
            new Dictionary<string, string> { ["System"] = "2.5.0", ["System.Identity"] = "2.23.0" },
            new Dictionary<string, string> { ["System.Identity"] = "2.23.0" });

        merged.Should().ContainSingle().Which.Key.Should().Be("System");
    }

    /// <summary>
    ///     N2: the model has no MigrationHistory row and the engine's import-time migration failed
    ///     (only logged). The pre-import version must stay, so the upgrade service migrates from it instead
    ///     of recording "already at target" and leaving the data in the old shape.
    /// </summary>
    [Fact]
    public void ImportChangedTheModel_ButNoMigrationHistoryRow_KeepsPreImportVersion()
    {
        var merged = DefaultConfigurationCreatorService.MergeSchemaVersionsAfterImport(
            new Dictionary<string, string> { ["System.Identity"] = "2.22.0" },
            new Dictionary<string, string> { ["System.Identity"] = "2.23.0" },
            new Dictionary<string, string>());

        merged["System.Identity"].Should().Be("2.22.0");
    }

    /// <summary>
    ///     The engine's import-time migration failed with an existing (older) history row: history stays
    ///     behind the post-import version, so the pre-import version is kept and the migration is retried.
    /// </summary>
    [Fact]
    public void ImportChangedTheModel_ButHistoryStillAtAnOlderVersion_KeepsPreImportVersion()
    {
        var merged = DefaultConfigurationCreatorService.MergeSchemaVersionsAfterImport(
            new Dictionary<string, string> { ["System.Identity"] = "2.22.0" },
            new Dictionary<string, string> { ["System.Identity"] = "2.23.0" },
            new Dictionary<string, string> { ["System.Identity"] = "2.22.0" });

        merged["System.Identity"].Should().Be("2.22.0");
    }

    /// <summary>
    ///     F1.0-S1 interplay: the engine's downgrade guard skipped the embedded import because the tenant already
    ///     runs a newer version. The schema version is unchanged, so the model is not "changed by the import"
    ///     and keeps its (newer) pre-import version — with or without a MigrationHistory row.
    /// </summary>
    [Theory]
    [InlineData("2.24.0")]
    [InlineData(null)]
    public void ImportSkippedByDowngradeGuard_KeepsPreImportVersion(string? historyVersion)
    {
        var history = new Dictionary<string, string>();
        if (historyVersion != null)
        {
            history["System.Identity"] = historyVersion;
        }

        var merged = DefaultConfigurationCreatorService.MergeSchemaVersionsAfterImport(
            new Dictionary<string, string> { ["System.Identity"] = "2.24.0" },
            new Dictionary<string, string> { ["System.Identity"] = "2.24.0" },
            history);

        merged["System.Identity"].Should().Be("2.24.0");
    }

    /// <summary>
    ///     No import happened, but MigrationHistory is ahead of the schema (manual downgrade): the pre-import
    ///     (schema) version is handed over unchanged, so the upgrade service's downgrade handling still applies.
    /// </summary>
    [Fact]
    public void NoImport_HistoryAheadOfSchema_KeepsPreImportVersion()
    {
        var merged = DefaultConfigurationCreatorService.MergeSchemaVersionsAfterImport(
            new Dictionary<string, string> { ["System.Identity"] = "2.22.0" },
            new Dictionary<string, string> { ["System.Identity"] = "2.22.0" },
            new Dictionary<string, string> { ["System.Identity"] = "2.23.0" });

        merged["System.Identity"].Should().Be("2.22.0");
    }
}
