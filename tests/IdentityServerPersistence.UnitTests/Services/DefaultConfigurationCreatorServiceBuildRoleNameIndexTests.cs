using IdentityServerPersistence.Services;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Services;

/// <summary>
///     Coverage for the duplicate-tolerant role-name index in
///     <see cref="DefaultConfigurationCreatorService.BuildRoleNameIndex"/>. The unguarded
///     <c>.ToDictionary(r =&gt; r.Name)</c> this replaced crashed Identity startup on test-2
///     2026-06-15 — that bug pattern is the regression target. The defensive build must:
///     <list type="bullet">
///         <item>not throw on duplicate names;</item>
///         <item>prefer the blueprint-range (660…) entry so the rest of the restore wires
///             against the authoritative new rtId;</item>
///         <item>surface the duplicate via a structured warning so the data-drift stays
///             visible to operations.</item>
///     </list>
/// </summary>
public class DefaultConfigurationCreatorServiceBuildRoleNameIndexTests
{
    [Fact]
    public void BuildRoleNameIndex_DuplicateName_PrefersBlueprintRtIdAndDoesNotThrow()
    {
        var preBlueprintAdminPanelMgmt = new RtRole
        {
            RtId = new OctoObjectId("686a5f60fd3e5972ff5693cd"),
            Name = "AdminPanelManagement",
            NormalizedName = "ADMINPANELMANAGEMENT",
        };
        var blueprintAdminPanelMgmt = new RtRole
        {
            RtId = new OctoObjectId("660000000000000000000005"),
            Name = "AdminPanelManagement",
            NormalizedName = "ADMINPANELMANAGEMENT",
            RtWellKnownName = "AdminPanelManagement",
        };

        var logger = Substitute.For<ILogger>();

        var index = DefaultConfigurationCreatorService.BuildRoleNameIndex(
            new[] { preBlueprintAdminPanelMgmt, blueprintAdminPanelMgmt },
            tenantId: "test-tenant",
            logger);

        Assert.True(index.TryGetValue("AdminPanelManagement", out var winnerRtId));
        Assert.Equal(blueprintAdminPanelMgmt.RtId, winnerRtId);
    }

    [Fact]
    public void BuildRoleNameIndex_DuplicateName_EmitsWarningWithAllRtIds()
    {
        var preBlueprint = new RtRole
        {
            RtId = new OctoObjectId("686a5f60fd3e5972ff5693cd"),
            Name = "AdminPanelManagement",
            NormalizedName = "ADMINPANELMANAGEMENT",
        };
        var blueprint = new RtRole
        {
            RtId = new OctoObjectId("660000000000000000000005"),
            Name = "AdminPanelManagement",
            NormalizedName = "ADMINPANELMANAGEMENT",
            RtWellKnownName = "AdminPanelManagement",
        };

        var logger = Substitute.For<ILogger>();

        DefaultConfigurationCreatorService.BuildRoleNameIndex(
            new[] { preBlueprint, blueprint },
            tenantId: "test-tenant",
            logger);

        // The structured-log surface is the operational signal we lean on after the crash safety
        // net swallows a duplicate. If this stops emitting, ops loses the only breadcrumb that
        // tells them the underlying drift is still happening.
        logger.Received().Log(
            LogLevel.Warning,
            Arg.Any<EventId>(),
            Arg.Is<object>(state => state!.ToString()!.Contains("AdminPanelManagement")
                                    && state.ToString()!.Contains("660000000000000000000005")
                                    && state.ToString()!.Contains("686a5f60fd3e5972ff5693cd")),
            Arg.Any<Exception?>(),
            Arg.Any<Func<object, Exception?, string>>()!);
    }

    [Fact]
    public void BuildRoleNameIndex_NoDuplicates_DoesNotEmitWarning()
    {
        var blueprintAdmin = new RtRole
        {
            RtId = new OctoObjectId("660000000000000000000005"),
            Name = "AdminPanelManagement",
            NormalizedName = "ADMINPANELMANAGEMENT",
            RtWellKnownName = "AdminPanelManagement",
        };
        var blueprintTenantMgmt = new RtRole
        {
            RtId = new OctoObjectId("660000000000000000000001"),
            Name = "TenantManagement",
            NormalizedName = "TENANTMANAGEMENT",
            RtWellKnownName = "TenantManagement",
        };

        var logger = Substitute.For<ILogger>();

        var index = DefaultConfigurationCreatorService.BuildRoleNameIndex(
            new[] { blueprintAdmin, blueprintTenantMgmt },
            tenantId: "test-tenant",
            logger);

        Assert.Equal(2, index.Count);
        Assert.Equal(blueprintAdmin.RtId, index["AdminPanelManagement"]);
        Assert.Equal(blueprintTenantMgmt.RtId, index["TenantManagement"]);
        logger.DidNotReceive().Log(
            LogLevel.Warning,
            Arg.Any<EventId>(),
            Arg.Any<object>(),
            Arg.Any<Exception?>(),
            Arg.Any<Func<object, Exception?, string>>()!);
    }

    [Fact]
    public void BuildRoleNameIndex_DuplicateWithoutAnyBlueprintEntry_PicksDeterministicallyByRtId()
    {
        // Two operator-created entries with the same name and no blueprint entry. The selection
        // must be deterministic across restarts so reattach-AssignedRole edges don't ping-pong
        // between rtIds. We pick by ordered rtId for that determinism.
        var operatorOlder = new RtRole
        {
            RtId = new OctoObjectId("100000000000000000000001"),
            Name = "DuplicateOperatorRole",
            NormalizedName = "DUPLICATEOPERATORROLE",
        };
        var operatorNewer = new RtRole
        {
            RtId = new OctoObjectId("200000000000000000000001"),
            Name = "DuplicateOperatorRole",
            NormalizedName = "DUPLICATEOPERATORROLE",
        };

        var logger = Substitute.For<ILogger>();

        var index = DefaultConfigurationCreatorService.BuildRoleNameIndex(
            new[] { operatorNewer, operatorOlder },
            tenantId: "test-tenant",
            logger);

        Assert.Equal(operatorOlder.RtId, index["DuplicateOperatorRole"]);
    }

    [Fact]
    public void BuildRoleNameIndex_RolesWithEmptyName_AreSkipped()
    {
        var named = new RtRole
        {
            RtId = new OctoObjectId("660000000000000000000005"),
            Name = "AdminPanelManagement",
            NormalizedName = "ADMINPANELMANAGEMENT",
        };
        var empty = new RtRole
        {
            RtId = new OctoObjectId("686a5f60fd3e5972ff5693cc"),
            Name = "",
        };

        var logger = Substitute.For<ILogger>();

        var index = DefaultConfigurationCreatorService.BuildRoleNameIndex(
            new[] { named, empty },
            tenantId: "test-tenant",
            logger);

        Assert.Single(index);
        Assert.Equal(named.RtId, index["AdminPanelManagement"]);
    }
}
