using System.Reflection;
using FluentAssertions;
using Meshmakers.Octo.Backend.IdentityServices.Authorization.RoleChange;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.ConstructionKit.Contracts.BlueprintCatalogs;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServices.UnitTests.Authorization;

/// <summary>
///     AB#8564: platform roles are the roles of the embedded <c>System.Identity.Bootstrap</c> seed; every other built-in role
///     is an app role. The set is read from the blueprint the service applies, never kept by hand.
/// </summary>
public class PlatformRoleCatalogTests
{
    private static readonly string[] PlatformRoleNames =
    [
        "TenantManagement", "UserManagement", "CommunicationManagement", "Development", "AdminPanelManagement",
        "BotManagement", "DashboardManagement", "DashboardViewer", "ReportingManagement", "ReportingViewer",
        "DataModelManagement", "StreamDataAdmin", "StreamDataWriter", "StreamDataReader", "SecretManagement",
        "FileManagement", "FileViewer"
    ];

    private static BootstrapPlatformRoleCatalog RealCatalog()
    {
        var services = new ServiceCollection();
        services.AddBlueprintSystemIdentityBootstrapV1();
        using var provider = services.BuildServiceProvider();
        return new BootstrapPlatformRoleCatalog(provider.GetServices<IBlueprintEmbeddedSource>().ToList(),
            NullLogger<BootstrapPlatformRoleCatalog>.Instance);
    }

    private static RtRole Role(string name, string? wellKnownName, OctoObjectId? rtId = null)
    {
        var role = new RtRoleBuilder().WithName(name).Build();
        role.RtId = rtId ?? OctoObjectId.GenerateNewId();
        role.RtWellKnownName = wellKnownName;
        return role;
    }

    [Fact]
    public void TheEmbeddedBootstrapSeed_YieldsExactlyTheSeventeenBuiltInRoles()
    {
        RealCatalog().WellKnownNames.Should().BeEquivalentTo(PlatformRoleNames);
    }

    [Theory]
    [InlineData("TenantManagement")]
    [InlineData("UserManagement")]
    [InlineData("StreamDataAdmin")]
    [InlineData("SecretManagement")]
    [InlineData("DataModelManagement")]
    public void ABootstrapRole_IsAPlatformRole(string name)
    {
        RealCatalog().IsPlatformRole(Role(name, name)).Should().BeTrue();
    }

    [Theory]
    [InlineData("EnergyCommunityManagement")]
    [InlineData("EnergyCommunityReporting")]
    [InlineData("MeterReporter")]
    [InlineData("MeshmakersAccounting")]
    public void ABuiltInRoleOfAnotherBlueprint_IsAnAppRole(string name)
    {
        RealCatalog().IsPlatformRole(Role(name, name)).Should().BeFalse();
    }

    [Fact]
    public void ACustomRole_IsNotAPlatformRole()
    {
        RealCatalog().IsPlatformRole(Role("UserManagementLookalike", null)).Should().BeFalse();
    }

    [Fact]
    public void ARoleWithTheRtIdOfABootstrapRole_IsAPlatformRole_EvenUnderAnotherWellKnownName()
    {
        RealCatalog().IsPlatformRole(Role("Renamed", "Renamed", new OctoObjectId("660000000000000000000002")))
            .Should().BeTrue();
    }

    [Fact]
    public void WithoutAReadableSeed_EveryBuiltInRoleIsAPlatformRole_FailClosed()
    {
        var empty = new BootstrapPlatformRoleCatalog([], NullLogger<BootstrapPlatformRoleCatalog>.Instance);

        empty.IsPlatformRole(Role("EnergyCommunityManagement", "EnergyCommunityManagement")).Should().BeTrue();
        empty.IsPlatformRole(Role("Custom", null)).Should().BeFalse();
    }

    [Fact]
    public void ABootstrapSourceWithoutARoleSeed_FailsClosed()
    {
        var source = Substitute.For<IBlueprintEmbeddedSource>();
        source.BlueprintId.Returns(new BlueprintId(BootstrapPlatformRoleCatalog.BootstrapBlueprintName, "9.9.9"));
        source.Assembly.Returns(Assembly.GetExecutingAssembly());
        source.ResourceNamespace.Returns("IdentityServices.UnitTests.NoSuchBootstrap");

        var catalog = new BootstrapPlatformRoleCatalog([source], NullLogger<BootstrapPlatformRoleCatalog>.Instance);

        catalog.WellKnownNames.Should().BeEmpty();
        catalog.IsPlatformRole(Role("EnergyCommunityManagement", "EnergyCommunityManagement")).Should().BeTrue();
    }

    [Fact]
    public void ReadRoles_TakesOnlyRoleEntities()
    {
        const string yaml = """
                            entities:
                              - rtId: '660000000000000000000002'
                                ckTypeId: System.Identity/Role
                                rtWellKnownName: UserManagement
                              - rtId: '660000000000000000000040'
                                ckTypeId: System.Identity/Group
                                rtWellKnownName: TenantOwners
                            """;
        var names = new HashSet<string>();
        var ids = new HashSet<string>();

        BootstrapPlatformRoleCatalog.ReadRoles(new StringReader(yaml), names, ids);

        names.Should().Equal("UserManagement");
        ids.Should().Equal("660000000000000000000002");
    }
}
