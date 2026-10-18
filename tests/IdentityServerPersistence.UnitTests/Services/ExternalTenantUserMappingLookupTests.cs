using FluentAssertions;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Services;

/// <summary>AB#6975: the duplicate-tolerant pick of an external tenant user mapping.</summary>
public class ExternalTenantUserMappingLookupTests
{
    private static RtExternalTenantUserMapping Mapping() => new() { RtId = OctoObjectId.GenerateNewId() };

    [Fact]
    public void PickOldest_Empty_ReturnsNull() =>
        ExternalTenantUserMappingLookup.PickOldest([], "t", "u").Should().BeNull();

    [Fact]
    public void PickOldest_Single_ReturnsItWithoutWarning()
    {
        var logger = Substitute.For<ILogger>();
        var only = Mapping();

        ExternalTenantUserMappingLookup.PickOldest([only], "t", "u", logger).Should().BeSameAs(only);

        logger.DidNotReceiveWithAnyArgs().Log(default, default, default(object), default, default!);
    }

    [Fact]
    public void PickOldest_TwoRows_ReturnsTheOldestWhateverTheInputOrder_AndWarnsOnce()
    {
        var oldest = Mapping();
        var newer = Mapping();
        var logger = Substitute.For<ILogger>();
        logger.IsEnabled(LogLevel.Warning).Returns(true);

        ExternalTenantUserMappingLookup.PickOldest([newer, oldest], "t", "u", logger).Should().BeSameAs(oldest);
        ExternalTenantUserMappingLookup.PickOldest([oldest, newer], "t", "u").Should().BeSameAs(oldest);

        logger.ReceivedWithAnyArgs(1).Log(LogLevel.Warning, default, default(object), default, default!);
    }
}
