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

    [Fact]
    public void PickOldest_WithGate_TwoLookupsOfTheSameDuplicateSet_WarnOnce()
    {
        var oldest = Mapping();
        var newer = Mapping();
        var logger = new CapturingLogger();
        var gate = new ExternalTenantUserMappingLookup.DuplicateWarningGate();

        // A login or a token exchange looks the mapping up twice per request.
        ExternalTenantUserMappingLookup.PickOldest([newer, oldest], "t", "u", logger, gate).Should().BeSameAs(oldest);
        ExternalTenantUserMappingLookup.PickOldest([oldest, newer], "t", "u", logger, gate).Should().BeSameAs(oldest);

        logger.Levels.Count(l => l == LogLevel.Warning).Should().Be(1);
        logger.Levels.Count(l => l == LogLevel.Debug).Should().Be(1, "the repeated lookup is still traceable at debug level");
        logger.Messages.Single(m => m.level == LogLevel.Warning).text
            .Should().Contain(oldest.RtId.ToString()).And.Contain(newer.RtId.ToString()).And.Contain("using the oldest");
    }

    [Fact]
    public void PickOldest_WithGate_ADifferentSourceUser_WarnsAgain()
    {
        var logger = new CapturingLogger();
        var gate = new ExternalTenantUserMappingLookup.DuplicateWarningGate();

        ExternalTenantUserMappingLookup.PickOldest([Mapping(), Mapping()], "t", "u1", logger, gate);
        ExternalTenantUserMappingLookup.PickOldest([Mapping(), Mapping()], "t", "u2", logger, gate);

        logger.Levels.Count(l => l == LogLevel.Warning).Should().Be(2);
    }

    [Fact]
    public void PickOldest_WithoutGate_StillWarnsOnEveryCall()
    {
        var logger = new CapturingLogger();
        var rows = new[] { Mapping(), Mapping() };

        ExternalTenantUserMappingLookup.PickOldest(rows, "t", "u", logger);
        ExternalTenantUserMappingLookup.PickOldest(rows, "t", "u", logger);

        logger.Levels.Count(l => l == LogLevel.Warning).Should().Be(2);
    }

    private sealed class CapturingLogger : ILogger
    {
        public List<(LogLevel level, string text)> Messages { get; } = [];

        public IEnumerable<LogLevel> Levels => Messages.Select(m => m.level);

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter) => Messages.Add((logLevel, formatter(state, exception)));
    }
}
