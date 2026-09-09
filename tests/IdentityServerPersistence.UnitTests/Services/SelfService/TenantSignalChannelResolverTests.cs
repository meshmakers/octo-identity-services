using FluentAssertions;
using IdentityServerPersistence.Services.SelfService;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Runtime.Engine.Repositories.Query;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Shared.TestUtilities.Fakes;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Services.SelfService;

/// <summary>
///     Pins the AB#5154 tenant SignalChannel read: only a channel in the <c>Registered</c> state
///     (2) yields a send endpoint; a channel in any other state, a tenant without the entity (or
///     without the CK type at all — read failure), and an unresolvable tenant all resolve to
///     <c>null</c> so the caller falls back to <c>SignalBridgeOptions</c>. A hand-crafted
///     multi-channel tie is broken deterministically by lowest rtId with a warning. The resolver
///     is strictly read-only — it never writes the entity.
/// </summary>
public class TenantSignalChannelResolverTests
{
    private const string TenantId = "acme";
    private const int Registered = 2;
    private const int CodePending = 1;

    private readonly ISystemContext _systemContext = Substitute.For<ISystemContext>();
    private readonly ITenantRepository _tenantRepository = Substitute.For<ITenantRepository>();
    private readonly RecordingLogger _logger = new();
    private readonly TenantSignalChannelResolver _sut;

    public TenantSignalChannelResolverTests()
    {
        _systemContext.TryFindTenantRepositoryAsync(TenantId)
            .Returns(Task.FromResult<ITenantRepository?>(_tenantRepository));
        _tenantRepository.GetSessionAsync()
            .Returns(Task.FromResult<IOctoSession>(new FakeOctoSession()));

        _sut = new TenantSignalChannelResolver(_systemContext, _logger);
    }

    private void GivenChannels(params RtEntity[] channels)
    {
        _tenantRepository
            .GetRtEntitiesByTypeAsync(
                Arg.Any<IOctoSession>(),
                Arg.Any<RtCkId<CkTypeId>>(),
                Arg.Any<RtEntityQueryOptions>(),
                Arg.Any<int?>(),
                Arg.Any<int?>())
            .Returns(Task.FromResult<IResultSet<RtEntity>>(
                new ResultSet<RtEntity>(channels.ToList(), channels.Length, null, null)));
    }

    private static RtEntity Channel(
        string rtId, int registrationState, string? number = "+436770000001", string? apiUrl = "http://bridge:8080")
    {
        var entity = new RtEntity(
            TenantSignalChannelResolver.SignalChannelCkTypeId, new OctoObjectId(rtId));
        entity.SetAttributeRawValue("RegistrationState", registrationState);
        entity.SetAttributeRawValue("Number", number);
        entity.SetAttributeRawValue("ApiUrl", apiUrl);
        return entity;
    }

    [Fact]
    public async Task Registered_channel_resolves_to_its_number_and_api_url()
    {
        GivenChannels(Channel("000000000000000000000001", Registered));

        var endpoint = await _sut.ResolveRegisteredChannelAsync(TenantId,
            TestContext.Current.CancellationToken);

        endpoint.Should().NotBeNull();
        endpoint!.Number.Should().Be("+436770000001");
        endpoint.ApiUrl.Should().Be("http://bridge:8080");
    }

    [Fact]
    public async Task Channel_not_in_registered_state_resolves_to_null()
    {
        GivenChannels(Channel("000000000000000000000001", CodePending));

        var endpoint = await _sut.ResolveRegisteredChannelAsync(TenantId,
            TestContext.Current.CancellationToken);

        endpoint.Should().BeNull("only a Registered channel may send");
    }

    [Fact]
    public async Task No_channel_entity_resolves_to_null()
    {
        GivenChannels();

        var endpoint = await _sut.ResolveRegisteredChannelAsync(TenantId,
            TestContext.Current.CancellationToken);

        endpoint.Should().BeNull();
    }

    [Fact]
    public async Task Unresolvable_tenant_resolves_to_null()
    {
        _systemContext.TryFindTenantRepositoryAsync("unknown")
            .Returns(Task.FromResult<ITenantRepository?>(null));

        var endpoint = await _sut.ResolveRegisteredChannelAsync("unknown",
            TestContext.Current.CancellationToken);

        endpoint.Should().BeNull();
    }

    [Fact]
    public async Task Read_failure_resolves_to_null_instead_of_throwing()
    {
        // A tenant whose System.Communication CK model predates the SignalChannel type makes the
        // typed read throw — that must degrade to the options fallback, never break OTP delivery.
        _tenantRepository
            .GetRtEntitiesByTypeAsync(
                Arg.Any<IOctoSession>(),
                Arg.Any<RtCkId<CkTypeId>>(),
                Arg.Any<RtEntityQueryOptions>(),
                Arg.Any<int?>(),
                Arg.Any<int?>())
            .Returns<Task<IResultSet<RtEntity>>>(_ => throw new InvalidOperationException("unknown CK type"));

        var endpoint = await _sut.ResolveRegisteredChannelAsync(TenantId,
            TestContext.Current.CancellationToken);

        endpoint.Should().BeNull();
        _logger.Entries.Should().Contain(e => e.Level == LogLevel.Warning);
    }

    [Fact]
    public async Task Multiple_registered_channels_pick_lowest_rtId_with_warning()
    {
        // Singleton by design (service-enforced); a hand-crafted tie is broken deterministically.
        GivenChannels(
            Channel("0000000000000000000000ff", Registered, number: "+430000000099"),
            Channel("000000000000000000000001", Registered, number: "+430000000001"));

        var endpoint = await _sut.ResolveRegisteredChannelAsync(TenantId,
            TestContext.Current.CancellationToken);

        endpoint!.Number.Should().Be("+430000000001", "the lowest rtId wins deterministically");
        _logger.Entries.Should().ContainSingle(e =>
            e.Level == LogLevel.Warning && e.Message.Contains("singleton"));
    }

    [Fact]
    public async Task Registered_channel_missing_number_resolves_to_null_with_warning()
    {
        GivenChannels(Channel("000000000000000000000001", Registered, number: null));

        var endpoint = await _sut.ResolveRegisteredChannelAsync(TenantId,
            TestContext.Current.CancellationToken);

        endpoint.Should().BeNull("a half-configured channel must not be used as sender");
        _logger.Entries.Should().Contain(e => e.Level == LogLevel.Warning);
    }

    [Fact]
    public async Task Resolver_never_writes_the_channel_entity()
    {
        GivenChannels(Channel("000000000000000000000001", Registered));

        await _sut.ResolveRegisteredChannelAsync(TenantId, TestContext.Current.CancellationToken);

        await _tenantRepository.DidNotReceiveWithAnyArgs()
            .ReplaceOneRtEntityByIdAsync(default!, default, default(RtEntity)!);
        await _tenantRepository.DidNotReceiveWithAnyArgs()
            .InsertOneRtEntityAsync(default!, default(RtEntity)!);
    }

    /// <summary>Records formatted log entries so warning paths are assertable.</summary>
    private sealed class RecordingLogger : ILogger<TenantSignalChannelResolver>
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            Entries.Add((logLevel, formatter(state, exception)));
        }
    }
}
