using FluentAssertions;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.Services.SourceTenantGrants;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Backend.IdentityServices.CrossTenantAudit;
using Meshmakers.Octo.Backend.IdentityServices.OpenIddict;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using NSubstitute.ExceptionExtensions;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Xunit;

namespace IdentityServices.UnitTests.CrossTenantAudit;

/// <summary>
///     AB#8436: a grant event reaches the source tenant S only when S is a registry ancestor of T or permits T. The source
///     tenant and user name of a mapping are free input of T's administrator; every other S gets nothing.
/// </summary>
public class CrossTenantGrantAuditRecorderTests
{
    private const string Target = "target";
    private const string Source = "source";

    private readonly IIdentityAuditService _audit = Substitute.For<IIdentityAuditService>();
    private readonly ITenantRegistry _registry = Substitute.For<ITenantRegistry>();
    private readonly ICrossTenantAncestryGuard _ancestry = Substitute.For<ICrossTenantAncestryGuard>();
    private readonly ISourceTenantGrantPolicy _policy = Substitute.For<ISourceTenantGrantPolicy>();
    private readonly IGroupStore _groups = Substitute.For<IGroupStore>();

    public CrossTenantGrantAuditRecorderTests()
    {
        _registry.TryGetRepositoryAsync(Source).Returns(Substitute.For<ITenantRepository>());
        _ancestry.GetRegistryAncestorsAsync(Target).Returns(Array.Empty<string>());
        _policy.IsPermittedAsync(default!, default!, Arg.Any<CancellationToken>()).ReturnsForAnyArgs(false);
    }

    [Theory]
    [InlineData(CrossTenantGrantAuditEvents.GrantCreated)]
    [InlineData(CrossTenantGrantAuditEvents.GrantChanged)]
    [InlineData(CrossTenantGrantAuditEvents.GrantRemoved)]
    public async Task Grant_ForASourceThatNeitherIsAnAncestorNorPermitsTheTarget_IsRecordedInTargetOnly(string name)
    {
        await Recorder().RecordGrantAsync(name, Target, "admin", Mapping(), []);

        await AssertWrittenToAsync(Target);
    }

    [Fact]
    public async Task Grant_ForAnAncestorSource_IsRecordedInTargetAndSource()
    {
        _ancestry.GetRegistryAncestorsAsync(Target).Returns(new[] { Source.ToUpperInvariant() });

        await Recorder().RecordGrantAsync(CrossTenantGrantAuditEvents.GrantCreated, Target, "admin", Mapping(), []);

        await AssertWrittenToAsync(Target, Source);
        await _policy.DidNotReceiveWithAnyArgs().IsPermittedAsync(default!, default!, Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Grant_ForASourceThatPermitsTheTarget_IsRecordedInTargetAndSource()
    {
        _policy.IsPermittedAsync(Source, Target, Arg.Any<CancellationToken>()).Returns(true);

        await Recorder().RecordGrantAsync(CrossTenantGrantAuditEvents.GrantCreated, Target, "admin", Mapping(), []);

        await AssertWrittenToAsync(Target, Source);
    }

    [Fact]
    public async Task Grant_WhenThePermissionCannotBeDecided_IsRecordedInTargetOnly_AndDoesNotThrow()
    {
        _policy.IsPermittedAsync(default!, default!, Arg.Any<CancellationToken>()).ThrowsAsyncForAnyArgs(new InvalidOperationException("down"));

        var act = () => Recorder().RecordGrantAsync(CrossTenantGrantAuditEvents.GrantRemoved, Target, "admin",
            Mapping(), []);

        await act.Should().NotThrowAsync();
        await AssertWrittenToAsync(Target);
    }

    [Fact]
    public async Task Grant_WhenTheAncestryCannotBeRead_IsRecordedInTargetOnly()
    {
        _ancestry.GetRegistryAncestorsAsync(Target).ThrowsAsync(new InvalidOperationException("registry down"));

        await Recorder().RecordGrantAsync(CrossTenantGrantAuditEvents.GrantChanged, Target, "admin", Mapping(), []);

        await AssertWrittenToAsync(Target);
    }

    [Fact]
    public async Task ExchangeRefused_IsStillRecordedInTheValidatedSourceTenant_WithoutAskingThePolicy()
    {
        // The source of a refused exchange comes from the validated subject token, not from free input.
        await Recorder().RecordExchangeRefusedAsync(Target, Source, "user-1", "not permitted");

        await _audit.Received(1).StoreWarningAsync(Source, CrossTenantGrantAuditEvents.ExchangeRefused,
            Arg.Any<string>(), Arg.Any<IReadOnlyDictionary<string, string>?>());
        await _policy.DidNotReceiveWithAnyArgs().IsPermittedAsync(default!, default!, Arg.Any<CancellationToken>());
    }

    private CrossTenantGrantAuditRecorder Recorder()
        => new(_audit, _registry, _ancestry, _policy, _groups, NullLogger<CrossTenantGrantAuditRecorder>.Instance);

    private static RtExternalTenantUserMapping Mapping() => new()
    {
        RtId = OctoObjectId.GenerateNewId(),
        SourceTenantId = Source,
        SourceUserId = OctoObjectId.GenerateNewId().ToString(),
        SourceUserName = "free text"
    };

    private async Task AssertWrittenToAsync(params string[] tenants)
    {
        var written = _audit.ReceivedCalls()
            .Where(c => c.GetMethodInfo().Name == nameof(IIdentityAuditService.StoreInfoAsync))
            .Select(c => (string)c.GetArguments()[0]!)
            .ToList();
        written.Should().BeEquivalentTo(tenants, "each tenant receives the event exactly once");
        await Task.CompletedTask;
    }
}
