using FluentAssertions;
using IdentityServerPersistence.Services;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.ConstructionKit.Contracts.DataTransferObjects;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Services;

/// <summary>
///     CK v2 Phase 1 G-H2: by-name "embedded version or newer within the same major" checks that replace the
///     exact-version <c>IsCkModelExistingAsync</c> calls once the engine's downgrade guard lets a tenant keep a
///     newer model.
/// </summary>
public class CkModelCompatibilityTests
{
    private static readonly CkModelId Embedded = new("System.Identity", "2.22.0");

    [Theory]
    [InlineData(null, CkModelCompatibilityState.NotInstalled)]
    [InlineData("2.21.5", CkModelCompatibilityState.Older)]
    [InlineData("1.99.0", CkModelCompatibilityState.Older)]
    [InlineData("2.22.0", CkModelCompatibilityState.Same)]
    [InlineData("2.22.1", CkModelCompatibilityState.NewerSameMajor)]
    [InlineData("2.30.0", CkModelCompatibilityState.NewerSameMajor)]
    [InlineData("3.0.0", CkModelCompatibilityState.NewerMajor)]
    public void Classify(string? installedVersion, CkModelCompatibilityState expected)
    {
        var installed = installedVersion == null ? null : new CkModelId("System.Identity", installedVersion);

        CkModelCompatibility.Classify(Embedded, installed).Should().Be(expected);
    }

    [Theory]
    [InlineData(CkModelCompatibilityState.Same, true)]
    [InlineData(CkModelCompatibilityState.NewerSameMajor, true)]
    [InlineData(CkModelCompatibilityState.NotInstalled, false)]
    [InlineData(CkModelCompatibilityState.Older, false)]
    [InlineData(CkModelCompatibilityState.NewerMajor, false)]
    public void IsSatisfied_OnlyForSameOrNewerSameMajor(CkModelCompatibilityState state, bool satisfied)
    {
        new CkModelCompatibilityResult(Embedded, null, state).IsSatisfied.Should().Be(satisfied);
    }

    [Fact]
    public void Evaluate_PicksTheHighestAvailableVersionOfTheSameName()
    {
        var result = CkModelCompatibility.Evaluate(Embedded,
        [
            (new CkModelId("System.Identity", "2.22.0"), ModelState.Available),
            (new CkModelId("System.Identity", "2.25.0"), ModelState.Available),
            (new CkModelId("System", "9.0.0"), ModelState.Available)
        ]);

        result.Installed.Should().Be(new CkModelId("System.Identity", "2.25.0"));
        result.State.Should().Be(CkModelCompatibilityState.NewerSameMajor);
    }

    [Theory]
    [InlineData(ModelState.Importing)]
    [InlineData(ModelState.ResolveFailed)]
    public void Evaluate_IgnoresModelsThatAreNotAvailable(ModelState state)
    {
        // A ResolveFailed model is not in the CK cache (its types are unusable); Importing is transient.
        var result = CkModelCompatibility.Evaluate(Embedded,
        [
            (new CkModelId("System.Identity", "2.22.0"), ModelState.Available),
            (new CkModelId("System.Identity", "3.0.0"), state)
        ]);

        result.State.Should().Be(CkModelCompatibilityState.Same);
    }

    [Fact]
    public void TooOldMessage_NamesBothVersionsAndMajors()
    {
        var result = new CkModelCompatibilityResult(Embedded, new CkModelId("System.Identity", "3.1.0"),
            CkModelCompatibilityState.NewerMajor);

        var message = CkModelCompatibility.TooOldMessage("acme", result);

        message.Should().Contain("acme").And.Contain("System.Identity-3.1.0").And.Contain("System.Identity-2.22.0")
            .And.Contain("too old");
    }

    [Fact]
    public void EmbeddedOrNewerSameMajor_IsTheRangeFromTheEmbeddedVersionToTheNextMajor()
    {
        var range = DefaultConfigurationCreatorService.EmbeddedOrNewerSameMajor(Embedded);

        range.Name.Should().Be("System.Identity");
        range.ModelVersionRange.MinVersion!.ToString().Should().Be("2.22.0");
        range.ModelVersionRange.IsSatisfiedBy(new CkVersion("2.30.0")).Should().BeTrue();
        range.ModelVersionRange.IsSatisfiedBy(new CkVersion("3.0.0")).Should().BeFalse();
        range.ModelVersionRange.IsSatisfiedBy(new CkVersion("2.21.0")).Should().BeFalse();
    }
}
