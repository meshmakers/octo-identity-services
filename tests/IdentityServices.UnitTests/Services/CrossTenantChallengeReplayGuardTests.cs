using FluentAssertions;
using Meshmakers.Octo.Backend.IdentityServices.Services;
using Microsoft.Extensions.Caching.Memory;
using Xunit;

namespace IdentityServices.UnitTests.Services;

/// <summary>AB#7861 — a cross-tenant two-factor challenge is single-use.</summary>
public class CrossTenantChallengeReplayGuardTests
{
    private readonly CrossTenantChallengeReplayGuard _sut = new(new MemoryCache(new MemoryCacheOptions()));

    [Fact]
    public void Nonce_IsUnusedUntilMarked_ThenUsed()
    {
        _sut.IsUsed("n1").Should().BeFalse();

        _sut.MarkUsed("n1", TimeSpan.FromMinutes(5));

        _sut.IsUsed("n1").Should().BeTrue();
        _sut.IsUsed("n2").Should().BeFalse("only the marked challenge is void");
    }

    [Fact]
    public async Task Marker_ExpiresWithTheChallengeLifetime()
    {
        _sut.MarkUsed("n3", TimeSpan.FromMilliseconds(50));

        await Task.Delay(TimeSpan.FromMilliseconds(200), TestContext.Current.CancellationToken);

        _sut.IsUsed("n3").Should().BeFalse("the cookie itself has expired by then, the marker need not outlive it");
    }
}
