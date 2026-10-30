using System.Net;
using FluentAssertions;
using IdentityServerPersistence.Configuration.Options;
using Meshmakers.Octo.Backend.IdentityServices.Services;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Xunit;

namespace IdentityServices.UnitTests.Services;

/// <summary>
///     AB#7854 — per-account and per-client limits of the sign-in endpoints.
/// </summary>
public class SignInRateLimiterTests
{
    [Fact]
    public void ParallelAttemptOfTheSameAccount_IsRefused_UntilTheFirstIsDone()
    {
        using var limiter = Create();
        var context = Request("198.51.100.1");

        using (var first = limiter.TryAcquire("user:alice", context))
        {
            first.IsAcquired.Should().BeTrue();
            using var parallel = limiter.TryAcquire("user:alice", context);
            parallel.IsAcquired.Should().BeFalse("only one attempt per account may run at a time");
            using var otherAccount = limiter.TryAcquire("user:bob", context);
            otherAccount.IsAcquired.Should().BeTrue("the concurrency limit is per account");
        }

        using var next = limiter.TryAcquire("user:alice", context);
        next.IsAcquired.Should().BeTrue("the permit is returned when the attempt is evaluated");
    }

    [Fact]
    public void AccountWindow_IsExhaustedAfterTheConfiguredAttempts_CaseInsensitive()
    {
        using var limiter = Create(perAccount: 3);
        var context = Request("198.51.100.2");

        for (var i = 0; i < 3; i++)
        {
            using var lease = limiter.TryAcquire(i % 2 == 0 ? "name:Alice" : "name:ALICE", context);
            lease.IsAcquired.Should().BeTrue();
        }

        using var refused = limiter.TryAcquire("name:alice", context);
        refused.IsAcquired.Should().BeFalse("the user name is one account, whatever its spelling");
    }

    [Fact]
    public void ClientWindow_CountsEveryAccount_AndAttemptsWithoutAccount()
    {
        using var limiter = Create(perClientIp: 3);
        var context = Request("198.51.100.3");

        using (limiter.TryAcquire("name:a", context))
        using (limiter.TryAcquire("name:b", context))
        using (limiter.TryAcquire(null, context))
        {
        }

        using var refused = limiter.TryAcquire("name:c", context);
        refused.IsAcquired.Should().BeFalse();
        using var otherClient = limiter.TryAcquire("name:c", Request("198.51.100.4"));
        otherClient.IsAcquired.Should().BeTrue("each client address has its own budget");
    }

    [Fact]
    public void Disabled_AllowsEverything()
    {
        using var limiter = Create(perAccount: 1, perClientIp: 1, enabled: false);
        var context = Request("198.51.100.6");
        using var first = limiter.TryAcquire("user:dave", context);
        using var second = limiter.TryAcquire("user:dave", context);
        second.IsAcquired.Should().BeTrue();
    }

    [Theory]
    [InlineData("203.0.113.9", "203.0.113.9")]
    [InlineData("10.0.0.1, 203.0.113.9", "203.0.113.9")]
    [InlineData("spoofed, 203.0.113.9 ", "203.0.113.9")]
    [InlineData("not-an-address", "192.0.2.1")]
    public void ClientAddress_IsTheRightMostForwardedEntry_ElseThePeer(string forwardedFor, string expected)
    {
        var context = Request("192.0.2.1");
        context.Request.Headers["X-Forwarded-For"] = forwardedFor;

        SignInRateLimiter.GetClientAddress(context, useForwardedFor: true).Should().Be(expected,
            "entries left of the last one are written by the client and could be chosen freely");
    }

    [Fact]
    public void ClientAddress_IgnoresTheHeader_WhenForwardedForIsOff()
    {
        var context = Request("192.0.2.1");
        context.Request.Headers["X-Forwarded-For"] = "203.0.113.9";

        SignInRateLimiter.GetClientAddress(context, useForwardedFor: false).Should().Be("192.0.2.1");
    }

    [Fact]
    public void Defaults_AreTheDocumentedOnes()
    {
        var options = new SignInRateLimitOptions();
        options.Enabled.Should().BeTrue();
        options.PermitsPerAccountPerMinute.Should().Be(10);
        options.ConcurrentAttemptsPerAccount.Should().Be(1);
        options.PermitsPerClientIpPerMinute.Should().Be(60);
        options.UseForwardedFor.Should().BeTrue();
    }

    private static SignInRateLimiter Create(int perAccount = 10, int perClientIp = 60, bool enabled = true)
        => new(Options.Create(new OctoIdentityServicesOptions
        {
            SignInRateLimit = new SignInRateLimitOptions
            {
                Enabled = enabled,
                PermitsPerAccountPerMinute = perAccount,
                PermitsPerClientIpPerMinute = perClientIp
            }
        }));

    private static DefaultHttpContext Request(string peer)
    {
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = IPAddress.Parse(peer);
        return context;
    }
}
