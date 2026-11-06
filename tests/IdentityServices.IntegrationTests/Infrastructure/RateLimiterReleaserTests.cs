using FluentAssertions;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace IdentityServices.IntegrationTests.Infrastructure;

/// <summary>
///     AB#8337: pins that <see cref="RateLimiterReleaser" /> still finds the limiter of ASP.NET Core's
///     <c>RateLimitingMiddleware</c> in the identity pipeline and disposes it when the host stops. If a framework update
///     changes the internal shape the releaser walks, these tests fail instead of every test host leaking again.
/// </summary>
public class RateLimiterReleaserTests(CustomWebApplicationFactory factory) : IntegrationTestBase(factory)
{
    [Fact]
    public void TheWalk_FindsTheLimiterOfTheRateLimitingMiddleware()
    {
        using var derived = Factory.WithWebHostBuilder(_ => { });
        var server = derived.Services.GetRequiredService<IServer>();

        RateLimiterReleaser.FindRateLimitingMiddlewareLimiters(server).Should().NotBeEmpty(
            "Program.cs calls app.UseRateLimiter() with the tenant-discovery and dcr policies");
    }

    [Fact]
    public async Task StoppingTheHost_DisposesTheLimiter()
    {
        var derived = Factory.WithWebHostBuilder(_ => { });
        var server = derived.Services.GetRequiredService<IServer>();
        var limiters = RateLimiterReleaser.FindRateLimitingMiddlewareLimiters(server);
        var releaser = derived.Services.GetServices<IHostedService>().OfType<RateLimiterReleaser>().Single();
        var context = new DefaultHttpContext();

        await derived.DisposeAsync();

        releaser.DisposedLimiterCount.Should().Be(limiters.Count);
        foreach (var limiter in limiters)
        {
            limiter.Invoking(l => l.AttemptAcquire(context)).Should().Throw<ObjectDisposedException>();
        }
    }
}
