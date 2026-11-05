using System.Threading.RateLimiting;
using IdentityServerPersistence.Configuration.Options;
using Microsoft.Extensions.Options;

namespace Meshmakers.Octo.Backend.IdentityServices.Services;

/// <summary>
///     Per-subject throttle of <c>GET /api/tenant-topology</c> (AB#7044).
/// </summary>
/// <remarks>
///     The ASP.NET rate-limiter middleware runs before authentication in this host, so it cannot partition by
///     the token's subject. The controller therefore asks this limiter after the bearer token has been
///     validated: partitions exist only for authenticated subjects (an invalid token is answered 401 first and
///     never allocates a partition), which bounds the key space by the number of real users.
/// </remarks>
public interface ITenantTopologyRateLimiter
{
    /// <returns><c>true</c> when the subject may proceed, <c>false</c> when the limit is exhausted (429).</returns>
    bool TryAcquire(string subject);
}

/// <inheritdoc />
public sealed class TenantTopologyRateLimiter : ITenantTopologyRateLimiter, IDisposable
{
    private readonly PartitionedRateLimiter<string> _limiter;

    public TenantTopologyRateLimiter(IOptions<OctoIdentityServicesOptions> options)
    {
        var permits = Math.Max(1, options.Value.TenantTopology.RateLimitPermitsPerMinute);
        _limiter = PartitionedRateLimiter.Create<string, string>(subject =>
            RateLimitPartition.GetSlidingWindowLimiter(subject, _ => new SlidingWindowRateLimiterOptions
            {
                PermitLimit = permits,
                Window = TimeSpan.FromMinutes(1),
                SegmentsPerWindow = 6,
                QueueLimit = 0
            }));
    }

    public bool TryAcquire(string subject)
    {
        using var lease = _limiter.AttemptAcquire(subject);
        return lease.IsAcquired;
    }

    public void Dispose() => _limiter.Dispose();
}
