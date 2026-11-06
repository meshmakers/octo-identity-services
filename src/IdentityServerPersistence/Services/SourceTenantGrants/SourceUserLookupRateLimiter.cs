using IdentityServerPersistence.Configuration.Options;
using Microsoft.Extensions.Options;

namespace IdentityServerPersistence.Services.SourceTenantGrants;

/// <summary>
///     Limit of the source user lookup per caller and target tenant (AB#8341, concept §4): a sliding window of
///     <see cref="SourceUserLookupRateLimitOptions.PermitLimit" /> lookups per
///     <see cref="SourceUserLookupRateLimitOptions.Window" />, in memory per pod like the sign-in limits.
/// </summary>
public interface ISourceUserLookupRateLimiter
{
    /// <summary>
    ///     Takes one permit for <paramref name="callerKey" /> in <paramref name="targetTenantId" />. Returns <c>null</c>
    ///     when the lookup may run, otherwise the seconds until the oldest counted lookup leaves the window (at least 1).
    /// </summary>
    int? TryAcquire(string callerKey, string targetTenantId);
}

/// <inheritdoc cref="ISourceUserLookupRateLimiter" />
/// <remarks>
///     An exact sliding log (the timestamps of the counted lookups, at most <c>PermitLimit</c> per key) instead of the
///     segmented <c>System.Threading.RateLimiting</c> limiter: the answer must name the real wait time in
///     <c>Retry-After</c> and <c>retryAfterSeconds</c>, and the limiter must not start a timer (every in-process test
///     host would keep it alive, AB#8337). Keys whose window has passed are swept when the map grows.
/// </remarks>
public sealed class SourceUserLookupRateLimiter(IOptions<OctoIdentityServicesOptions> options, TimeProvider timeProvider)
    : ISourceUserLookupRateLimiter
{
    private const int SweepThreshold = 4096;

    private readonly SourceUserLookupRateLimitOptions _options = options.Value.SourceUserLookupRateLimit;
    private readonly Dictionary<string, Queue<DateTimeOffset>> _log = new(StringComparer.Ordinal);
    private readonly Lock _gate = new();

    /// <inheritdoc />
    public int? TryAcquire(string callerKey, string targetTenantId)
    {
        if (!_options.Enabled)
        {
            return null;
        }

        var limit = Math.Max(1, _options.PermitLimit);
        var window = _options.Window > TimeSpan.Zero ? _options.Window : TimeSpan.FromMinutes(10);
        var now = timeProvider.GetUtcNow();
        var key = $"{targetTenantId.ToLowerInvariant()}\n{callerKey}";

        lock (_gate)
        {
            if (_log.Count > SweepThreshold)
            {
                Sweep(now, window);
            }

            if (!_log.TryGetValue(key, out var stamps))
            {
                stamps = new Queue<DateTimeOffset>(limit);
                _log[key] = stamps;
            }

            while (stamps.Count > 0 && stamps.Peek() + window <= now)
            {
                stamps.Dequeue();
            }

            if (stamps.Count < limit)
            {
                stamps.Enqueue(now);
                return null;
            }

            var wait = stamps.Peek() + window - now;
            return Math.Max(1, (int)Math.Ceiling(wait.TotalSeconds));
        }
    }

    private void Sweep(DateTimeOffset now, TimeSpan window)
    {
        foreach (var (key, stamps) in _log.ToList())
        {
            if (stamps.Count == 0 || stamps.Last() + window <= now)
            {
                _log.Remove(key);
            }
        }
    }
}
