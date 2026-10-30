using System.Net;
using System.Threading.RateLimiting;
using IdentityServerPersistence.Configuration.Options;
using Microsoft.Extensions.Options;

namespace Meshmakers.Octo.Backend.IdentityServices.Services;

/// <summary>
///     Per-account and per-client limits of the interactive sign-in endpoints (AB#7854).
/// </summary>
/// <remarks>
///     <para>
///         Three in-memory limiters per pod, asked in this order: the client address (sliding minute), the account's
///         concurrent attempts (default 1, parallel attempts are refused) and the account (sliding minute). The account is
///         the user name of a password login, or the user of a pending second-factor / recovery-code sign-in — so a
///         password guessed through any child tenant, or a TOTP guessed with many parallel requests, shares one budget.
///     </para>
///     <para>
///         The ASP.NET rate-limiter middleware cannot be used: the account is in the request body or behind the
///         two-factor cookie, which only the controller has resolved. The controller therefore asks this limiter and
///         keeps the returned lease until the attempt is evaluated (that is what the concurrency limit counts).
///     </para>
/// </remarks>
public interface ISignInRateLimiter
{
    /// <summary>
    ///     Asks for one sign-in attempt. Dispose the lease when the attempt has been evaluated.
    /// </summary>
    /// <param name="accountKey">The account the attempt is for, or <c>null</c> when none is known (client limit only).</param>
    /// <param name="httpContext">The request (client address).</param>
    SignInAttemptLease TryAcquire(string? accountKey, HttpContext httpContext);
}

/// <summary>Result of <see cref="ISignInRateLimiter.TryAcquire" />; holds the concurrency permit until disposed.</summary>
public sealed class SignInAttemptLease : IDisposable
{
    private readonly RateLimitLease? _concurrencyLease;

    internal SignInAttemptLease(bool isAcquired, RateLimitLease? concurrencyLease)
    {
        IsAcquired = isAcquired;
        _concurrencyLease = concurrencyLease;
    }

    /// <summary>A lease that allows the attempt (limits switched off).</summary>
    public static SignInAttemptLease Allowed { get; } = new(true, null);

    /// <summary><c>false</c>: answer 429 and do not evaluate the attempt.</summary>
    public bool IsAcquired { get; }

    /// <summary>Seconds a refused client should wait (the window length).</summary>
    public static int RetryAfterSeconds => 60;

    public void Dispose() => _concurrencyLease?.Dispose();
}

/// <inheritdoc cref="ISignInRateLimiter" />
public sealed class SignInRateLimiter : ISignInRateLimiter, IDisposable
{
    private readonly SignInRateLimitOptions _options;
    private readonly PartitionedRateLimiter<string> _perClient;
    private readonly PartitionedRateLimiter<string> _perAccount;
    private readonly PartitionedRateLimiter<string> _concurrentPerAccount;

    public SignInRateLimiter(IOptions<OctoIdentityServicesOptions> options)
    {
        _options = options.Value.SignInRateLimit;
        var perClient = Math.Max(1, _options.PermitsPerClientIpPerMinute);
        var perAccount = Math.Max(1, _options.PermitsPerAccountPerMinute);
        var concurrent = Math.Max(1, _options.ConcurrentAttemptsPerAccount);

        _perClient = PartitionedRateLimiter.Create<string, string>(key =>
            RateLimitPartition.GetSlidingWindowLimiter(key, _ => SlidingMinute(perClient)));
        _perAccount = PartitionedRateLimiter.Create<string, string>(key =>
            RateLimitPartition.GetSlidingWindowLimiter(key, _ => SlidingMinute(perAccount)));
        _concurrentPerAccount = PartitionedRateLimiter.Create<string, string>(key =>
            RateLimitPartition.GetConcurrencyLimiter(key, _ => new ConcurrencyLimiterOptions
            {
                PermitLimit = concurrent,
                QueueLimit = 0
            }));
    }

    public SignInAttemptLease TryAcquire(string? accountKey, HttpContext httpContext)
    {
        if (!_options.Enabled)
        {
            return SignInAttemptLease.Allowed;
        }

        using (var clientLease = _perClient.AttemptAcquire(GetClientAddress(httpContext, _options.UseForwardedFor)))
        {
            if (!clientLease.IsAcquired)
            {
                return new SignInAttemptLease(false, null);
            }
        }

        if (string.IsNullOrEmpty(accountKey))
        {
            return SignInAttemptLease.Allowed;
        }

        var key = accountKey.ToUpperInvariant();
        var concurrencyLease = _concurrentPerAccount.AttemptAcquire(key);
        if (!concurrencyLease.IsAcquired)
        {
            concurrencyLease.Dispose();
            return new SignInAttemptLease(false, null);
        }

        using var accountLease = _perAccount.AttemptAcquire(key);
        if (!accountLease.IsAcquired)
        {
            concurrencyLease.Dispose();
            return new SignInAttemptLease(false, null);
        }

        return new SignInAttemptLease(true, concurrencyLease);
    }

    /// <summary>
    ///     The client address: the right-most <c>X-Forwarded-For</c> entry when enabled and present — the address the
    ///     closest proxy (the ingress) saw; entries further left are set by the client and are ignored — otherwise the
    ///     TCP peer.
    /// </summary>
    public static string GetClientAddress(HttpContext httpContext, bool useForwardedFor)
    {
        if (useForwardedFor &&
            httpContext.Request.Headers.TryGetValue("X-Forwarded-For", out var forwardedFor))
        {
            var last = forwardedFor.ToString().Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .LastOrDefault();
            if (last != null && IPAddress.TryParse(last, out var forwarded))
            {
                return forwarded.ToString();
            }
        }

        return httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    }

    private static SlidingWindowRateLimiterOptions SlidingMinute(int permits) => new()
    {
        PermitLimit = permits,
        Window = TimeSpan.FromMinutes(1),
        SegmentsPerWindow = 6,
        QueueLimit = 0
    };

    public void Dispose()
    {
        _perClient.Dispose();
        _perAccount.Dispose();
        _concurrentPerAccount.Dispose();
    }
}
