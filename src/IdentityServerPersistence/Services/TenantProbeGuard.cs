using System.Collections.Concurrent;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Configuration;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using MongoDB.Driver;

namespace IdentityServerPersistence.Services;

/// <summary>Options of <see cref="TenantProbeGuard" /> (section <see cref="SectionName" />).</summary>
public class TenantProbeGuardOptions
{
    /// <summary>Configuration section.</summary>
    public const string SectionName = "TenantProbeGuard";

    /// <summary>
    ///     Longest a single probe of one tenant database may take. A healthy probe is a single-collection read
    ///     (milliseconds); a tenant database that cannot be reached or authenticated takes the driver ~10 s per attempt.
    /// </summary>
    public TimeSpan ProbeTimeout { get; set; } = TimeSpan.FromSeconds(3);

    /// <summary>
    ///     How long a tenant stays "open" (probes answer immediately without touching its database) after a failed
    ///     probe, before the next request probes it again.
    /// </summary>
    public TimeSpan OpenDuration { get; set; } = TimeSpan.FromSeconds(60);
}

/// <summary>Outcome of a guarded probe.</summary>
/// <param name="Succeeded">False when the circuit of the tenant was open, the probe timed out or it failed.</param>
/// <param name="Value">The probe result when <paramref name="Succeeded" />, otherwise the default.</param>
public readonly record struct TenantProbeResult<T>(bool Succeeded, T? Value);

/// <summary>
///     Guards the per-request probes of tenant databases (AB#8177). Token issuance, tenant discovery and the CORS
///     policy read from <b>other</b> tenants' databases than the one the request is for (cross-tenant mappings, user
///     search, client origins). When one such tenant's MongoDB user is missing, every one of those probes used to wait
///     ~10 s for the failed authentication, repeated 2-3 times per request, so a single broken tenant slowed every
///     token request of all tenants to 18-30 s.
/// </summary>
/// <remarks>
///     Per tenant a small circuit breaker: a probe is bounded by <see cref="TenantProbeGuardOptions.ProbeTimeout" />;
///     a failed or timed out probe opens the circuit for <see cref="TenantProbeGuardOptions.OpenDuration" />, during
///     which probes of that tenant answer "unavailable" immediately and without I/O. After that exactly one request
///     probes again (half-open); a success closes the circuit. The failure is logged once per opening at error level
///     with the tenant, its database and the name of the MongoDB user, which is the clear signal the bug asked for.
///     A failure that looks like a missing or rejected database user (authentication error, or the timeout a SCRAM
///     attempt against a missing user runs into) also asks <see cref="TenantDatabaseUserHealer" /> to re-create the
///     user in the background, rate-limited per tenant: a running tenant heals without a restart (AB#8177) and the
///     circuit closes as soon as the user is back. Callers treat "unavailable" like the failure they already handled: fail closed, do not cache it.
/// </remarks>
public interface ITenantProbeGuard
{
    /// <summary>Runs <paramref name="probe" /> against the database of <paramref name="tenant" /> under the guard.</summary>
    /// <param name="tenant">The probed tenant.</param>
    /// <param name="operation">Short description for the log, e.g. "external tenant user mapping lookup".</param>
    /// <param name="probe">The read.</param>
    Task<TenantProbeResult<T>> RunAsync<T>(OctoTenant tenant, string operation, Func<Task<T>> probe);
}

/// <inheritdoc />
public sealed class TenantProbeGuard(
    IOptions<TenantProbeGuardOptions> options,
    IOptions<OctoSystemConfiguration> systemConfiguration,
    ILogger<TenantProbeGuard> logger,
    TimeProvider? timeProvider = null,
    ISystemContext? systemContext = null,
    TenantDatabaseUserHealer? healer = null) : ITenantProbeGuard
{
    private readonly TenantDatabaseUserHealer _healer = healer ?? TenantDatabaseUserHealer.Default;

    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;
    private readonly ConcurrentDictionary<string, State> _states = new(StringComparer.OrdinalIgnoreCase);

    /// <inheritdoc />
    public async Task<TenantProbeResult<T>> RunAsync<T>(OctoTenant tenant, string operation, Func<Task<T>> probe)
    {
        var state = _states.GetOrAdd(tenant.TenantId, _ => new State());
        var settings = options.Value;

        if (!state.TryEnter(_time.GetUtcNow(), out var generation))
        {
            return new TenantProbeResult<T>(false, default);
        }

        Task<T>? task = null;
        try
        {
            task = probe();
            var value = await task.WaitAsync(settings.ProbeTimeout, _time).ConfigureAwait(false);
            state.Close(generation);
            return new TenantProbeResult<T>(true, value);
        }
        catch (Exception ex)
        {
            if (task is { IsCompleted: false })
            {
                // Timed out: the abandoned probe may still fail later; never leave its exception unobserved.
                _ = task.ContinueWith(t => _ = t.Exception, CancellationToken.None,
                    TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously,
                    TaskScheduler.Default);
            }

            var now = _time.GetUtcNow();
            if (state.Open(generation, now, now + settings.OpenDuration))
            {
                LogOpened(tenant, operation, settings, ex);
            }

            if (systemContext is not null && MayBeAMissingDatabaseUser(ex))
            {
                HealInBackground(systemContext, tenant, state, ex);
            }

            return new TenantProbeResult<T>(false, default);
        }
    }

    /// <summary>
    ///     A missing user surfaces as an authentication error (pooled connection: MongoDB error 13) or, on a fresh
    ///     connection, as the SCRAM attempt that exceeds the probe timeout.
    /// </summary>
    private static bool MayBeAMissingDatabaseUser(Exception ex) =>
        TenantDatabaseUserHealer.IsAuthenticationFailure(ex) || ex is TimeoutException;

    /// <summary>
    ///     Re-creates the tenant's MongoDB user off the request path (the admin connection can be as slow as the
    ///     failed probe) and closes the circuit once the user was missing and is back.
    /// </summary>
    private void HealInBackground(ISystemContext healingContext, OctoTenant tenant, State state, Exception cause)
    {
        _ = Task.Run(async () =>
        {
            try
            {
                var result = await _healer.TryHealAsync(healingContext, tenant.TenantId, logger, cause).ConfigureAwait(false);
                // Created: the user was missing and is back. AlreadyPresent after an authentication failure: the user
                // was re-created elsewhere and the healer evicted this process's stale pooled connections.
                if (result == TenantDatabaseUserEnsureResult.Created ||
                    (result == TenantDatabaseUserEnsureResult.AlreadyPresent &&
                     TenantDatabaseUserHealer.IsAuthenticationFailure(cause)))
                {
                    state.Reset();
                }
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Healing the MongoDB user of tenant '{TenantId}' failed", tenant.TenantId);
            }
        });
    }

    private void LogOpened(OctoTenant tenant, string operation, TenantProbeGuardOptions settings, Exception ex)
    {
        var user = FormatUser(tenant.DatabaseName);
        if (IsAuthenticationFailure(ex))
        {
            logger.LogError(ex,
                "Tenant '{TenantId}' is skipped for {OpenSeconds:F0} s: the {Operation} could not authenticate against its " +
                "database '{DatabaseName}'. The MongoDB user '{DatabaseUser}' does not exist or rejects the configured " +
                "credentials; it is re-created automatically within about a minute (AB#8177), or create it with readWrite on '{DatabaseName}'.",
                tenant.TenantId, settings.OpenDuration.TotalSeconds, operation, tenant.DatabaseName, user,
                tenant.DatabaseName);
        }
        else
        {
            logger.LogError(ex,
                "Tenant '{TenantId}' is skipped for {OpenSeconds:F0} s: the {Operation} on its database " +
                "'{DatabaseName}' (MongoDB user '{DatabaseUser}') failed or took longer than {TimeoutSeconds:F0} s.",
                tenant.TenantId, settings.OpenDuration.TotalSeconds, operation, tenant.DatabaseName, user,
                settings.ProbeTimeout.TotalSeconds);
        }
    }

    private string FormatUser(string databaseName)
    {
        var format = systemConfiguration.Value.DatabaseUser;
        return string.IsNullOrWhiteSpace(format) ? "(none configured)" : string.Format(format, databaseName.ToLowerInvariant());
    }

    private static bool IsAuthenticationFailure(Exception ex)
    {
        for (Exception? current = ex; current is not null; current = current.InnerException)
        {
            if (current is MongoAuthenticationException)
            {
                return true;
            }
        }

        return false;
    }

    private sealed class State
    {
        private readonly object _gate = new();
        private DateTimeOffset? _openUntil;
        private bool _probing;
        private long _generation;

        /// <summary>
        ///     True when the caller may probe: the circuit is closed, or it is half-open and no probe runs.
        ///     <paramref name="generation" /> identifies the circuit state the probe started in.
        /// </summary>
        public bool TryEnter(DateTimeOffset now, out long generation)
        {
            lock (_gate)
            {
                generation = _generation;
                if (_openUntil is null)
                {
                    return true;
                }

                if (now < _openUntil || _probing)
                {
                    return false;
                }

                _probing = true;
                return true;
            }
        }

        /// <summary>
        ///     Closes the circuit after a successful probe, unless another probe opened it meanwhile: concurrent probes
        ///     overlap while the circuit is closed, and a late success must not clear an opening it did not see.
        /// </summary>
        public void Close(long generation)
        {
            lock (_gate)
            {
                if (generation != _generation)
                {
                    return;
                }

                _openUntil = null;
                _probing = false;
            }
        }

        /// <summary>Closes the circuit unconditionally (the cause was fixed): the next probe runs at once.</summary>
        public void Reset()
        {
            lock (_gate)
            {
                _generation++;
                _openUntil = null;
                _probing = false;
            }
        }

        /// <summary>
        ///     Opens the circuit; true when it was closed or half-open (worth logging), false for a concurrent duplicate.
        ///     A failure of a probe that started in an earlier circuit state (<paramref name="generation" /> differs) is
        ///     stale - the circuit was opened or reset meanwhile - and leaves the current state alone, so a late failure
        ///     cannot re-open a circuit the healing just closed.
        /// </summary>
        public bool Open(long generation, DateTimeOffset now, DateTimeOffset until)
        {
            lock (_gate)
            {
                if (generation != _generation)
                {
                    return false;
                }

                var report = _openUntil is null || now >= _openUntil;
                _generation++;
                _openUntil = until;
                _probing = false;
                return report;
            }
        }
    }
}
