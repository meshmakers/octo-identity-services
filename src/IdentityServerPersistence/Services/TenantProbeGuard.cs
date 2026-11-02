using System.Collections.Concurrent;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Configuration;
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
///     Callers treat "unavailable" like the failure they already handled: fail closed, do not cache it.
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
    TimeProvider? timeProvider = null) : ITenantProbeGuard
{
    private readonly TimeProvider _time = timeProvider ?? TimeProvider.System;
    private readonly ConcurrentDictionary<string, State> _states = new(StringComparer.OrdinalIgnoreCase);

    /// <inheritdoc />
    public async Task<TenantProbeResult<T>> RunAsync<T>(OctoTenant tenant, string operation, Func<Task<T>> probe)
    {
        var state = _states.GetOrAdd(tenant.TenantId, _ => new State());
        var settings = options.Value;

        if (!state.TryEnter(_time.GetUtcNow()))
        {
            return new TenantProbeResult<T>(false, default);
        }

        Task<T>? task = null;
        try
        {
            task = probe();
            var value = await task.WaitAsync(settings.ProbeTimeout, _time).ConfigureAwait(false);
            state.Close();
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
            if (state.Open(now, now + settings.OpenDuration))
            {
                LogOpened(tenant, operation, settings, ex);
            }

            return new TenantProbeResult<T>(false, default);
        }
    }

    private void LogOpened(OctoTenant tenant, string operation, TenantProbeGuardOptions settings, Exception ex)
    {
        var user = FormatUser(tenant.DatabaseName);
        if (IsAuthenticationFailure(ex))
        {
            logger.LogError(ex,
                "Tenant '{TenantId}' is skipped for {OpenSeconds:F0} s: the {Operation} could not authenticate against its " +
                "database '{DatabaseName}'. The MongoDB user '{DatabaseUser}' does not exist or rejects the configured " +
                "credentials; the tenant setup retry re-creates the user, or create it with readWrite on '{DatabaseName}'.",
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

        /// <summary>True when the caller may probe: the circuit is closed, or it is half-open and no probe runs.</summary>
        public bool TryEnter(DateTimeOffset now)
        {
            lock (_gate)
            {
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

        public void Close()
        {
            lock (_gate)
            {
                _openUntil = null;
                _probing = false;
            }
        }

        /// <summary>Opens the circuit; true when it was closed or half-open (worth logging), false for a concurrent duplicate.</summary>
        public bool Open(DateTimeOffset now, DateTimeOffset until)
        {
            lock (_gate)
            {
                var report = _openUntil is null || now >= _openUntil;
                _openUntil = until;
                _probing = false;
                return report;
            }
        }
    }
}
