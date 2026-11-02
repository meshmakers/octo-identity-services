using IdentityServerPersistence.Services;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;

namespace Shared.TestUtilities.Fakes;

/// <summary>
///     <see cref="ITenantProbeGuard" /> without timeout and circuit: runs the probe and reports a failure as
///     "unavailable", which is what the callers did before the guard existed (AB#8177).
/// </summary>
public sealed class PassThroughTenantProbeGuard : ITenantProbeGuard
{
    public async Task<TenantProbeResult<T>> RunAsync<T>(OctoTenant tenant, string operation, Func<Task<T>> probe)
    {
        try
        {
            return new TenantProbeResult<T>(true, await probe());
        }
        catch (Exception)
        {
            return new TenantProbeResult<T>(false, default);
        }
    }
}
