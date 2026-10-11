using System.Collections.Concurrent;

namespace IdentityServerPersistence.Services.FileRoles;

/// <summary>
///     Serialises the writers of the pipeline service accounts' FileManagement edge inside this process (AB#6457,
///     review of #163): the tenant-setup pass and the identity-data consumer can reach the same account at the same
///     moment, and the engine does not reject a second identical <c>AssignedRole</c> edge — six concurrent runs left six
///     edges in the integration test. Writers take the lock, re-read the edges and insert only what is missing.
///     Several identity replicas starting at the same instant can still race; the edge is then duplicated, which the
///     role reads treat as a set, and the next run finds the account covered.
/// </summary>
public static class PipelineServiceAccountFileRoleLock
{
    private static readonly ConcurrentDictionary<string, SemaphoreSlim> Locks = new(StringComparer.Ordinal);

    public static async Task<IDisposable> AcquireAsync(string tenantId)
    {
        var semaphore = Locks.GetOrAdd(tenantId, _ => new SemaphoreSlim(1, 1));
        await semaphore.WaitAsync().ConfigureAwait(false);
        return new Releaser(semaphore);
    }

    private sealed class Releaser(SemaphoreSlim semaphore) : IDisposable
    {
        public void Dispose() => semaphore.Release();
    }
}
