namespace IdentityServerPersistence.Services;

/// <summary>
///     Hook that runs after a tenant's setup completed outside the cold-start initialization loop —
///     on the background setup retry (<c>FailedTenantRetryBackgroundService</c>) and on every tenant
///     lifecycle event (PosCreateTenant / PosUpdateTenant, attach, restore, enable).
/// </summary>
/// <remarks>
///     <para>
///         Lets layers above the persistence assembly (which cannot be referenced from here) react to a
///         tenant becoming usable, e.g. registering its external identity provider auth schemes. A
///         tenant whose setup failed during cold start is skipped by the startup initializers; this
///         hook is how it catches up once the retry succeeds (AB#5540).
///     </para>
///     <para>
///         Implementations must be idempotent: the hook fires on every completed non-cold-start setup.
///         A throwing handler is logged and does not fail the setup or stop the other handlers.
///     </para>
/// </remarks>
public interface ITenantSetupCompletedHandler
{
    /// <summary>
    ///     Called after the setup of <paramref name="tenantId" /> completed successfully.
    /// </summary>
    /// <param name="tenantId">Normalized tenant id.</param>
    Task OnTenantSetupCompletedAsync(string tenantId);
}
