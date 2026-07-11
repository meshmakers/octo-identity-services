namespace IdentityServerPersistence.Services.DynamicClientRegistration;

/// <summary>
///     Hand-rolled RFC 7591 Dynamic Client Registration (AB#4338). Validates a registration request
///     against the security gate, builds a public authorization-code+PKCE <c>RtClient</c> in the
///     system tenant (flagged <c>DynamicRegistration=true</c> + <c>AutoProvisionInChildTenants=true</c>),
///     mirrors it into every existing tenant so it is resolvable wherever the user authenticates
///     (§9 email-first tenant-discovery), and returns the RFC 7591 client information. Deduplicates
///     identical redirect-URI sets so a client that re-registers on every launch does not accumulate.
/// </summary>
public interface IDynamicClientRegistrationService
{
    /// <summary>
    ///     Registers (or re-issues) a dynamic client. Never throws for a bad request — the failure is
    ///     carried in the returned <see cref="DynamicClientRegistrationResult"/>.
    /// </summary>
    Task<DynamicClientRegistrationResult> RegisterAsync(
        DynamicClientRegistrationRequest request, CancellationToken cancellationToken = default);
}
