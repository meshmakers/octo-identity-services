namespace IdentityServerPersistence.Services.SelfService;

/// <summary>
///     The Signal bridge endpoint one OTP send goes out over: the bridge base URL and the sender
///     account number (E.164). Resolved per tenant at send time (AB#5154).
/// </summary>
/// <param name="ApiUrl">Base URL of the signal-cli-rest-api bridge, e.g. <c>http://localhost:8080</c>.</param>
/// <param name="Number">The registered sender account number in E.164, e.g. <c>+4366012345678</c>.</param>
public sealed record TenantSignalBridgeEndpoint(string ApiUrl, string Number);

/// <summary>
///     Resolves the tenant's own Signal sender from its <c>System.Communication/SignalChannel</c>
///     entity (AB#5143/5145 — the Studio-activated, tenant-owned phone number; rtWellKnownName
///     <c>signal-channel</c>). The sender number is TENANT state, not deployment state (AB#5154):
///     a tenant that activated a number in the Studio sends the self-service phone OTP from that
///     number, with no identity-service configuration involved.
/// </summary>
/// <remarks>
///     Read-only: the entity is owned by the Communication Controller (the only component allowed
///     to talk to the bridge's registration API); this resolver only reads <c>Number</c> /
///     <c>ApiUrl</c> of a channel whose <c>RegistrationState</c> is <c>Registered</c>. Any state
///     short of Registered — and any read failure, e.g. a tenant whose System.Communication CK
///     model predates the SignalChannel type — resolves to <c>null</c>, letting the caller fall
///     back to the env-bound <see cref="Configuration.Options.SignalBridgeOptions" />.
/// </remarks>
public interface ITenantSignalChannelResolver
{
    /// <summary>
    ///     Returns the tenant's Registered Signal channel as a send endpoint, or <c>null</c> when
    ///     the tenant has no usable registered channel (no entity, none in the Registered state, or
    ///     the read failed). Never throws.
    /// </summary>
    Task<TenantSignalBridgeEndpoint?> ResolveRegisteredChannelAsync(
        string tenantId, CancellationToken cancellationToken = default);
}
