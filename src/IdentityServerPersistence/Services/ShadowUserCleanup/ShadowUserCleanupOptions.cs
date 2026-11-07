namespace IdentityServerPersistence.Services.ShadowUserCleanup;

/// <summary>Mode of the cleanup of rights-less cross-tenant shadow users (AB#8305).</summary>
public enum ShadowUserCleanupMode
{
    /// <summary>Nothing is read or written. The default.</summary>
    Off = 0,

    /// <summary>Logs per tenant every candidate and the skip reason of every other <c>xt_</c> user; writes nothing.</summary>
    DryRun = 1,

    /// <summary>Deletes the candidates through the identity user store, one audit event per deleted user.</summary>
    Apply = 2
}

/// <summary>
///     Options of the shadow user cleanup, bound from the <c>"IdentityApiAuthorization"</c> configuration section,
///     i.e. <c>OCTO_IDENTITYAPIAUTHORIZATION__SHADOWUSERCLEANUP=Off|DryRun|Apply</c>. Shares the section with the
///     identity REST API authorization options; only this key is read here.
/// </summary>
public class ShadowUserCleanupOptions
{
    /// <summary>The configuration section name.</summary>
    public const string SectionName = "IdentityApiAuthorization";

    /// <summary>Gets or sets the cleanup mode. Default <see cref="ShadowUserCleanupMode.Off" />.</summary>
    public ShadowUserCleanupMode ShadowUserCleanup { get; set; } = ShadowUserCleanupMode.Off;
}
