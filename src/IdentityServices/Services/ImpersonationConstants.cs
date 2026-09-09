namespace Meshmakers.Octo.Backend.IdentityServices.Services;

/// <summary>
///     Protocol constants of the OctoMesh impersonation grant (AB#5114), shared by
///     <c>ImpersonationProcessor</c> (which validates the request and resolves the target's roles),
///     <c>TokenEndpointController</c> (which issues the client-credentials-shaped principal for the
///     target), <c>OctoAccessTokenShapeHandler</c> (which re-stamps <c>client_id</c> and strips
///     <c>sub</c>) and <c>OidcTenantResolutionMiddleware</c> (which wires the request to the target
///     tenant).
/// </summary>
/// <remarks>
///     <para>
///         The grant lets an authenticated confidential client (the <b>actor</b>, typically an
///         adapter's own AB#5072 chart client) obtain a token that is byte-for-byte shaped like a
///         <c>client_credentials</c> token of a <b>different</b> client (the target, typically a
///         pipeline service account) — without ever holding the target's secret. Authorization is
///         the explicit <c>System.Identity/MayActAs</c> edge actor→target in the request tenant;
///         no edge, no token.
///     </para>
///     <para>
///         <b>Own grant-type URN</b>, for the same reason the delegation grant has one (see
///         <see cref="DelegationConstants.OnBehalfOfGrantType" />): the URN is the per-client
///         opt-in surface. Sharing the delegation or token-exchange URN would silently hand every
///         client already allowed to delegate or exchange the far stronger capability of becoming
///         another client outright.
///     </para>
/// </remarks>
public static class ImpersonationConstants
{
    /// <summary>The OctoMesh-proprietary grant type URN for client impersonation (AB#5114).</summary>
    public const string ImpersonationGrantType = "urn:meshmakers:params:oauth:grant-type:impersonate";

    /// <summary>
    ///     The request parameter naming the target client's <c>client_id</c>. Also accepted by the
    ///     on-behalf-of grant, where it names the service account an authorized actor delegates
    ///     through (AB#5114 extension of AB#5026).
    /// </summary>
    public const string RequestedClientIdParameter = "requested_client_id";

    /// <summary>
    ///     The <c>act</c> ("actor") claim type — deliberately the same claim, in the same flat
    ///     <c>client_id</c>-string v1 shape, as the delegation grant's
    ///     (<see cref="DelegationConstants.ActClaimType" />): consumers and the audit trail read one
    ///     claim to learn who really called, regardless of which grant minted the token.
    /// </summary>
    public const string ActClaimType = DelegationConstants.ActClaimType;

    /// <summary>The authentication method recorded on the issued token for auditability.</summary>
    public const string AuthenticationMethod = "impersonation";
}
