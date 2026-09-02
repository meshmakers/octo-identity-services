namespace Meshmakers.Octo.Backend.IdentityServices.Services;

/// <summary>
///     Protocol constants of the OctoMesh delegation ("on-behalf-of") grant (AB#5026), shared by
///     <c>OnBehalfOfProcessor</c> (which validates the request and resolves the role intersection),
///     <c>TokenEndpointController</c> (which issues the delegated principal) and
///     <c>OidcTenantResolutionMiddleware</c> (which wires the request to the target tenant).
/// </summary>
public static class DelegationConstants
{
    /// <summary>
    ///     The OctoMesh-proprietary grant type URN for delegation.
    /// </summary>
    /// <remarks>
    ///     <para>
    ///         <b>Deliberately NOT the RFC 8693 token-exchange URN</b>
    ///         (<c>urn:ietf:params:oauth:grant-type:token-exchange</c>), even though the request
    ///         shape is token-exchange-like. The grant type is the per-client <b>opt-in surface</b>
    ///         (an <c>AllowedGrantTypes</c> entry becomes a grant permission): sharing the URN
    ///         would mean every client already allowed to token-exchange would implicitly be
    ///         allowed to delegate.
    ///     </para>
    ///     <para>
    ///         That surface is not hypothetical. The only client carrying the token-exchange grant
    ///         today is <c>octo-mcpServices-device</c>, a <b>public client with no secret</b>
    ///         (<c>RequireClientSecret: false</c>, empty <c>Secrets</c>, seeded by the
    ///         <c>System.Identity.Bootstrap</c> blueprint). A shared URN would let that secretless
    ///         client mint delegated tokens. Separate URNs keep the two capabilities as separate,
    ///         individually auditable <c>AllowedGrantTypes</c> entries.
    ///     </para>
    /// </remarks>
    public const string OnBehalfOfGrantType = "urn:meshmakers:params:oauth:grant-type:on-behalf-of";

    /// <summary>
    ///     The <c>act</c> ("actor") claim type. Carries the <c>client_id</c> of the service account
    ///     that acted on the user's behalf, so downstream services and the audit trail can tell a
    ///     delegated token apart from a token the user obtained themselves.
    /// </summary>
    /// <remarks>
    ///     RFC 8693 models <c>act</c> as a nested JSON object; this v1 emits the flat
    ///     <c>client_id</c> string, which is what the consuming pipelines need and what the CK
    ///     record stamps store. Widening it to the nested form is a breaking change for consumers
    ///     and is therefore deferred.
    /// </remarks>
    public const string ActClaimType = "act";

    /// <summary>The authentication method recorded on the issued token for auditability.</summary>
    public const string AuthenticationMethod = "delegation";
}
