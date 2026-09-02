using System.Collections.Immutable;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace IdentityServerPersistence.SystemStores.OpenIddict;

/// <summary>
///     Pure one-way transform from the legacy <see cref="RtClient" /> configuration shape
///     (<c>AllowedGrantTypes</c>, <c>AllowedScopes</c>, flags) to OpenIddict's permissions and
///     requirements model (AB#4991). The stored client data does NOT change — the transform runs
///     at read time inside <see cref="OpenIddictApplicationStore" />.
/// </summary>
/// <remarks>
///     Mapping rules (see docs/CONCEPT-OPENIDDICT-MIGRATION.md §4.3):
///     <list type="bullet">
///         <item><c>authorization_code</c> → authorization code grant + <c>code</c> response type
///             + authorize/token/PAR/end-session endpoints.</item>
///         <item><c>client_credentials</c> → client credentials grant + token endpoint.</item>
///         <item><c>urn:ietf:params:oauth:grant-type:device_code</c> → device code grant +
///             device authorization/token endpoints.</item>
///         <item><c>urn:ietf:params:oauth:grant-type:token-exchange</c> → token exchange grant +
///             token endpoint (native OpenIddict flow since 7.0, AB#4992).</item>
///         <item><c>AllowOfflineAccess</c> → refresh token grant.</item>
///         <item>every entry of <c>AllowedScopes</c> → scope permission
///             (<c>scp:&lt;name&gt;</c>).</item>
///         <item><c>RequirePkce</c> → PKCE requirement.</item>
///     </list>
///     Revocation is permitted for every client (/connect/revocation has always been open to all
///     authenticated clients on this platform). Introspection stays with API-resource secrets and
///     is NOT granted to clients — /connect/introspect authenticates API resources, as before the
///     migration.
/// </remarks>
public static class ClientPermissionsMapper
{
    public const string DeviceCodeGrantType = "urn:ietf:params:oauth:grant-type:device_code";
    public const string TokenExchangeGrantType = "urn:ietf:params:oauth:grant-type:token-exchange";

    /// <summary>The OctoMesh delegation ("on-behalf-of") grant type URN (AB#5026).</summary>
    public const string OnBehalfOfGrantType = "urn:meshmakers:params:oauth:grant-type:on-behalf-of";

    /// <summary>Computes the OpenIddict permission set for a client.</summary>
    public static ImmutableArray<string> MapPermissions(RtClient client)
    {
        var permissions = ImmutableArray.CreateBuilder<string>();

        var grantTypes = client.AllowedGrantTypes?.ToList() ?? [];
        var usesTokenEndpoint = false;

        if (grantTypes.Contains(GrantTypes.AuthorizationCode))
        {
            permissions.Add(Permissions.GrantTypes.AuthorizationCode);
            permissions.Add(Permissions.ResponseTypes.Code);
            permissions.Add(Permissions.Endpoints.Authorization);
            permissions.Add(Permissions.Endpoints.PushedAuthorization);
            permissions.Add(Permissions.Endpoints.EndSession);
            usesTokenEndpoint = true;
        }

        if (grantTypes.Contains(GrantTypes.ClientCredentials))
        {
            permissions.Add(Permissions.GrantTypes.ClientCredentials);
            usesTokenEndpoint = true;
        }

        if (grantTypes.Contains(DeviceCodeGrantType))
        {
            permissions.Add(Permissions.GrantTypes.DeviceCode);
            permissions.Add(Permissions.Endpoints.DeviceAuthorization);
            usesTokenEndpoint = true;
        }

        if (grantTypes.Contains(TokenExchangeGrantType))
        {
            permissions.Add(Permissions.GrantTypes.TokenExchange);
            usesTokenEndpoint = true;
        }

        if (grantTypes.Contains(OnBehalfOfGrantType))
        {
            // Custom flow (AB#5026): OpenIddict models non-built-in grants as prefixed permissions.
            permissions.Add(Permissions.Prefixes.GrantType + OnBehalfOfGrantType);
            usesTokenEndpoint = true;
        }

        // The stored client configuration models refresh tokens via AllowOfflineAccess; a
        // "refresh_token" entry in AllowedGrantTypes is a legacy variant that is also honored.
        if (client.AllowOfflineAccess || grantTypes.Contains(GrantTypes.RefreshToken))
        {
            permissions.Add(Permissions.GrantTypes.RefreshToken);
            usesTokenEndpoint = true;
        }

        if (usesTokenEndpoint)
        {
            permissions.Add(Permissions.Endpoints.Token);
        }

        // Token revocation is available to every authenticated client (pre-migration behavior
        // consumers rely on).
        permissions.Add(Permissions.Endpoints.Revocation);

        foreach (var scope in client.AllowedScopes ?? Enumerable.Empty<string>())
        {
            if (!string.IsNullOrWhiteSpace(scope))
            {
                permissions.Add(Permissions.Prefixes.Scope + scope);
            }
        }

        return permissions.Distinct(StringComparer.Ordinal).ToImmutableArray();
    }

    /// <summary>Computes the OpenIddict requirement set for a client.</summary>
    public static ImmutableArray<string> MapRequirements(RtClient client)
    {
        return client.RequirePkce
            ? [Requirements.Features.ProofKeyForCodeExchange]
            : ImmutableArray<string>.Empty;
    }
}
