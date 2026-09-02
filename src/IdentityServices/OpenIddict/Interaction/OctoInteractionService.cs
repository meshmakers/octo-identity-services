using System.Collections.Immutable;
using System.Text.Json;
using IdentityServerPersistence.SystemStores;
using IdentityServerPersistence.SystemStores.OpenIddict;
using Meshmakers.Octo.Backend.IdentityServices.Controllers.Api;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.WebUtilities;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Meshmakers.Octo.Backend.IdentityServices.OpenIddict.Interaction;

/// <summary>
///     The interaction façade the SPA API controllers consume (AB#4995), replacing the former
///     <c>IIdentityServerInteractionService</c>. All round-trip state (error, logout and one-time
///     consent contexts) is carried in self-contained data-protected payloads instead of a
///     server-side message store — multi-pod safe with the shared MongoDB DataProtection key ring.
///     Remembered consent is persisted as a permanent <see cref="RtOAuthAuthorization" />.
/// </summary>
public interface IOctoInteractionService
{
    /// <summary>Parses + validates the pending authorize request from a returnUrl (client must exist).</summary>
    Task<OctoAuthorizationContext?> GetAuthorizationContextAsync(string? returnUrl);

    /// <summary>Open-redirect guard: local URL, /connect/authorize based.</summary>
    bool IsValidReturnUrl(string? returnUrl);

    string CreateErrorId(OctoErrorContext context);
    OctoErrorContext? GetErrorContext(string? errorId);

    string CreateLogoutId(OctoLogoutContext context);
    OctoLogoutContext? GetLogoutContext(string? logoutId);

    /// <summary>
    ///     Records the consent decision: remembered consent persists a permanent authorization;
    ///     the one-time decision (grant or deny) is returned as the redirect URL the SPA
    ///     navigates to (returnUrl + protected <c>octo_consent</c> parameter).
    /// </summary>
    Task<string> GrantConsentAsync(OctoAuthorizationContext context, string subjectId,
        IReadOnlyList<string> scopesConsented, bool rememberConsent, string? description);

    /// <summary>Records a denial; returns the redirect URL (authorize responds access_denied).</summary>
    string DenyConsent(OctoAuthorizationContext context, string subjectId);

    /// <summary>Reads + validates an octo_consent decision for the authorize endpoint.</summary>
    OctoConsentDecision? GetConsentDecision(string? protectedDecision, string subjectId, string clientId);

    /// <summary>Finds a valid remembered (permanent) authorization covering the requested scopes.</summary>
    Task<RtOAuthAuthorization?> FindRememberedConsentAsync(string subjectId, string clientId,
        IReadOnlyList<string> scopes);

    Task<IReadOnlyList<OctoUserGrant>> GetAllUserGrantsAsync(string subjectId);
    Task RevokeUserConsentAsync(string subjectId, string clientId);

    /// <summary>Resolves scope names into the SPA consent DTO items (identity vs API scopes).</summary>
    Task<(List<ScopeItemDto> IdentityScopes, List<ScopeItemDto> ApiScopes)> ResolveScopeItemsAsync(
        IEnumerable<string> scopes);
}

internal class OctoInteractionService(
    IOctoClientStore clientStore,
    IOctoResourceStore resourceStore,
    global::OpenIddict.Abstractions.IOpenIddictAuthorizationStore<RtOAuthAuthorization> authorizationStore,
    global::OpenIddict.Abstractions.IOpenIddictTokenStore<RtOAuthToken> tokenStore,
    IDataProtectionProvider dataProtectionProvider,
    ILogger<OctoInteractionService> logger) : IOctoInteractionService
{
    /// <summary>Query parameter carrying the protected one-time consent decision.</summary>
    public const string ConsentParameterName = "octo_consent";

    private static readonly TimeSpan RoundTripLifetime = TimeSpan.FromMinutes(15);

    private readonly IDataProtector _errorProtector =
        dataProtectionProvider.CreateProtector("OctoInteraction.Error");

    private readonly IDataProtector _logoutProtector =
        dataProtectionProvider.CreateProtector("OctoInteraction.Logout");

    private readonly IDataProtector _consentProtector =
        dataProtectionProvider.CreateProtector("OctoInteraction.Consent");

    public async Task<OctoAuthorizationContext?> GetAuthorizationContextAsync(string? returnUrl)
    {
        if (!IsValidReturnUrl(returnUrl))
        {
            return null;
        }

        var query = ParseQuery(returnUrl!);
        var clientId = query.GetValueOrDefault("client_id").FirstOrDefault();
        if (string.IsNullOrEmpty(clientId))
        {
            return null;
        }

        var client = await clientStore.FindRtClientByIdAsync(clientId);
        if (client is not { Enabled: true })
        {
            return null;
        }

        var scopes = (query.GetValueOrDefault("scope").FirstOrDefault() ?? string.Empty)
            .Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var acrValues = (query.GetValueOrDefault("acr_values").FirstOrDefault() ?? string.Empty)
            .Split(' ', StringSplitOptions.RemoveEmptyEntries);

        return new OctoAuthorizationContext
        {
            ReturnUrl = returnUrl!,
            Client = client,
            Scopes = scopes,
            AcrValues = acrValues,
            TenantId = acrValues
                .FirstOrDefault(v => v.StartsWith("tenant:", StringComparison.OrdinalIgnoreCase))?["tenant:".Length..],
            IdP = acrValues
                .FirstOrDefault(v => v.StartsWith("idp:", StringComparison.OrdinalIgnoreCase))?["idp:".Length..]
        };
    }

    public bool IsValidReturnUrl(string? returnUrl)
    {
        if (string.IsNullOrEmpty(returnUrl))
        {
            return false;
        }

        // Local URL only (no scheme/host, no protocol-relative), targeting the authorize endpoint.
        if (!returnUrl.StartsWith('/') || returnUrl.StartsWith("//") || returnUrl.StartsWith("/\\"))
        {
            return false;
        }

        var path = returnUrl.Split('?', 2)[0];
        return path.Equals("/connect/authorize", StringComparison.OrdinalIgnoreCase) ||
               path.StartsWith("/connect/authorize/", StringComparison.OrdinalIgnoreCase);
    }

    public string CreateErrorId(OctoErrorContext context) => Protect(_errorProtector, context);

    public OctoErrorContext? GetErrorContext(string? errorId)
        => Unprotect<OctoErrorContext>(_errorProtector, errorId, c => c.CreatedAt);

    public string CreateLogoutId(OctoLogoutContext context) => Protect(_logoutProtector, context);

    public OctoLogoutContext? GetLogoutContext(string? logoutId)
        => Unprotect<OctoLogoutContext>(_logoutProtector, logoutId, c => c.CreatedAt);

    public async Task<string> GrantConsentAsync(OctoAuthorizationContext context, string subjectId,
        IReadOnlyList<string> scopesConsented, bool rememberConsent, string? description)
    {
        if (rememberConsent)
        {
            // Remembered consent: a permanent authorization the authorize endpoint (and the
            // grants page) can find on every future request.
            var existing = await FindRememberedConsentAsync(subjectId, context.Client.ClientId, []);
            if (existing != null)
            {
                var merged = (existing.Scopes?.ToList() ?? []).Union(scopesConsented).ToList();
                existing.Scopes = new Meshmakers.Octo.Runtime.Contracts.RepositoryEntities
                    .AttributeStringValueList(merged);
                await authorizationStore.UpdateAsync(existing, CancellationToken.None);
            }
            else
            {
                var authorization = await authorizationStore.InstantiateAsync(CancellationToken.None);
                authorization.SubjectId = subjectId;
                authorization.ClientId = context.Client.ClientId;
                authorization.AuthorizationType = AuthorizationTypes.Permanent;
                authorization.Status = Statuses.Valid;
                authorization.Scopes = new Meshmakers.Octo.Runtime.Contracts.RepositoryEntities
                    .AttributeStringValueList(scopesConsented.ToList());
                authorization.CreationDateTime = DateTime.UtcNow;
                await authorizationStore.CreateAsync(authorization, CancellationToken.None);
            }
        }

        var decision = new OctoConsentDecision
        {
            SubjectId = subjectId,
            ClientId = context.Client.ClientId,
            ScopesConsented = scopesConsented,
            Description = description
        };
        return QueryHelpers.AddQueryString(context.ReturnUrl, ConsentParameterName,
            Protect(_consentProtector, decision));
    }

    public string DenyConsent(OctoAuthorizationContext context, string subjectId)
    {
        var decision = new OctoConsentDecision
        {
            SubjectId = subjectId,
            ClientId = context.Client.ClientId,
            Denied = true
        };
        return QueryHelpers.AddQueryString(context.ReturnUrl, ConsentParameterName,
            Protect(_consentProtector, decision));
    }

    public OctoConsentDecision? GetConsentDecision(string? protectedDecision, string subjectId, string clientId)
    {
        var decision = Unprotect<OctoConsentDecision>(_consentProtector, protectedDecision, c => c.CreatedAt);
        if (decision == null)
        {
            return null;
        }

        // The decision is bound to the user and client it was taken for.
        if (!string.Equals(decision.SubjectId, subjectId, StringComparison.Ordinal) ||
            !string.Equals(decision.ClientId, clientId, StringComparison.Ordinal))
        {
            logger.LogWarning("Consent decision rejected: subject/client mismatch");
            return null;
        }

        return decision;
    }

    public async Task<RtOAuthAuthorization?> FindRememberedConsentAsync(string subjectId, string clientId,
        IReadOnlyList<string> scopes)
    {
        await foreach (var authorization in authorizationStore.FindAsync(
                           subjectId, clientId, Statuses.Valid, AuthorizationTypes.Permanent,
                           null, CancellationToken.None))
        {
            if (scopes.Count == 0 || scopes.All(s => authorization.Scopes?.Contains(s) == true))
            {
                return authorization;
            }
        }

        return null;
    }

    public async Task<IReadOnlyList<OctoUserGrant>> GetAllUserGrantsAsync(string subjectId)
    {
        // Remembered consents (permanent authorizations), one entry per client.
        var byClient = new Dictionary<string, OctoUserGrant>(StringComparer.Ordinal);
        await foreach (var authorization in authorizationStore.FindBySubjectAsync(
                           subjectId, CancellationToken.None))
        {
            if (!string.Equals(authorization.Status, Statuses.Valid, StringComparison.Ordinal) ||
                !string.Equals(authorization.AuthorizationType, AuthorizationTypes.Permanent,
                    StringComparison.Ordinal) ||
                string.IsNullOrEmpty(authorization.ClientId))
            {
                continue;
            }

            byClient[authorization.ClientId] = new OctoUserGrant
            {
                ClientId = authorization.ClientId,
                Scopes = authorization.Scopes?.ToList() ?? [],
                Created = authorization.CreationDateTime ?? DateTime.UtcNow
            };
        }

        // Clients holding live refresh tokens for the user also constitute a grant — the grants
        // page must list them so the user can revoke silent long-lived access.
        // NB: the store persists the URN form (urn:ietf:params:oauth:token-type:refresh_token),
        // not the short TokenTypeHints form — same trap as GenerateTokenContext.TokenType.
        await foreach (var token in tokenStore.FindBySubjectAsync(subjectId, CancellationToken.None))
        {
            if (token.TokenType is not (TokenTypeIdentifiers.RefreshToken or TokenTypeHints.RefreshToken) ||
                !string.Equals(token.Status, Statuses.Valid, StringComparison.Ordinal) ||
                string.IsNullOrEmpty(token.ClientId) ||
                (token.ExpirationDateTime.HasValue && token.ExpirationDateTime.Value <= DateTime.UtcNow))
            {
                continue;
            }

            if (!byClient.ContainsKey(token.ClientId))
            {
                byClient[token.ClientId] = new OctoUserGrant
                {
                    ClientId = token.ClientId,
                    Scopes = [Scopes.OfflineAccess],
                    Created = token.CreationDateTime ?? DateTime.UtcNow,
                    Expires = token.ExpirationDateTime
                };
            }
        }

        return byClient.Values.OrderBy(g => g.ClientId, StringComparer.Ordinal).ToList();
    }

    public async Task RevokeUserConsentAsync(string subjectId, string clientId)
    {
        await authorizationStore.RevokeAsync(subjectId, clientId, null, null, CancellationToken.None);
        await tokenStore.RevokeAsync(subjectId, clientId, null, null, CancellationToken.None);
    }

    public async Task<(List<ScopeItemDto> IdentityScopes, List<ScopeItemDto> ApiScopes)> ResolveScopeItemsAsync(
        IEnumerable<string> scopes)
    {
        var identityScopes = new List<ScopeItemDto>();
        var apiScopes = new List<ScopeItemDto>();

        foreach (var scope in scopes.Distinct(StringComparer.Ordinal))
        {
            if (string.Equals(scope, Scopes.OfflineAccess, StringComparison.Ordinal))
            {
                identityScopes.Add(new ScopeItemDto
                {
                    Name = Scopes.OfflineAccess,
                    DisplayName = "Offline Access",
                    Description = "Access to your applications when you are offline",
                    Emphasize = true,
                    Required = false,
                    Checked = true
                });
                continue;
            }

            var identityResource = await resourceStore.GetIdentityResourceByNameAsync(scope);
            if (identityResource != null)
            {
                identityScopes.Add(new ScopeItemDto
                {
                    Name = identityResource.Name,
                    DisplayName = identityResource.DisplayName ?? identityResource.Name,
                    Description = identityResource.Description,
                    Emphasize = identityResource.IsEmphasized,
                    Required = identityResource.IsRequired,
                    Checked = true
                });
                continue;
            }

            var apiScope = await resourceStore.GetApiScopeByNameAsync(scope);
            if (apiScope != null)
            {
                apiScopes.Add(new ScopeItemDto
                {
                    Name = apiScope.Name,
                    DisplayName = apiScope.DisplayName ?? apiScope.Name,
                    Description = apiScope.Description,
                    Emphasize = apiScope.IsEmphasized,
                    Required = apiScope.IsRequired,
                    Checked = true
                });
            }
        }

        return (identityScopes, apiScopes);
    }

    private static string Protect<T>(IDataProtector protector, T payload)
        => Base64UrlTextEncoder.Encode(
            protector.Protect(JsonSerializer.SerializeToUtf8Bytes(payload)));

    private T? Unprotect<T>(IDataProtector protector, string? payload, Func<T, DateTimeOffset> createdAt)
        where T : class
    {
        if (string.IsNullOrEmpty(payload))
        {
            return null;
        }

        try
        {
            var value = JsonSerializer.Deserialize<T>(
                protector.Unprotect(Base64UrlTextEncoder.Decode(payload)));
            if (value == null || createdAt(value) < DateTimeOffset.UtcNow - RoundTripLifetime)
            {
                return null;
            }

            return value;
        }
        catch (Exception ex)
        {
            logger.LogDebug(ex, "Failed to unprotect interaction round-trip payload");
            return null;
        }
    }

    private static Dictionary<string, Microsoft.Extensions.Primitives.StringValues> ParseQuery(string url)
    {
        var queryIndex = url.IndexOf('?');
        return queryIndex < 0
            ? new Dictionary<string, Microsoft.Extensions.Primitives.StringValues>()
            : QueryHelpers.ParseQuery(url[(queryIndex + 1)..]);
    }
}
