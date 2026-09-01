using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.IdentityServices.OpenIddict.Interaction;

/// <summary>
///     The validated context of a pending authorize request, parsed from the <c>returnUrl</c>
///     round-tripped through the login/consent SPA pages (AB#4995). Replaces Duende's
///     <c>AuthorizationRequest</c> for the interaction layer.
/// </summary>
public sealed record OctoAuthorizationContext
{
    public required string ReturnUrl { get; init; }
    public required RtClient Client { get; init; }
    public IReadOnlyList<string> Scopes { get; init; } = [];
    public IReadOnlyList<string> AcrValues { get; init; } = [];

    /// <summary>The tenant requested via <c>acr_values=tenant:{id}</c>, if any.</summary>
    public string? TenantId { get; init; }

    /// <summary>The idp filter requested via <c>acr_values=idp:{scheme}</c>, if any.</summary>
    public string? IdP { get; init; }
}

/// <summary>
///     Error page context round-tripped through the self-contained, data-protected
///     <c>errorId</c> query parameter (no server-side storage — multi-pod safe). Replaces
///     Duende's error message store (AB#4950 semantics preserved).
/// </summary>
public sealed record OctoErrorContext
{
    public required string Error { get; init; }
    public string? ErrorDescription { get; init; }
    public string? RequestId { get; init; }
    public string? ClientId { get; init; }
    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;
}

/// <summary>
///     Logout page context round-tripped through the self-contained, data-protected
///     <c>logoutId</c> query parameter. Created by the end-session endpoint; consumed by the
///     SPA logout flow. Replaces Duende's logout message store.
/// </summary>
public sealed record OctoLogoutContext
{
    public string? ClientId { get; init; }
    public string? ClientName { get; init; }
    public string? PostLogoutRedirectUri { get; init; }
    public string? State { get; init; }
    public string? SessionId { get; init; }
    public string? SubjectId { get; init; }
    public string? TenantId { get; init; }
    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;
}

/// <summary>
///     The one-time consent decision round-tripped from the consent SPA page back to the
///     authorize endpoint through the data-protected <c>octo_consent</c> query parameter —
///     stateless, so it works across pods without a server-side consent message store.
/// </summary>
public sealed record OctoConsentDecision
{
    public required string SubjectId { get; init; }
    public required string ClientId { get; init; }
    public bool Denied { get; init; }
    public IReadOnlyList<string> ScopesConsented { get; init; } = [];
    public string? Description { get; init; }
    public DateTimeOffset CreatedAt { get; init; } = DateTimeOffset.UtcNow;
}

/// <summary>A user's remembered grant for a client (consents + offline access), for the grants page.</summary>
public sealed record OctoUserGrant
{
    public required string ClientId { get; init; }
    public IReadOnlyList<string> Scopes { get; init; } = [];
    public DateTime Created { get; init; }
    public DateTime? Expires { get; init; }
}
