using System.Security.Claims;
using OpenIddictAbstractions = global::OpenIddict.Abstractions;

namespace Meshmakers.Octo.Backend.IdentityServices.Services;

/// <summary>
///     The caller of an audited administrative action, read from the access token claims (AB#7958).
/// </summary>
/// <remarks>
///     The identity service's bearer handler keeps the raw JWT claim names (<c>MapInboundClaims = false</c>), so the
///     octo-cli token carries <c>sub</c> and <c>preferred_username</c> but nothing that maps to
///     <see cref="ClaimsIdentity.Name" /> — <c>User.Identity.Name</c> alone logged <c>(unknown)</c>. Only these four
///     values are read; no other claim value, token or cookie ever reaches an audit line.
/// </remarks>
/// <param name="Subject">The <c>sub</c> claim (for a client-credentials token: the client id).</param>
/// <param name="UserName"><c>preferred_username</c>, else <c>name</c>, else the identity name; <c>null</c> for a client.</param>
/// <param name="ClientId">The <c>client_id</c> (else <c>azp</c>) claim.</param>
/// <param name="TenantId">The caller's <c>tenant_id</c> claim.</param>
public sealed record AuditActor(string? Subject, string? UserName, string? ClientId, string? TenantId)
{
    private const string TenantIdClaimType = "tenant_id";
    private const string AuthorizedPartyClaimType = "azp";
    private const string Unknown = "(unknown)";
    private const string None = "-";

    /// <summary>No caller information (e.g. an internal call).</summary>
    public static AuditActor Anonymous { get; } = new(null, null, null, null);

    /// <summary>Reads the caller from <paramref name="principal" />.</summary>
    public static AuditActor FromPrincipal(ClaimsPrincipal? principal)
    {
        if (principal == null)
        {
            return Anonymous;
        }

        return new AuditActor(
            Value(principal, OpenIddictAbstractions.OpenIddictConstants.Claims.Subject),
            Value(principal, OpenIddictAbstractions.OpenIddictConstants.Claims.PreferredUsername)
            ?? Value(principal, OpenIddictAbstractions.OpenIddictConstants.Claims.Name)
            ?? Blank(principal.Identity?.Name),
            Value(principal, OpenIddictAbstractions.OpenIddictConstants.Claims.ClientId)
            ?? Value(principal, AuthorizedPartyClaimType),
            Value(principal, TenantIdClaimType));
    }

    /// <summary>
    ///     Who acted, for the audit line: the user name, for a client-credentials caller (no user) the client, else the
    ///     subject; <c>(unknown)</c> only when the token carries none of them.
    /// </summary>
    public string Actor => UserName
                           ?? (ClientId != null ? $"client {ClientId}" : null)
                           ?? Subject
                           ?? Unknown;

    /// <summary>The subject for the audit line (<c>-</c> when absent).</summary>
    public string SubjectOrNone => Subject ?? None;

    /// <summary>The client id for the audit line (<c>-</c> when absent).</summary>
    public string ClientIdOrNone => ClientId ?? None;

    /// <summary>The caller's tenant for the audit line (<c>-</c> when absent).</summary>
    public string TenantIdOrNone => TenantId ?? None;

    private static string? Value(ClaimsPrincipal principal, string type) => Blank(principal.FindFirst(type)?.Value);

    private static string? Blank(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}
