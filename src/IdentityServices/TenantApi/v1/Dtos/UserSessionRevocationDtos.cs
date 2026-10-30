namespace Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Dtos;

/// <summary>Result of revoking all sessions and tokens of one user (AB#7899).</summary>
public record UserSessionRevocationResultDto
{
    /// <summary>The user name.</summary>
    public string UserName { get; init; } = string.Empty;

    /// <summary>The subject (user id) whose tokens and sessions were revoked.</summary>
    public string Subject { get; init; } = string.Empty;

    /// <summary>The security stamp was rotated (cookie sessions elsewhere fail their next revalidation).</summary>
    public bool SecurityStampRotated { get; init; }

    /// <summary>OAuth tokens (refresh tokens, codes) revoked.</summary>
    public long RevokedTokens { get; init; }

    /// <summary>OAuth authorizations (remembered consents) revoked.</summary>
    public long RevokedAuthorizations { get; init; }

    /// <summary>Server-side browser sessions removed.</summary>
    public long RemovedSessions { get; init; }
}

/// <summary>Result of the bulk revocation for the cross-tenant shadow users (xt_*) of a tenant (AB#7899).</summary>
public record ShadowUserSessionRevocationResultDto
{
    /// <summary><c>true</c>: nothing was changed, the counts show what an apply would revoke.</summary>
    public bool DryRun { get; init; }

    /// <summary>The selection; only <c>shadowUsers</c> exists.</summary>
    public string Scope { get; init; } = string.Empty;

    /// <summary>The tenant.</summary>
    public string TenantId { get; init; } = string.Empty;

    /// <summary>Shadow users selected.</summary>
    public int Users { get; init; }

    /// <summary>Valid OAuth tokens of those users (revoked when applied).</summary>
    public long Tokens { get; init; }

    /// <summary>Valid OAuth authorizations of those users (revoked when applied).</summary>
    public long Authorizations { get; init; }

    /// <summary>Server-side browser sessions of those users (removed when applied).</summary>
    public long Sessions { get; init; }

    /// <summary>The first <see cref="MaxListedUserNames" /> user names, for review before applying.</summary>
    public IReadOnlyList<string> UserNames { get; init; } = [];

    /// <summary>Upper bound of <see cref="UserNames" />.</summary>
    public const int MaxListedUserNames = 100;
}
