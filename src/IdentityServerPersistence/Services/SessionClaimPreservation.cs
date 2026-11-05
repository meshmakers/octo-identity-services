using System.Security.Claims;
using Microsoft.AspNetCore.Identity;

namespace IdentityServerPersistence.Services;

/// <summary>
///     Keeps the claims that describe the sign-in itself when the security-stamp validator rebuilds the session
///     principal (AB#7859).
/// </summary>
/// <remarks>
///     <para>
///         <see cref="SecurityStampValidator{TUser}" /> re-creates the cookie principal from the user every
///         <see cref="SecurityStampValidatorOptions.ValidationInterval" /> (default 30 minutes) through
///         <c>CreateUserPrincipalAsync</c>, which knows the user but not how the user signed in. Without this hook the
///         session lost <c>amr=mfa</c> after the first revalidation: every token issued afterwards said <c>amr=pwd</c>,
///         and a 2FA user was refused at <c>cross-tenant-token</c>, <c>tenant-switch</c>, device approval and token
///         exchange half an hour after signing in.
///     </para>
///     <para>
///         The preserved types are the session claims <c>AuthorizeController</c> copies into tokens: <c>amr</c>,
///         <c>idp</c> and <c>sid</c>. They are taken only from the principal the validator just verified (the security
///         stamp still matches), so nothing a client sends can add them.
///     </para>
/// </remarks>
public static class SessionClaimPreservation
{
    /// <summary>The claim types that belong to the sign-in, not to the user.</summary>
    public static readonly IReadOnlyList<string> SessionClaimTypes =
        [SecondFactorEvidence.AuthenticationMethodClaimType, "idp", "sid"];

    /// <summary><see cref="SecurityStampValidatorOptions.OnRefreshingPrincipal" /> handler.</summary>
    public static Task OnRefreshingPrincipalAsync(SecurityStampRefreshingPrincipalContext context)
    {
        Preserve(context.CurrentPrincipal, context.NewPrincipal);
        return Task.CompletedTask;
    }

    /// <summary>Copies the session claims of <paramref name="current" /> onto <paramref name="refreshed" />.</summary>
    public static void Preserve(ClaimsPrincipal? current, ClaimsPrincipal? refreshed)
    {
        if (current == null || refreshed?.Identity is not ClaimsIdentity target)
        {
            return;
        }

        foreach (var type in SessionClaimTypes)
        {
            foreach (var claim in current.FindAll(type))
            {
                if (!target.HasClaim(type, claim.Value))
                {
                    target.AddClaim(new Claim(type, claim.Value, claim.ValueType));
                }
            }
        }
    }
}
