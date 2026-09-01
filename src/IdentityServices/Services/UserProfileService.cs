using System.Security.Claims;
using Duende.IdentityServer.AspNetIdentity;
using Duende.IdentityServer.Extensions;
using Duende.IdentityServer.Models;
using IdentityModel;
using IdentityServerPersistence.Services;
using Meshmakers.Octo.Services.Infrastructure;
using Microsoft.AspNetCore.Identity;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.IdentityServices.Services;

// ReSharper disable once ClassNeverInstantiated.Global
public class UserProfileService : ProfileService<RtUser>
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly IAllowedTenantsResolver _allowedTenantsResolver;

    // ReSharper disable once UnusedMember.Global
    public UserProfileService(UserManager<RtUser> userManager, IUserClaimsPrincipalFactory<RtUser> claimsFactory,
        IHttpContextAccessor httpContextAccessor, IAllowedTenantsResolver allowedTenantsResolver)
        : base(userManager, claimsFactory)
    {
        _httpContextAccessor = httpContextAccessor;
        _allowedTenantsResolver = allowedTenantsResolver;
    }

    // ReSharper disable once UnusedMember.Global
    // ReSharper disable once ContextualLoggerProblem
    public UserProfileService(UserManager<RtUser> userManager, IUserClaimsPrincipalFactory<RtUser> claimsFactory,
        IHttpContextAccessor httpContextAccessor, IAllowedTenantsResolver allowedTenantsResolver,
        ILogger<ProfileService<RtUser>> logger) : base(userManager, claimsFactory, logger)
    {
        _httpContextAccessor = httpContextAccessor;
        _allowedTenantsResolver = allowedTenantsResolver;
    }

    public override async Task GetProfileDataAsync(ProfileDataRequestContext context, CancellationToken cancellationToken = default)
    {
        await base.GetProfileDataAsync(context, cancellationToken);

        // AB#5026 delegation: MUST run right after the base call, which has just resolved the user's
        // FULL role set. See ApplyDelegationClaims for why leaving those in place would make the
        // whole delegation grant a placebo.
        ApplyDelegationClaims(context.Subject, context.IssuedClaims);

        var loginTenantId = _httpContextAccessor.HttpContext?.Items[InfrastructureCommon.TenantIdName] as string;
        if (!string.IsNullOrEmpty(loginTenantId))
        {
            // Always include tenant_id so the SPA can detect tenant mismatch and force re-auth
            context.IssuedClaims.Add(new Claim("tenant_id", loginTenantId));

            // Always include allowed_tenants — regardless of requested claim types
            var user = await FindUserAsync(context.Subject.GetSubjectId());
            if (user != null)
            {
                var allowedTenants = await _allowedTenantsResolver.ResolveAsync(loginTenantId, user);
                foreach (var tenantId in allowedTenants)
                {
                    context.IssuedClaims.Add(new Claim("allowed_tenants", tenantId));
                }
            }
        }
    }

    /// <summary>
    ///     Replaces the naturally resolved role claims with the delegation role intersection when the
    ///     token is being issued for a delegation ("on-behalf-of") grant (AB#5026). Returns
    ///     <c>true</c> when this was a delegated request.
    /// </summary>
    /// <remarks>
    ///     <para>
    ///         <b>This is the load-bearing half of the delegation grant.</b>
    ///         <c>OnBehalfOfGrantValidator</c> issues the token for the <b>user's</b> <c>sub</c>, and
    ///         Duende's <c>AddAspNetIdentity&lt;RtUser&gt;</c> + <see cref="ProfileService{TUser}" />
    ///         pipeline therefore resolves that user's <b>full</b> role set from
    ///         <c>OctoUserStore</c> and puts it into <see cref="ProfileDataRequestContext.IssuedClaims" />
    ///         — exactly as for a normal login. Without stripping those, the role intersection
    ///         computed by <c>IDelegatedIdentityResolver</c> would never reach the token and the
    ///         delegation would silently grant the user's full authority.
    ///     </para>
    ///     <para>
    ///         The intersection is carried on the grant result's subject as
    ///         <see cref="DelegationConstants.DelegatedRoleClaimType" /> claims and re-emitted here as
    ///         ordinary <c>role</c> claims, so downstream consumers need no delegation-specific code
    ///         path. The <c>act</c> claim is added unconditionally to <c>IssuedClaims</c> — the same
    ///         mechanism that gets <c>tenant_id</c> / <c>allowed_tenants</c> into tokens although
    ///         neither is listed in the <c>octoAPI</c> ApiResource's user claims, so no blueprint /
    ///         resource-claim change is needed for it.
    ///     </para>
    ///     <para>
    ///         An empty intersection removes every role claim and adds none back: the token is issued
    ///         but authorizes nothing, so role-gated consumers fail closed.
    ///     </para>
    /// </remarks>
    internal static bool ApplyDelegationClaims(ClaimsPrincipal? subject, ICollection<Claim> issuedClaims)
    {
        var actClaim = subject?.FindFirst(DelegationConstants.ActClaimType);
        if (actClaim == null)
        {
            return false;
        }

        foreach (var roleClaim in issuedClaims.Where(c => c.Type == JwtClaimTypes.Role).ToList())
        {
            issuedClaims.Remove(roleClaim);
        }

        issuedClaims.Add(new Claim(DelegationConstants.ActClaimType, actClaim.Value));

        foreach (var delegatedRole in subject!.FindAll(DelegationConstants.DelegatedRoleClaimType))
        {
            issuedClaims.Add(new Claim(JwtClaimTypes.Role, delegatedRole.Value));
        }

        return true;
    }

    /// <summary>
    ///     We add custom data to the claims of the user.
    /// </summary>
    /// <param name="user"></param>
    /// <returns></returns>
    protected override async Task<ClaimsPrincipal> GetUserClaimsAsync(RtUser user)
    {
        var principal = await base.GetUserClaimsAsync(user);
        var identity = principal.Identities.First();

        if (!string.IsNullOrEmpty(user.LastName))
        {
            identity.AddClaim(new Claim("family_name", user.LastName));
        }

        if (!string.IsNullOrEmpty(user.FirstName))
        {
            identity.AddClaim(new Claim("given_name", user.FirstName));
        }

        // Include tenant_id claim so that /connect/endsession can resolve the correct
        // tenant-scoped cookie from the id_token_hint JWT payload.
        var tenantId = _httpContextAccessor.HttpContext?.Items[InfrastructureCommon.TenantIdName] as string;
        if (!string.IsNullOrEmpty(tenantId))
        {
            identity.AddClaim(new Claim("tenant_id", tenantId));
        }

        // If the user is a cross-tenant user, include the home_tenant_id claim.
        // Cross-tenant users have usernames prefixed with "xt_" followed by the source tenant ID.
        if (user.UserName != null && user.UserName.StartsWith("xt_"))
        {
            var parts = user.UserName.Split('_', 3);
            if (parts.Length >= 3)
            {
                identity.AddClaim(new Claim("home_tenant_id", parts[1]));
            }
        }

        return principal;
    }
}
