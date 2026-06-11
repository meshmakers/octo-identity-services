using System.Security.Claims;
using Duende.IdentityServer.AspNetIdentity;
using Duende.IdentityServer.Extensions;
using Duende.IdentityServer.Models;
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
