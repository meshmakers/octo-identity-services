using System.Security.Claims;
using Duende.IdentityServer.AspNetIdentity;
using Microsoft.AspNetCore.Identity;
using Persistence.IdentityCkModel.ConstructionKit.Generated.System.Identity.v1;

namespace Meshmakers.Octo.Backend.IdentityServices.Services;

// ReSharper disable once ClassNeverInstantiated.Global
public class UserProfileService : ProfileService<RtUser>
{
    // ReSharper disable once UnusedMember.Global
    public UserProfileService(UserManager<RtUser> userManager, IUserClaimsPrincipalFactory<RtUser> claimsFactory) : base(userManager,
        claimsFactory)
    {
    }

    // ReSharper disable once UnusedMember.Global
    // ReSharper disable once ContextualLoggerProblem
    public UserProfileService(UserManager<RtUser> userManager, IUserClaimsPrincipalFactory<RtUser> claimsFactory,
        ILogger<ProfileService<RtUser>> logger) : base(userManager, claimsFactory, logger)
    {
    }


    /// <summary>
    ///     We add custom data to the claims of the user.
    /// </summary>
    /// <param name="user"></param>
    /// <returns></returns>
    protected override async Task<ClaimsPrincipal> GetUserClaimsAsync(RtUser user)
    {
        var principal = await base.GetUserClaimsAsync(user)!;
        var identity = principal.Identities.First();

        if (!string.IsNullOrEmpty(user.LastName))
        {
            identity.AddClaim(new Claim("family_name", user.LastName));
        }

        if (!string.IsNullOrEmpty(user.FirstName))
        {
            identity.AddClaim(new Claim("given_name", user.FirstName));
        }

        return principal;
    }
}