using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Duende.IdentityServer.AspNetIdentity;
using Meshmakers.Octo.SystematizedData.Persistence.SystemEntities;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;

namespace Meshmakers.Octo.Backend.IdentityServices.Services;

// ReSharper disable once ClassNeverInstantiated.Global
public class UserProfileService : ProfileService<OctoUser>
{
    // ReSharper disable once UnusedMember.Global
    public UserProfileService(UserManager<OctoUser> userManager, IUserClaimsPrincipalFactory<OctoUser> claimsFactory) : base(userManager,
        claimsFactory)
    {
    }

    // ReSharper disable once UnusedMember.Global
    // ReSharper disable once ContextualLoggerProblem
    public UserProfileService(UserManager<OctoUser> userManager, IUserClaimsPrincipalFactory<OctoUser> claimsFactory,
        ILogger<ProfileService<OctoUser>> logger) : base(userManager, claimsFactory, logger)
    {
    }


    /// <summary>
    /// We add custom data to the claims of the user.
    /// </summary>
    /// <param name="user"></param>
    /// <returns></returns>
    protected override async Task<ClaimsPrincipal> GetUserClaimsAsync(OctoUser user)
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
