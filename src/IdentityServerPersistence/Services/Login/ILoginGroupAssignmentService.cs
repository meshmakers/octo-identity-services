using System.Security.Claims;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.Services.Login;

/// <summary>
/// Assigns groups to a newly created user based on provider configuration and email domain rules,
/// and synchronizes external identity group claims (e.g., AD group memberships) on every login.
/// </summary>
public interface ILoginGroupAssignmentService
{
    /// <summary>
    /// Assigns groups to a newly created user based on:
    /// 1. The provider's DefaultGroupRtId (if set)
    /// 2. Email domain group rules matching the user's email
    /// </summary>
    Task AssignGroupsAsync(RtUser user, RtIdentityProvider? provider);

    /// <summary>
    /// Synchronizes external identity role claims (e.g., AD group names) with OctoMesh group memberships.
    /// Matches role claims against existing OctoMesh groups by name and adds the user as a member.
    /// Also removes the user from groups that no longer appear in the external claims.
    /// Called on every login to keep group memberships in sync with the external identity provider.
    /// </summary>
    Task SyncExternalGroupClaimsAsync(RtUser user, IReadOnlyList<Claim> externalClaims);
}
