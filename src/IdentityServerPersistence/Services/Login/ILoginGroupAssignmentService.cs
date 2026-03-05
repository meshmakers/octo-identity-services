using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.Services.Login;

/// <summary>
/// Assigns groups to a newly created user based on provider configuration and email domain rules.
/// </summary>
public interface ILoginGroupAssignmentService
{
    /// <summary>
    /// Assigns groups to a newly created user based on:
    /// 1. The provider's DefaultGroupRtId (if set)
    /// 2. Email domain group rules matching the user's email
    /// </summary>
    /// <param name="user">The newly created user</param>
    /// <param name="provider">The identity provider used for login (may be null)</param>
    Task AssignGroupsAsync(RtUser user, RtIdentityProvider? provider);
}
