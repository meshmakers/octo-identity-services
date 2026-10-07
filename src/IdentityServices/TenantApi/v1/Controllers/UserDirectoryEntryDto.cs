namespace Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;

/// <summary>
/// One entry of the slim user directory (<c>GET {tenant}/v1/users/directory</c>, AB#5859): just enough
/// to pick a colleague (e.g. an assignee) — deliberately no e-mail, roles, groups or logins, because
/// every signed-in user of the tenant may read it.
/// </summary>
public sealed class UserDirectoryEntryDto
{
    /// <summary>The user's id (RtId) — the same value as <c>UserDto.UserId</c> and the token's <c>sub</c>.</summary>
    public required string UserId { get; init; }

    /// <summary>"FirstName LastName" when either is set, otherwise the user name.</summary>
    public required string DisplayName { get; init; }
}
