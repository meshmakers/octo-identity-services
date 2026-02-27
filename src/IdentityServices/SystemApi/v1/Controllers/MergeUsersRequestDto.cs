using System.ComponentModel.DataAnnotations;

namespace Meshmakers.Octo.Backend.IdentityServices.SystemApi.v1.Controllers;

/// <summary>
///     Request DTO for merging two users. External logins from the source user
///     are transferred to the target user, then the source user is deleted.
/// </summary>
public record MergeUsersRequestDto
{
    /// <summary>
    ///     The username of the source user whose external logins will be transferred.
    ///     This user will be deleted after the merge.
    /// </summary>
    [Required]
    public string SourceUserName { get; init; } = string.Empty;
}
