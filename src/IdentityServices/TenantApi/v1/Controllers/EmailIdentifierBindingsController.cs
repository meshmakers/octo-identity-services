using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using Asp.Versioning;
using IdentityServerPersistence;
using IdentityServerPersistence.Services.Admin;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Backend.Authentication;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;

/// <summary>
///     REST controller for the tenant's admin-managed e-mail verified whitelist (AB#5125, "Strang B"
///     of Epic AB#4979): a tenant admin binds an e-mail address to an OctoMesh user so an inbound mail
///     from that address is attributed to the user by the mesh adapter's verified-caller directory.
///     Every binding is written through the AB#5122 directory with <c>Source = Admin</c> and
///     <c>EnrollmentTrust = Strong</c>.
/// </summary>
/// <remarks>
///     🔴 <b>DKIM/DMARC requirement.</b> A whitelisted address proves the address BELONGS to the user,
///     but not that a given message really came from it — the SMTP <c>From</c> is spoofable. The mesh
///     adapter evaluates each inbound mail's <c>Authentication-Results</c> (DKIM/DMARC) verdict and the
///     verified-caller directory takes <c>effective = min(enrollment, message)</c>, so a message
///     without a valid, aligned DKIM/DMARC pass resolves only Weak and can never authorize an elevated
///     operation — even from a whitelisted address.
///     <para>
///         Same shape and gating as <see cref="ExternalTenantUserMappingsController" />: bearer
///         authentication, read on <see cref="IdentityServiceConstants.IdentityApiReadOnlyPolicy" />
///         and write on <see cref="IdentityServiceConstants.IdentityApiReadWritePolicy" />.
///     </para>
/// </remarks>
[Authorize(AuthenticationSchemes = AuthenticationConstants.BearerAuthenticationScheme)]
[Route(IdentityServiceConstants.ApiPathPrefix + "/[controller]")]
[ApiController]
[ApiVersion(IdentityServiceConstants.ApiVersion1)]
public class EmailIdentifierBindingsController(
    IAdminEmailBindingService adminEmailBindingService) : ControllerBase
{
    /// <summary>Lists every e-mail→user binding in the tenant.</summary>
    [HttpGet]
    [Authorize(IdentityServiceConstants.IdentityApiReadOnlyPolicy)]
    [EndpointSummary("Returns all e-mail→user verified-identifier bindings for the tenant.")]
    [ProducesResponseType(typeof(IEnumerable<EmailIdentifierBindingDto>), StatusCodes.Status200OK)]
    public async Task<ActionResult<IEnumerable<EmailIdentifierBindingDto>>> GetAll()
    {
        var bindings = await adminEmailBindingService.ListAsync();
        return Ok(bindings.Select(MapToDto).ToList());
    }

    /// <summary>Binds (upserts) an e-mail address to a user as a Strong, admin-sourced identifier.</summary>
    [HttpPost]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Binds an e-mail address to a user (admin verified whitelist, enrollment Strong).")]
    [ProducesResponseType(typeof(EmailIdentifierBindingResultDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult<EmailIdentifierBindingResultDto>> Create(
        [Required][FromBody][Description("The e-mail→user binding to create")] CreateEmailIdentifierBindingDto dto)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var result = await adminEmailBindingService.BindEmailAsync(dto.UserId, dto.Email ?? string.Empty);

        return result.Status switch
        {
            AdminBindEmailStatus.InvalidEmail => BadRequest($"'{dto.Email}' is not a valid e-mail address."),
            AdminBindEmailStatus.UserNotFound => NotFound($"User '{dto.UserId}' does not exist."),
            _ => Ok(new EmailIdentifierBindingResultDto
            {
                RtId = result.BindingRtId?.ToString(),
                Email = result.NormalizedEmail ?? string.Empty,
                UserId = dto.UserId.ToString()
            })
        };
    }

    /// <summary>Removes the e-mail binding for the given address. Idempotent.</summary>
    [HttpDelete]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Removes the e-mail→user binding for the given address.")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> Delete(
        [Required][FromQuery][Description("The e-mail address whose binding to remove")] string email)
    {
        var removed = await adminEmailBindingService.RemoveAsync(email);
        return removed ? Ok() : NotFound();
    }

    private static EmailIdentifierBindingDto MapToDto(VerifiedIdentifierWithUser binding) => new()
    {
        RtId = binding.Identifier.RtId.ToString(),
        Email = binding.Identifier.IdentifierValue,
        UserId = binding.UserRtId == OctoObjectId.Empty ? null : binding.UserRtId.ToString(),
        UserName = binding.UserName,
        UserEmail = binding.UserEmail,
        EnrollmentTrust = binding.Identifier.EnrollmentTrust.ToString(),
        Source = binding.Identifier.Source.ToString(),
        EnrolledAt = binding.Identifier.EnrolledAt,
        LastVerifiedAt = binding.Identifier.LastVerifiedAt,
        IsValid = binding.Identifier.IsValid
    };
}

#region DTOs

/// <summary>An e-mail→user binding as the admin whitelist UI shows it (AB#5125).</summary>
public record EmailIdentifierBindingDto
{
    /// <summary>RtId of the underlying <c>VerifiedExternalIdentifier</c>.</summary>
    public string RtId { get; init; } = string.Empty;

    /// <summary>The bound e-mail address (normalized, lower-case).</summary>
    public string Email { get; init; } = string.Empty;

    /// <summary>RtId of the user the address maps to; null when the binding is dangling.</summary>
    public string? UserId { get; init; }

    /// <summary>The bound user's user name, for display.</summary>
    public string? UserName { get; init; }

    /// <summary>The bound user's e-mail, for display.</summary>
    public string? UserEmail { get; init; }

    /// <summary>The stored enrollment-trust dimension ("Strong" for an admin whitelist entry).</summary>
    public string EnrollmentTrust { get; init; } = string.Empty;

    /// <summary>Provenance of the binding ("Admin" / "SelfService").</summary>
    public string Source { get; init; } = string.Empty;

    public DateTime? EnrolledAt { get; init; }
    public DateTime? LastVerifiedAt { get; init; }

    /// <summary>Whether the binding is currently valid (expiry folded in).</summary>
    public bool IsValid { get; init; }
}

/// <summary>Request to bind an e-mail address to a user (AB#5125).</summary>
public record CreateEmailIdentifierBindingDto
{
    /// <summary>The OctoMesh user the address maps to.</summary>
    [Required]
    public OctoObjectId UserId { get; init; }

    /// <summary>The e-mail address to bind. Validated and normalized (trimmed, lower-cased) server-side.</summary>
    [Required]
    public string? Email { get; init; }
}

/// <summary>Result of creating an e-mail binding (AB#5125).</summary>
public record EmailIdentifierBindingResultDto
{
    public string? RtId { get; init; }
    public string Email { get; init; } = string.Empty;
    public string UserId { get; init; } = string.Empty;
}

#endregion
