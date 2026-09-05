using IdentityServerPersistence.Services.SelfService;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Backend.Authentication;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.IdentityServices.Controllers.Api;

/// <summary>
///     Self-service "My identities" API for the Angular SPA (AB#5123, "Strang B" of Epic AB#4979):
///     the signed-in user manages their OWN strong channel identifiers — phone numbers (OTP-verified)
///     and client certificates — with no admin in the loop. Every write goes through the AB#5122
///     verified-identifier directory with <c>Source = SelfService</c> and maps ONLY to the current
///     user's identity (an identifier owned by someone else is refused, never re-pointed). Same shape
///     and conventions as <see cref="ManageApiController" /> (route base, <c>[Authorize]</c>, current
///     user via <see cref="UserManager{TUser}" />).
/// </summary>
[ApiController]
[Route("{tenantId}/api/manage/identifiers")]
// Self-service: called cross-origin by the app with a JWT bearer, so it must use the bearer scheme
// (the sibling ManageApiController's bare [Authorize] resolves the identity ClientApp cookie, which
// a bearer-only caller never carries → 401). No admin scope policy: any authenticated user manages
// their OWN identifiers; the actions scope every read/write to userManager.GetUserAsync(User).
[Authorize(AuthenticationSchemes = AuthenticationConstants.BearerAuthenticationScheme)]
public class MyIdentifiersApiController(
    UserManager<RtUser> userManager,
    ISystemContext systemContext,
    ISelfServiceIdentifierService selfServiceIdentifierService) : ControllerBase
{
    /// <summary>Lists the current user's own verified identifiers (certificate validity folded in).</summary>
    [HttpGet]
    public async Task<ActionResult<IEnumerable<VerifiedIdentifierDto>>> List(string tenantId)
    {
        if (await systemContext.TryFindTenantContextAsync(tenantId) == null)
        {
            return NotFound($"Tenant '{tenantId}' not found.");
        }

        var user = await userManager.GetUserAsync(User);
        if (user == null)
        {
            return NotFound();
        }

        var identifiers = await selfServiceIdentifierService.ListAsync(user);
        return Ok(identifiers.Select(ToDto).ToList());
    }

    /// <summary>Adds a phone number and sends a one-time code to it (nothing is enrolled yet).</summary>
    [HttpPost("phone/start")]
    public async Task<ActionResult<StartPhoneEnrollmentResponseDto>> StartPhoneEnrollment(string tenantId,
        [FromBody] StartPhoneEnrollmentRequestDto request, CancellationToken cancellationToken)
    {
        var user = await userManager.GetUserAsync(User);
        if (user == null)
        {
            return NotFound();
        }

        var result = await selfServiceIdentifierService.StartPhoneEnrollmentAsync(tenantId, user,
            request.PhoneNumber ?? string.Empty, cancellationToken);

        return Ok(new StartPhoneEnrollmentResponseDto
        {
            Status = result.Status.ToString(),
            Success = result.Status == StartPhoneEnrollmentStatus.CodeSent,
            NormalizedNumber = result.NormalizedNumber,
            MaskedDestination = result.MaskedDestination,
            ExpiresAtUtc = result.ExpiresAtUtc
        });
    }

    /// <summary>Verifies the one-time code and, on success, enrolls the phone number as Strong.</summary>
    [HttpPost("phone/verify")]
    public async Task<ActionResult<VerifyPhoneResponseDto>> VerifyPhone(string tenantId,
        [FromBody] VerifyPhoneRequestDto request)
    {
        var user = await userManager.GetUserAsync(User);
        if (user == null)
        {
            return NotFound();
        }

        var result = await selfServiceIdentifierService.VerifyPhoneAsync(tenantId, user,
            request.PhoneNumber ?? string.Empty, request.Code ?? string.Empty);

        return Ok(new VerifyPhoneResponseDto
        {
            Status = result.Status.ToString(),
            Success = result.Status == OtpVerificationStatus.Verified,
            AttemptsRemaining = result.AttemptsRemaining
        });
    }

    /// <summary>Enrolls a client certificate as a Strong identifier (fingerprint + validity stored).</summary>
    [HttpPost("certificate")]
    public async Task<ActionResult<EnrollCertificateResponseDto>> EnrollCertificate(string tenantId,
        [FromBody] EnrollCertificateRequestDto request)
    {
        var user = await userManager.GetUserAsync(User);
        if (user == null)
        {
            return NotFound();
        }

        byte[] certificateBytes;
        try
        {
            certificateBytes = Convert.FromBase64String(request.CertificateBase64 ?? string.Empty);
        }
        catch (FormatException)
        {
            return Ok(new EnrollCertificateResponseDto
            {
                Status = CertificateEnrollmentStatus.Unreadable.ToString(),
                Success = false
            });
        }

        var result = await selfServiceIdentifierService.EnrollCertificateAsync(tenantId, user, certificateBytes);

        return Ok(new EnrollCertificateResponseDto
        {
            Status = result.Status.ToString(),
            Success = result.Status == CertificateEnrollmentStatus.Enrolled,
            Fingerprint = result.Fingerprint,
            ValidUntilUtc = result.ValidUntilUtc
        });
    }

    /// <summary>Removes one of the current user's own verified identifiers.</summary>
    [HttpPost("remove")]
    public async Task<ActionResult<RemoveIdentifierResponseDto>> Remove(string tenantId,
        [FromBody] RemoveIdentifierRequestDto request)
    {
        var user = await userManager.GetUserAsync(User);
        if (user == null)
        {
            return NotFound();
        }

        if (!Enum.TryParse<RtIdentifierKindEnum>(request.IdentifierKind, out var kind))
        {
            return BadRequest($"Unknown identifier kind '{request.IdentifierKind}'.");
        }

        var removed = await selfServiceIdentifierService.RemoveAsync(user, kind, request.IdentifierValue ?? string.Empty);
        return Ok(new RemoveIdentifierResponseDto { Success = removed });
    }

    private static VerifiedIdentifierDto ToDto(VerifiedIdentifierSummary summary) => new()
    {
        RtId = summary.RtId.ToString(),
        IdentifierKind = summary.IdentifierKind.ToString(),
        IdentifierValue = summary.IdentifierValue,
        EnrollmentTrust = summary.EnrollmentTrust.ToString(),
        Source = summary.Source.ToString(),
        EnrolledAt = summary.EnrolledAt,
        LastVerifiedAt = summary.LastVerifiedAt,
        ValidUntil = summary.ValidUntil,
        IsValid = summary.IsValid
    };
}

#region DTOs

public record VerifiedIdentifierDto
{
    public string RtId { get; init; } = string.Empty;
    public string IdentifierKind { get; init; } = string.Empty;
    public string IdentifierValue { get; init; } = string.Empty;
    public string EnrollmentTrust { get; init; } = string.Empty;
    public string Source { get; init; } = string.Empty;
    public DateTime? EnrolledAt { get; init; }
    public DateTime? LastVerifiedAt { get; init; }
    public DateTime? ValidUntil { get; init; }
    public bool IsValid { get; init; }
}

public record StartPhoneEnrollmentRequestDto
{
    public string? PhoneNumber { get; init; }
}

public record StartPhoneEnrollmentResponseDto
{
    public string Status { get; init; } = string.Empty;
    public bool Success { get; init; }
    public string? NormalizedNumber { get; init; }
    public string? MaskedDestination { get; init; }
    public DateTime? ExpiresAtUtc { get; init; }
}

public record VerifyPhoneRequestDto
{
    public string? PhoneNumber { get; init; }
    public string? Code { get; init; }
}

public record VerifyPhoneResponseDto
{
    public string Status { get; init; } = string.Empty;
    public bool Success { get; init; }
    public int AttemptsRemaining { get; init; }
}

public record EnrollCertificateRequestDto
{
    /// <summary>The certificate, base64-encoded (DER bytes or the UTF-8 bytes of a PEM document).</summary>
    public string? CertificateBase64 { get; init; }
}

public record EnrollCertificateResponseDto
{
    public string Status { get; init; } = string.Empty;
    public bool Success { get; init; }
    public string? Fingerprint { get; init; }
    public DateTime? ValidUntilUtc { get; init; }
}

public record RemoveIdentifierRequestDto
{
    public string? IdentifierKind { get; init; }
    public string? IdentifierValue { get; init; }
}

public record RemoveIdentifierResponseDto
{
    public bool Success { get; init; }
}

#endregion
