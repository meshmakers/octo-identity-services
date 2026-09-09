using IdentityServerPersistence.Services.SelfService;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Backend.Authentication;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;
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
// Accepts BOTH auth schemes (AB#5135). The identity ClientApp calls this SAME-ORIGIN with the
// session cookie (IdentityConstants.ApplicationScheme = "Identity.Application" — the default scheme
// AddIdentity registers, which the sibling ManageApiController's bare [Authorize] relies on), while
// the cross-origin meshmakers-app calls it with a JWT bearer. Listing both lets either principal
// authenticate. No admin scope policy: any authenticated user manages their OWN identifiers; the
// actions scope every read/write to the current user resolved by GetCurrentUserAsync (sub for the
// bearer principal, NameIdentifier for the cookie principal).
[Authorize(AuthenticationSchemes = CookieAndBearerSchemes)]
public class MyIdentifiersApiController(
    UserManager<RtUser> userManager,
    ISystemContext systemContext,
    ISelfServiceIdentifierService selfServiceIdentifierService,
    IPreferredChannelService preferredChannelService) : ControllerBase
{
    // The cookie scheme is IdentityConstants.ApplicationScheme ("Identity.Application"), the default
    // scheme AddIdentity registers and the sibling ManageApiController's bare [Authorize] relies on.
    // Its literal is inlined here because IdentityConstants.ApplicationScheme is a static readonly
    // field (not a const) and so cannot be used in an attribute argument; the bearer half IS a const.
    private const string CookieAndBearerSchemes =
        "Identity.Application," + AuthenticationConstants.BearerAuthenticationScheme;

    /// <summary>
    ///     Resolves the calling user from the bearer principal. The JWT pipeline runs with
    ///     <c>MapInboundClaims = false</c>, so the subject stays under the raw <c>sub</c> claim and is
    ///     never remapped to <see cref="ClaimTypes.NameIdentifier" /> — the only claim
    ///     <see cref="UserManager{TUser}.GetUserAsync" /> looks at. (That is why the cookie-authenticated
    ///     <see cref="ManageApiController" /> can use <c>GetUserAsync</c> but a bearer caller cannot.)
    ///     Probe <c>sub</c> first, fall back to <c>NameIdentifier</c> for a cookie principal — the same
    ///     "probe both claim spellings" rule the role check uses.
    /// </summary>
    private async Task<RtUser?> GetCurrentUserAsync()
    {
        var subjectId = User.FindFirstValue("sub") ?? User.FindFirstValue(ClaimTypes.NameIdentifier);
        return subjectId is null ? null : await userManager.FindByIdAsync(subjectId);
    }

    /// <summary>Lists the current user's own verified identifiers (certificate validity folded in).</summary>
    [HttpGet]
    public async Task<ActionResult<IEnumerable<VerifiedIdentifierDto>>> List(string tenantId)
    {
        if (await systemContext.TryFindTenantContextAsync(tenantId) == null)
        {
            return NotFound($"Tenant '{tenantId}' not found.");
        }

        var user = await GetCurrentUserAsync();
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
        var user = await GetCurrentUserAsync();
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
        var user = await GetCurrentUserAsync();
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

    /// <summary>Adds an e-mail address and sends a one-time code to it (nothing is enrolled yet).</summary>
    [HttpPost("email/start")]
    public async Task<ActionResult<StartEmailEnrollmentResponseDto>> StartEmailEnrollment(string tenantId,
        [FromBody] StartEmailEnrollmentRequestDto request, CancellationToken cancellationToken)
    {
        var user = await GetCurrentUserAsync();
        if (user == null)
        {
            return NotFound();
        }

        var result = await selfServiceIdentifierService.StartEmailEnrollmentAsync(tenantId, user,
            request.Email ?? string.Empty, cancellationToken);

        return Ok(new StartEmailEnrollmentResponseDto
        {
            Status = result.Status.ToString(),
            Success = result.Status == StartEmailEnrollmentStatus.CodeSent,
            NormalizedEmail = result.NormalizedEmail,
            MaskedDestination = result.MaskedDestination,
            ExpiresAtUtc = result.ExpiresAtUtc
        });
    }

    /// <summary>Verifies the one-time code and, on success, enrolls the e-mail address as Strong.</summary>
    [HttpPost("email/verify")]
    public async Task<ActionResult<VerifyEmailResponseDto>> VerifyEmail(string tenantId,
        [FromBody] VerifyEmailRequestDto request)
    {
        var user = await GetCurrentUserAsync();
        if (user == null)
        {
            return NotFound();
        }

        var result = await selfServiceIdentifierService.VerifyEmailAsync(tenantId, user,
            request.Email ?? string.Empty, request.Code ?? string.Empty);

        return Ok(new VerifyEmailResponseDto
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
        var user = await GetCurrentUserAsync();
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
        var user = await GetCurrentUserAsync();
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

    /// <summary>
    ///     Reads the current user's preferred outbound channel selection (AB#5149, binding-specific):
    ///     the chosen binding (with its derived channel kind and display value; all null while no
    ///     usable preference is set) plus every binding the user may choose right now. The channel
    ///     kind is DERIVED from the referenced binding (PhoneNumber ⇒ SIGNAL, EntraIdObjectId ⇒
    ///     TEAMS), never stored separately.
    /// </summary>
    [HttpGet("preferredChannel")]
    public async Task<ActionResult<PreferredChannelResponseDto>> GetPreferredChannel(string tenantId)
    {
        var user = await GetCurrentUserAsync();
        if (user == null)
        {
            return NotFound();
        }

        var selection = await preferredChannelService.GetSelectionAsync(user);
        var options = await preferredChannelService.GetOptionsAsync(user);
        return Ok(new PreferredChannelResponseDto
        {
            BindingId = selection.BindingId?.ToString(),
            Channel = selection.Channel,
            IdentifierValue = selection.IdentifierValue,
            Options = options.Select(ToOptionDto).ToList()
        });
    }

    /// <summary>
    ///     Sets (or clears, with a null <c>BindingId</c>) the current user's preferred outbound
    ///     channel binding (AB#5149). The binding must be one of the caller's own valid bindings of a
    ///     channel-mapped kind; anything else — malformed id, foreign binding, expired binding,
    ///     unmapped kind — is refused with <c>Success = false</c> and
    ///     <c>Status = BindingNotEligible</c>, same status/success shape as the enrollment endpoints
    ///     (and deliberately without distinguishing "not yours" from "does not exist").
    /// </summary>
    [HttpPut("preferredChannel")]
    public async Task<ActionResult<SetPreferredChannelResponseDto>> SetPreferredChannel(string tenantId,
        [FromBody] SetPreferredChannelRequestDto request)
    {
        var user = await GetCurrentUserAsync();
        if (user == null)
        {
            return NotFound();
        }

        var result = await preferredChannelService.SetPreferredChannelAsync(user, request.BindingId);
        return Ok(new SetPreferredChannelResponseDto
        {
            Status = result.Status.ToString(),
            Success = result.Status is SetPreferredChannelStatus.Set or SetPreferredChannelStatus.Cleared,
            BindingId = result.Selection.BindingId?.ToString(),
            Channel = result.Selection.Channel,
            IdentifierValue = result.Selection.IdentifierValue
        });
    }

    private static PreferredChannelOptionDto ToOptionDto(PreferredChannelOption option) => new()
    {
        BindingId = option.BindingId.ToString(),
        Channel = option.Channel,
        IdentifierValue = option.IdentifierValue
    };

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

public record StartEmailEnrollmentRequestDto
{
    public string? Email { get; init; }
}

public record StartEmailEnrollmentResponseDto
{
    public string Status { get; init; } = string.Empty;
    public bool Success { get; init; }
    public string? NormalizedEmail { get; init; }
    public string? MaskedDestination { get; init; }
    public DateTime? ExpiresAtUtc { get; init; }
}

public record VerifyEmailRequestDto
{
    public string? Email { get; init; }
    public string? Code { get; init; }
}

public record VerifyEmailResponseDto
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

/// <summary>One selectable preferred-channel target: a valid binding with its derived channel kind.</summary>
public record PreferredChannelOptionDto
{
    /// <summary>The rtId of the VerifiedExternalIdentifier.</summary>
    public string BindingId { get; init; } = string.Empty;

    /// <summary>The channel derived from the binding's kind ("TEAMS" | "SIGNAL").</summary>
    public string Channel { get; init; } = string.Empty;

    /// <summary>The binding's identifier value, for display.</summary>
    public string IdentifierValue { get; init; } = string.Empty;
}

public record PreferredChannelResponseDto
{
    /// <summary>The rtId of the chosen binding, or null for "no preference" (incl. dangling references).</summary>
    public string? BindingId { get; init; }

    /// <summary>The channel derived from the chosen binding's kind ("TEAMS" | "SIGNAL"), or null.</summary>
    public string? Channel { get; init; }

    /// <summary>The chosen binding's identifier value, for display, or null.</summary>
    public string? IdentifierValue { get; init; }

    /// <summary>Every binding the user may choose right now.</summary>
    public IReadOnlyList<PreferredChannelOptionDto> Options { get; init; } = [];
}

public record SetPreferredChannelRequestDto
{
    /// <summary>The rtId of one of the caller's own valid bindings, or null to clear the preference.</summary>
    public string? BindingId { get; init; }
}

public record SetPreferredChannelResponseDto
{
    public string Status { get; init; } = string.Empty;
    public bool Success { get; init; }

    /// <summary>The effective selection after the call (null members while unset).</summary>
    public string? BindingId { get; init; }

    public string? Channel { get; init; }
    public string? IdentifierValue { get; init; }
}

#endregion
