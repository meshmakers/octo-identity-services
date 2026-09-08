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
    ///     Reads the current user's preferred outbound channel (AB#5149) — the channel the platform
    ///     uses for system-initiated messages. Null means "no preference".
    /// </summary>
    [HttpGet("preferredChannel")]
    public async Task<ActionResult<PreferredChannelResponseDto>> GetPreferredChannel(string tenantId)
    {
        var user = await GetCurrentUserAsync();
        if (user == null)
        {
            return NotFound();
        }

        return Ok(new PreferredChannelResponseDto
        {
            PreferredChannel = user.PreferredChannel,
            SupportedChannels = preferredChannelService.SupportedChannels
        });
    }

    /// <summary>
    ///     Sets (or clears, with a null <c>PreferredChannel</c>) the current user's preferred outbound
    ///     channel (AB#5149). A channel is only accepted while the user holds a valid verified binding
    ///     of the channel's identifier kind (TEAMS ⇒ EntraIdObjectId, SIGNAL ⇒ PhoneNumber); the
    ///     refusal is reported with <c>Success = false</c> and <c>Status = ChannelNotBound</c>, same
    ///     status/success shape as the enrollment endpoints. An unknown channel name is a caller
    ///     mistake and answers 400, mirroring the unknown-kind handling of <see cref="Remove" />.
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

        var result = await preferredChannelService.SetPreferredChannelAsync(user, request.PreferredChannel);
        if (result.Status == SetPreferredChannelStatus.UnknownChannel)
        {
            return BadRequest(
                $"Unknown channel '{request.PreferredChannel}'. Supported channels: " +
                $"{string.Join(", ", preferredChannelService.SupportedChannels)}.");
        }

        return Ok(new SetPreferredChannelResponseDto
        {
            Status = result.Status.ToString(),
            Success = result.Status is SetPreferredChannelStatus.Set or SetPreferredChannelStatus.Cleared,
            PreferredChannel = result.PreferredChannel
        });
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

public record PreferredChannelResponseDto
{
    /// <summary>The stored preference ("TEAMS" | "SIGNAL") or null for "no preference".</summary>
    public string? PreferredChannel { get; init; }

    /// <summary>All channel names the platform supports (whether or not the user may pick them).</summary>
    public IReadOnlyList<string> SupportedChannels { get; init; } = [];
}

public record SetPreferredChannelRequestDto
{
    /// <summary>The channel to prefer ("TEAMS" | "SIGNAL", case-insensitive) or null to clear.</summary>
    public string? PreferredChannel { get; init; }
}

public record SetPreferredChannelResponseDto
{
    public string Status { get; init; } = string.Empty;
    public bool Success { get; init; }

    /// <summary>The stored preference after the call (canonical spelling), or null.</summary>
    public string? PreferredChannel { get; init; }
}

#endregion
