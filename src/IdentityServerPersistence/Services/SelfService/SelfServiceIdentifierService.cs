using System.Net.Mail;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using IdentityServerPersistence.SystemStores;
using Microsoft.Extensions.Logging;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.Services.SelfService;

/// <inheritdoc />
public sealed class SelfServiceIdentifierService(
    IVerifiedIdentifierResolver verifiedIdentifierResolver,
    IOtpChallengeStore challengeStore,
    IEnumerable<IOtpDeliveryChannel> deliveryChannels,
    TimeProvider timeProvider,
    ILogger<SelfServiceIdentifierService> logger) : ISelfServiceIdentifierService
{
    private const int CodeLength = 6;
    private const int MaxAttempts = 5;
    private static readonly TimeSpan CodeTtl = TimeSpan.FromMinutes(5);

    // A phone OTP is delivered over Signal for this WI (AB#5123). The modality is fixed here rather
    // than guessed so a mis-registered channel fails loudly instead of silently not delivering.
    private const OtpDeliveryChannelKind PhoneOtpChannel = OtpDeliveryChannelKind.Signal;

    // An e-mail OTP is delivered over the e-mail channel (AB#5135), same fail-loud contract.
    private const OtpDeliveryChannelKind EmailOtpChannel = OtpDeliveryChannelKind.Email;

    public async Task<IReadOnlyList<VerifiedIdentifierSummary>> ListAsync(RtUser user)
        => await verifiedIdentifierResolver.GetByUserAsync(user.RtId);

    public async Task<StartPhoneEnrollmentResult> StartPhoneEnrollmentAsync(string tenantId, RtUser user,
        string rawPhoneNumber, CancellationToken cancellationToken = default)
    {
        if (!TryNormalizePhoneNumber(rawPhoneNumber, out var normalized))
        {
            return new StartPhoneEnrollmentResult(StartPhoneEnrollmentStatus.InvalidNumber);
        }

        if (await IsOwnedByAnotherUserAsync(RtIdentifierKindEnum.PhoneNumber, normalized, user))
        {
            logger.LogWarning(
                "[{TenantId}] Self-service phone enrollment refused: number is already a verified identifier of another user",
                tenantId);
            return new StartPhoneEnrollmentResult(StartPhoneEnrollmentStatus.AlreadyOwnedByAnotherUser);
        }

        var code = GenerateNumericCode();
        var salt = RandomNumberGenerator.GetBytes(16);
        var now = timeProvider.GetUtcNow().UtcDateTime;
        var expiresAt = now + CodeTtl;

        var challenge = new OtpChallenge(
            normalized,
            Convert.ToBase64String(HashCode(salt, code)),
            Convert.ToBase64String(salt),
            expiresAt,
            0,
            MaxAttempts);

        // Store the (hashed) challenge BEFORE delivery so a delivered code is always verifiable, and
        // deliver only after: if delivery throws, the user is told it failed rather than "code sent".
        await challengeStore.StoreAsync(user, challenge);
        await DeliverAsync(PhoneOtpChannel,
            new OtpDeliveryContext(tenantId, normalized, code, CodeTtl, user.UserName),
            cancellationToken);

        logger.LogInformation(
            "[{TenantId}] Self-service phone enrollment started for a user's number (masked {Masked}); code expires {ExpiresAt:o}",
            tenantId, Mask(normalized), expiresAt);

        return new StartPhoneEnrollmentResult(StartPhoneEnrollmentStatus.CodeSent, normalized, Mask(normalized),
            expiresAt);
    }

    public async Task<OtpVerificationResult> VerifyPhoneAsync(string tenantId, RtUser user,
        string rawPhoneNumber, string code)
    {
        if (!TryNormalizePhoneNumber(rawPhoneNumber, out var normalized))
        {
            return new OtpVerificationResult(OtpVerificationStatus.InvalidNumber);
        }

        var challenge = await challengeStore.GetAsync(user, normalized);
        if (challenge == null)
        {
            return new OtpVerificationResult(OtpVerificationStatus.NoChallenge);
        }

        var now = timeProvider.GetUtcNow().UtcDateTime;
        if (challenge.ExpiresAtUtc <= now)
        {
            // Expired: burn it so a later guess cannot use it, and never enroll.
            await challengeStore.RemoveAsync(user, normalized);
            return new OtpVerificationResult(OtpVerificationStatus.Expired);
        }

        if (challenge.Attempts >= challenge.MaxAttempts)
        {
            await challengeStore.RemoveAsync(user, normalized);
            return new OtpVerificationResult(OtpVerificationStatus.AttemptLimitReached);
        }

        if (!CodeMatches(challenge, code))
        {
            // Consume one attempt. When the budget is now exhausted, burn the challenge so a further
            // guess must restart the whole flow.
            var consumed = challenge with { Attempts = challenge.Attempts + 1 };
            var remaining = consumed.MaxAttempts - consumed.Attempts;
            if (remaining <= 0)
            {
                await challengeStore.RemoveAsync(user, normalized);
            }
            else
            {
                await challengeStore.StoreAsync(user, consumed);
            }

            return new OtpVerificationResult(OtpVerificationStatus.CodeMismatch, Math.Max(remaining, 0));
        }

        // Correct code. Re-check ownership at the last moment (it may have been enrolled elsewhere
        // since the code was sent) so a self-service identifier only ever maps to its own user.
        if (await IsOwnedByAnotherUserAsync(RtIdentifierKindEnum.PhoneNumber, normalized, user))
        {
            await challengeStore.RemoveAsync(user, normalized);
            return new OtpVerificationResult(OtpVerificationStatus.AlreadyOwnedByAnotherUser);
        }

        var bindingRtId = await verifiedIdentifierResolver.StoreBindingAsync(new VerifiedIdentifierBinding(
            RtIdentifierKindEnum.PhoneNumber,
            normalized,
            user.RtId,
            RtTrustLevelEnum.Strong,
            RtIdentifierSourceEnum.SelfService,
            RequiredMessageAuthentication: true,
            LastVerifiedAt: now));

        await challengeStore.RemoveAsync(user, normalized);

        logger.LogInformation(
            "[{TenantId}] Self-service phone identifier verified and enrolled Strong (binding {BindingRtId})",
            tenantId, bindingRtId);

        return new OtpVerificationResult(OtpVerificationStatus.Verified, 0, bindingRtId);
    }

    public async Task<StartEmailEnrollmentResult> StartEmailEnrollmentAsync(string tenantId, RtUser user,
        string rawEmail, CancellationToken cancellationToken = default)
    {
        if (!TryNormalizeEmail(rawEmail, out var normalized))
        {
            return new StartEmailEnrollmentResult(StartEmailEnrollmentStatus.InvalidEmail);
        }

        if (await IsOwnedByAnotherUserAsync(RtIdentifierKindEnum.EmailAddress, normalized, user))
        {
            logger.LogWarning(
                "[{TenantId}] Self-service e-mail enrollment refused: address is already a verified identifier of another user",
                tenantId);
            return new StartEmailEnrollmentResult(StartEmailEnrollmentStatus.AlreadyOwnedByAnotherUser);
        }

        var code = GenerateNumericCode();
        var salt = RandomNumberGenerator.GetBytes(16);
        var now = timeProvider.GetUtcNow().UtcDateTime;
        var expiresAt = now + CodeTtl;

        var challenge = new OtpChallenge(
            normalized,
            Convert.ToBase64String(HashCode(salt, code)),
            Convert.ToBase64String(salt),
            expiresAt,
            0,
            MaxAttempts);

        // Store the (hashed) challenge BEFORE delivery so a delivered code is always verifiable, and
        // deliver only after: if delivery throws, the user is told it failed rather than "code sent".
        await challengeStore.StoreAsync(user, challenge);
        await DeliverAsync(EmailOtpChannel,
            new OtpDeliveryContext(tenantId, normalized, code, CodeTtl, user.UserName),
            cancellationToken);

        logger.LogInformation(
            "[{TenantId}] Self-service e-mail enrollment started for a user's address (masked {Masked}); code expires {ExpiresAt:o}",
            tenantId, MaskEmail(normalized), expiresAt);

        return new StartEmailEnrollmentResult(StartEmailEnrollmentStatus.CodeSent, normalized, MaskEmail(normalized),
            expiresAt);
    }

    public async Task<OtpVerificationResult> VerifyEmailAsync(string tenantId, RtUser user,
        string rawEmail, string code)
    {
        if (!TryNormalizeEmail(rawEmail, out var normalized))
        {
            return new OtpVerificationResult(OtpVerificationStatus.InvalidEmail);
        }

        var challenge = await challengeStore.GetAsync(user, normalized);
        if (challenge == null)
        {
            return new OtpVerificationResult(OtpVerificationStatus.NoChallenge);
        }

        var now = timeProvider.GetUtcNow().UtcDateTime;
        if (challenge.ExpiresAtUtc <= now)
        {
            // Expired: burn it so a later guess cannot use it, and never enroll.
            await challengeStore.RemoveAsync(user, normalized);
            return new OtpVerificationResult(OtpVerificationStatus.Expired);
        }

        if (challenge.Attempts >= challenge.MaxAttempts)
        {
            await challengeStore.RemoveAsync(user, normalized);
            return new OtpVerificationResult(OtpVerificationStatus.AttemptLimitReached);
        }

        if (!CodeMatches(challenge, code))
        {
            // Consume one attempt. When the budget is now exhausted, burn the challenge so a further
            // guess must restart the whole flow.
            var consumed = challenge with { Attempts = challenge.Attempts + 1 };
            var remaining = consumed.MaxAttempts - consumed.Attempts;
            if (remaining <= 0)
            {
                await challengeStore.RemoveAsync(user, normalized);
            }
            else
            {
                await challengeStore.StoreAsync(user, consumed);
            }

            return new OtpVerificationResult(OtpVerificationStatus.CodeMismatch, Math.Max(remaining, 0));
        }

        // Correct code. Re-check ownership at the last moment (it may have been enrolled elsewhere
        // since the code was sent) so a self-service identifier only ever maps to its own user.
        if (await IsOwnedByAnotherUserAsync(RtIdentifierKindEnum.EmailAddress, normalized, user))
        {
            await challengeStore.RemoveAsync(user, normalized);
            return new OtpVerificationResult(OtpVerificationStatus.AlreadyOwnedByAnotherUser);
        }

        var bindingRtId = await verifiedIdentifierResolver.StoreBindingAsync(new VerifiedIdentifierBinding(
            RtIdentifierKindEnum.EmailAddress,
            normalized,
            user.RtId,
            RtTrustLevelEnum.Strong,
            RtIdentifierSourceEnum.SelfService,
            // Mirrors the admin e-mail binding: the channel is expected to authenticate every message
            // (valid DKIM/DMARC), capped by min() at the directory before the address is trusted for an
            // elevated operation. Documents the binding's intent; not part of the enrollment min.
            RequiredMessageAuthentication: true,
            LastVerifiedAt: now));

        await challengeStore.RemoveAsync(user, normalized);

        logger.LogInformation(
            "[{TenantId}] Self-service e-mail identifier verified and enrolled Strong (binding {BindingRtId})",
            tenantId, bindingRtId);

        return new OtpVerificationResult(OtpVerificationStatus.Verified, 0, bindingRtId);
    }

    public async Task<CertificateEnrollmentResult> EnrollCertificateAsync(string tenantId, RtUser user,
        byte[] certificateBytes)
    {
        X509Certificate2 certificate;
        try
        {
            certificate = LoadCertificate(certificateBytes);
        }
        catch (CryptographicException)
        {
            return new CertificateEnrollmentResult(CertificateEnrollmentStatus.Unreadable);
        }

        using (certificate)
        {
            var fingerprint = certificate.GetCertHashString(HashAlgorithmName.SHA256).ToUpperInvariant();
            var now = timeProvider.GetUtcNow().UtcDateTime;
            var notBefore = certificate.NotBefore.ToUniversalTime();
            var notAfter = certificate.NotAfter.ToUniversalTime();

            // Validity is checked at enrollment: an already-expired or not-yet-valid certificate is
            // invalid and never enrolls (and a stored one drops to invalid once notAfter passes —
            // enforced by the resolver via the ValidUntil attribute).
            if (now < notBefore || now > notAfter)
            {
                return new CertificateEnrollmentResult(CertificateEnrollmentStatus.NotValid, fingerprint, notAfter);
            }

            if (await IsOwnedByAnotherUserAsync(RtIdentifierKindEnum.ClientCertificateFingerprint, fingerprint, user))
            {
                return new CertificateEnrollmentResult(CertificateEnrollmentStatus.AlreadyOwnedByAnotherUser,
                    fingerprint, notAfter);
            }

            var bindingRtId = await verifiedIdentifierResolver.StoreBindingAsync(new VerifiedIdentifierBinding(
                RtIdentifierKindEnum.ClientCertificateFingerprint,
                fingerprint,
                user.RtId,
                RtTrustLevelEnum.Strong,
                RtIdentifierSourceEnum.SelfService,
                LastVerifiedAt: now,
                ValidUntil: notAfter));

            logger.LogInformation(
                "[{TenantId}] Self-service client certificate enrolled Strong (binding {BindingRtId}, valid until {NotAfter:o})",
                tenantId, bindingRtId, notAfter);

            return new CertificateEnrollmentResult(CertificateEnrollmentStatus.Enrolled, fingerprint, notAfter,
                bindingRtId);
        }
    }

    public async Task<bool> RemoveAsync(RtUser user, RtIdentifierKindEnum identifierKind, string identifierValue)
    {
        // Only ever remove the user's OWN identifier: confirm it is in this user's set first, so a
        // caller cannot delete another user's binding by guessing its (kind, value).
        var owned = await verifiedIdentifierResolver.GetByUserAsync(user.RtId);
        var isOwn = owned.Any(s => s.IdentifierKind == identifierKind && s.IdentifierValue == identifierValue);
        if (!isOwn)
        {
            return false;
        }

        return await verifiedIdentifierResolver.RemoveBindingAsync(identifierKind, identifierValue);
    }

    private async Task<bool> IsOwnedByAnotherUserAsync(RtIdentifierKindEnum kind, string value, RtUser user)
    {
        var resolution = await verifiedIdentifierResolver.ResolveAsync(kind, value, RtTrustLevelEnum.None);
        return resolution != null && resolution.User.RtId != user.RtId;
    }

    private async Task DeliverAsync(OtpDeliveryChannelKind kind, OtpDeliveryContext context,
        CancellationToken cancellationToken)
    {
        var channel = deliveryChannels.FirstOrDefault(c => c.Kind == kind);
        if (channel == null)
        {
            throw new InvalidOperationException(
                $"No OTP delivery channel is registered for modality '{kind}'.");
        }

        await channel.DeliverAsync(context, cancellationToken);
    }

    private bool CodeMatches(OtpChallenge challenge, string code)
    {
        var salt = Convert.FromBase64String(challenge.Salt);
        var expected = Convert.FromBase64String(challenge.CodeHash);
        var actual = HashCode(salt, (code ?? string.Empty).Trim());
        return CryptographicOperations.FixedTimeEquals(expected, actual);
    }

    private static byte[] HashCode(byte[] salt, string code)
    {
        var codeBytes = Encoding.UTF8.GetBytes(code);
        var buffer = new byte[salt.Length + codeBytes.Length];
        Buffer.BlockCopy(salt, 0, buffer, 0, salt.Length);
        Buffer.BlockCopy(codeBytes, 0, buffer, salt.Length, codeBytes.Length);
        return SHA256.HashData(buffer);
    }

    private static string GenerateNumericCode()
    {
        // Cryptographically-random, fixed-width numeric code (leading zeros kept).
        var max = (int)Math.Pow(10, CodeLength);
        var value = RandomNumberGenerator.GetInt32(0, max);
        return value.ToString($"D{CodeLength}");
    }

    private static X509Certificate2 LoadCertificate(byte[] bytes)
    {
        // Accept both PEM and DER. PEM is detected by its armor so a copy-pasted certificate works.
        var text = TryGetText(bytes);
        if (text != null && text.Contains("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal))
        {
            return X509Certificate2.CreateFromPem(text);
        }

        return X509CertificateLoader.LoadCertificate(bytes);
    }

    private static string? TryGetText(byte[] bytes)
    {
        try
        {
            return Encoding.UTF8.GetString(bytes);
        }
        catch (ArgumentException)
        {
            return null;
        }
    }

    /// <summary>
    ///     Normalizes user input toward E.164: strips spaces, dashes, parentheses and dots, maps a
    ///     leading international "00" prefix to "+", and requires a leading "+" followed by 8–15
    ///     digits. This is a deliberately small normalizer (no external phone-number SDK, AB#5123);
    ///     it rejects obviously malformed input rather than validating every national numbering plan.
    /// </summary>
    private static bool TryNormalizePhoneNumber(string? raw, out string normalized)
    {
        normalized = string.Empty;
        if (string.IsNullOrWhiteSpace(raw))
        {
            return false;
        }

        var trimmed = raw.Trim();
        var sb = new StringBuilder(trimmed.Length);
        foreach (var ch in trimmed)
        {
            if (ch is ' ' or '-' or '(' or ')' or '.' or '/')
            {
                continue;
            }

            sb.Append(ch);
        }

        var cleaned = sb.ToString();
        if (cleaned.StartsWith("00", StringComparison.Ordinal))
        {
            cleaned = "+" + cleaned[2..];
        }

        if (!cleaned.StartsWith('+'))
        {
            return false;
        }

        var digits = cleaned[1..];
        if (digits.Length is < 8 or > 15 || !digits.All(char.IsAsciiDigit))
        {
            return false;
        }

        normalized = "+" + digits;
        return true;
    }

    /// <summary>Masks all but the last two digits of a phone number for display / logs.</summary>
    private static string Mask(string normalized)
    {
        if (normalized.Length <= 4)
        {
            return normalized;
        }

        var visible = normalized[^2..];
        return string.Concat(new string('•', normalized.Length - 2), visible);
    }

    /// <summary>
    ///     Trims and lower-cases the address and requires it to be a bare, valid e-mail — no display
    ///     name, no angle brackets, no list of addresses. Kept identical to
    ///     <c>AdminEmailBindingService</c> / the adapter's e-mail lookup normalization so the stored
    ///     value and the inbound From match case-insensitively (AB#5135).
    /// </summary>
    private static bool TryNormalizeEmail(string? raw, out string normalized)
    {
        normalized = string.Empty;
        if (string.IsNullOrWhiteSpace(raw))
        {
            return false;
        }

        var candidate = raw.Trim().ToLowerInvariant();

        // MailAddress accepts "Name <a@b.com>"; require the parsed address to equal the input so only
        // a bare address passes.
        if (!MailAddress.TryCreate(candidate, out var address) ||
            !string.Equals(address.Address, candidate, StringComparison.Ordinal))
        {
            return false;
        }

        normalized = candidate;
        return true;
    }

    /// <summary>Masks the local part of an e-mail address (keeps first char + full domain) for logs.</summary>
    private static string MaskEmail(string normalized)
    {
        var at = normalized.IndexOf('@');
        if (at <= 0)
        {
            return normalized;
        }

        var local = normalized[..at];
        var domain = normalized[at..];
        var head = local[0];
        return local.Length <= 1
            ? $"{head}{domain}"
            : $"{head}{new string('•', local.Length - 1)}{domain}";
    }
}
