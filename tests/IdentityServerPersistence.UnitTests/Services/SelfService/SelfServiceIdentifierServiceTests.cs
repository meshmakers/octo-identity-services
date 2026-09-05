using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using FluentAssertions;
using IdentityServerPersistence.Services.SelfService;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Services.SelfService;

/// <summary>
///     Pins the self-service verified-identifier flow (AB#5123): a phone OTP enrolls the number Strong
///     with Source = SelfService ONLY on a correct, unexpired, in-budget code, and a wrong / expired /
///     over-budget code NEVER enrolls. The OTP is exercised end-to-end (real salted-hash + attempt
///     budget) via an in-memory challenge store and a delivery channel that captures the sent code.
///     Certificate enrollment checks validity before it enrolls.
/// </summary>
public class SelfServiceIdentifierServiceTests
{
    private const string TenantId = "acme";
    private const string RawNumber = "+43 660 1234567";
    private const string NormalizedNumber = "+436601234567";
    private const string RawEmail = "  Alice@Example.COM ";
    private const string NormalizedEmail = "alice@example.com";

    private readonly IVerifiedIdentifierResolver _resolver = Substitute.For<IVerifiedIdentifierResolver>();
    private readonly InMemoryChallengeStore _challengeStore = new();
    private readonly CapturingDeliveryChannel _delivery = new(OtpDeliveryChannelKind.Signal);
    private readonly CapturingDeliveryChannel _emailDelivery = new(OtpDeliveryChannelKind.Email);
    private readonly MutableTimeProvider _time = new(new DateTime(2026, 9, 4, 12, 0, 0, DateTimeKind.Utc));
    private readonly SelfServiceIdentifierService _service;
    private readonly RtUser _user = new() { RtId = OctoObjectId.GenerateNewId(), UserName = "alice" };

    public SelfServiceIdentifierServiceTests()
    {
        _resolver.StoreBindingAsync(Arg.Any<VerifiedIdentifierBinding>()).Returns(OctoObjectId.GenerateNewId());
        // No pre-existing binding: the identifier is not owned by anyone yet.
        _resolver.ResolveAsync(Arg.Any<RtIdentifierKindEnum>(), Arg.Any<string>(), Arg.Any<RtTrustLevelEnum>())
            .Returns((VerifiedIdentifierResolution?)null);
        _service = new SelfServiceIdentifierService(_resolver, _challengeStore, [_delivery, _emailDelivery], _time,
            Substitute.For<ILogger<SelfServiceIdentifierService>>());
    }

    private async Task<string> StartAndGetCodeAsync()
    {
        var start = await _service.StartPhoneEnrollmentAsync(TenantId, _user, RawNumber, TestContext.Current.CancellationToken);
        start.Status.Should().Be(StartPhoneEnrollmentStatus.CodeSent);
        _delivery.LastCode.Should().NotBeNull();
        return _delivery.LastCode!;
    }

    [Fact]
    public async Task Start_normalizes_the_number_and_delivers_a_code_without_enrolling()
    {
        var start = await _service.StartPhoneEnrollmentAsync(TenantId, _user, RawNumber, TestContext.Current.CancellationToken);

        start.Status.Should().Be(StartPhoneEnrollmentStatus.CodeSent);
        start.NormalizedNumber.Should().Be(NormalizedNumber);
        _delivery.LastDestination.Should().Be(NormalizedNumber);
        // The challenge must be persisted hashed — the clear code never appears in the store.
        _challengeStore.Stored(NormalizedNumber)!.CodeHash.Should().NotContain(_delivery.LastCode!);
        await _resolver.DidNotReceive().StoreBindingAsync(Arg.Any<VerifiedIdentifierBinding>());
    }

    [Fact]
    public async Task Correct_code_enrolls_the_number_Strong_self_service()
    {
        var code = await StartAndGetCodeAsync();

        var result = await _service.VerifyPhoneAsync(TenantId, _user, RawNumber, code);

        result.Status.Should().Be(OtpVerificationStatus.Verified);
        await _resolver.Received(1).StoreBindingAsync(Arg.Is<VerifiedIdentifierBinding>(b =>
            b.IdentifierKind == RtIdentifierKindEnum.PhoneNumber &&
            b.IdentifierValue == NormalizedNumber &&
            b.UserRtId == _user.RtId &&
            b.EnrollmentTrust == RtTrustLevelEnum.Strong &&
            b.Source == RtIdentifierSourceEnum.SelfService));
        // The challenge is consumed on success.
        _challengeStore.Stored(NormalizedNumber).Should().BeNull();
    }

    [Fact]
    public async Task Wrong_code_does_not_enroll_and_consumes_one_attempt()
    {
        var code = await StartAndGetCodeAsync();
        var wrong = code == "000000" ? "111111" : "000000";

        var result = await _service.VerifyPhoneAsync(TenantId, _user, RawNumber, wrong);

        result.Status.Should().Be(OtpVerificationStatus.CodeMismatch);
        result.AttemptsRemaining.Should().Be(4);
        await _resolver.DidNotReceive().StoreBindingAsync(Arg.Any<VerifiedIdentifierBinding>());
        // A subsequent correct code still works while attempts remain.
        (await _service.VerifyPhoneAsync(TenantId, _user, RawNumber, code)).Status
            .Should().Be(OtpVerificationStatus.Verified);
    }

    [Fact]
    public async Task Expired_code_does_not_enroll()
    {
        var code = await StartAndGetCodeAsync();
        _time.Advance(TimeSpan.FromMinutes(6)); // TTL is 5 minutes

        var result = await _service.VerifyPhoneAsync(TenantId, _user, RawNumber, code);

        result.Status.Should().Be(OtpVerificationStatus.Expired);
        await _resolver.DidNotReceive().StoreBindingAsync(Arg.Any<VerifiedIdentifierBinding>());
        _challengeStore.Stored(NormalizedNumber).Should().BeNull();
    }

    [Fact]
    public async Task Attempt_limit_burns_the_challenge_and_never_enrolls()
    {
        var code = await StartAndGetCodeAsync();
        var wrong = code == "000000" ? "111111" : "000000";

        OtpVerificationResult? last = null;
        for (var i = 0; i < 5; i++)
        {
            last = await _service.VerifyPhoneAsync(TenantId, _user, RawNumber, wrong);
        }

        last!.Status.Should().Be(OtpVerificationStatus.CodeMismatch);
        last.AttemptsRemaining.Should().Be(0);
        _challengeStore.Stored(NormalizedNumber).Should().BeNull();

        // Even the correct code cannot enroll once the budget is exhausted — the challenge is gone.
        var afterBurn = await _service.VerifyPhoneAsync(TenantId, _user, RawNumber, code);
        afterBurn.Status.Should().Be(OtpVerificationStatus.NoChallenge);
        await _resolver.DidNotReceive().StoreBindingAsync(Arg.Any<VerifiedIdentifierBinding>());
    }

    [Fact]
    public async Task Verify_without_a_pending_challenge_is_a_no_op()
    {
        var result = await _service.VerifyPhoneAsync(TenantId, _user, RawNumber, "123456");

        result.Status.Should().Be(OtpVerificationStatus.NoChallenge);
        await _resolver.DidNotReceive().StoreBindingAsync(Arg.Any<VerifiedIdentifierBinding>());
    }

    [Fact]
    public async Task Invalid_number_is_rejected_before_any_code_is_sent()
    {
        var result = await _service.StartPhoneEnrollmentAsync(TenantId, _user, "not-a-number", TestContext.Current.CancellationToken);

        result.Status.Should().Be(StartPhoneEnrollmentStatus.InvalidNumber);
        _delivery.LastCode.Should().BeNull();
    }

    [Fact]
    public async Task A_number_owned_by_another_user_is_refused()
    {
        _resolver.ResolveAsync(RtIdentifierKindEnum.PhoneNumber, NormalizedNumber, Arg.Any<RtTrustLevelEnum>())
            .Returns(new VerifiedIdentifierResolution(
                new RtUser { RtId = OctoObjectId.GenerateNewId(), UserName = "mallory" },
                OctoObjectId.GenerateNewId(), RtTrustLevelEnum.Strong, RtTrustLevelEnum.None, RtTrustLevelEnum.None));

        var result = await _service.StartPhoneEnrollmentAsync(TenantId, _user, RawNumber, TestContext.Current.CancellationToken);

        result.Status.Should().Be(StartPhoneEnrollmentStatus.AlreadyOwnedByAnotherUser);
        _delivery.LastCode.Should().BeNull();
    }

    [Fact]
    public async Task Remove_refuses_an_identifier_the_user_does_not_own()
    {
        _resolver.GetByUserAsync(_user.RtId).Returns(Array.Empty<VerifiedIdentifierSummary>());

        var removed = await _service.RemoveAsync(_user, RtIdentifierKindEnum.PhoneNumber, NormalizedNumber);

        removed.Should().BeFalse();
        await _resolver.DidNotReceive().RemoveBindingAsync(Arg.Any<RtIdentifierKindEnum>(), Arg.Any<string>());
    }

    // ==== AB#5135 e-mail modality — mirrors the phone flow ==================================

    private async Task<string> StartEmailAndGetCodeAsync()
    {
        var start = await _service.StartEmailEnrollmentAsync(TenantId, _user, RawEmail, TestContext.Current.CancellationToken);
        start.Status.Should().Be(StartEmailEnrollmentStatus.CodeSent);
        _emailDelivery.LastCode.Should().NotBeNull();
        return _emailDelivery.LastCode!;
    }

    [Fact]
    public async Task Start_email_normalizes_the_address_and_delivers_a_code_over_the_email_channel_without_enrolling()
    {
        var start = await _service.StartEmailEnrollmentAsync(TenantId, _user, RawEmail, TestContext.Current.CancellationToken);

        start.Status.Should().Be(StartEmailEnrollmentStatus.CodeSent);
        start.NormalizedEmail.Should().Be(NormalizedEmail);
        // Delivered over the Email-kind channel, NOT the Signal one.
        _emailDelivery.LastDestination.Should().Be(NormalizedEmail);
        _delivery.LastCode.Should().BeNull();
        // The challenge must be persisted hashed — the clear code never appears in the store.
        _challengeStore.Stored(NormalizedEmail)!.CodeHash.Should().NotContain(_emailDelivery.LastCode!);
        await _resolver.DidNotReceive().StoreBindingAsync(Arg.Any<VerifiedIdentifierBinding>());
    }

    [Fact]
    public async Task Correct_email_code_enrolls_the_address_Strong_self_service()
    {
        var code = await StartEmailAndGetCodeAsync();

        var result = await _service.VerifyEmailAsync(TenantId, _user, RawEmail, code);

        result.Status.Should().Be(OtpVerificationStatus.Verified);
        await _resolver.Received(1).StoreBindingAsync(Arg.Is<VerifiedIdentifierBinding>(b =>
            b.IdentifierKind == RtIdentifierKindEnum.EmailAddress &&
            b.IdentifierValue == NormalizedEmail &&
            b.UserRtId == _user.RtId &&
            b.EnrollmentTrust == RtTrustLevelEnum.Strong &&
            b.Source == RtIdentifierSourceEnum.SelfService));
        // The challenge is consumed on success.
        _challengeStore.Stored(NormalizedEmail).Should().BeNull();
    }

    [Fact]
    public async Task Wrong_email_code_does_not_enroll_and_consumes_one_attempt()
    {
        var code = await StartEmailAndGetCodeAsync();
        var wrong = code == "000000" ? "111111" : "000000";

        var result = await _service.VerifyEmailAsync(TenantId, _user, RawEmail, wrong);

        result.Status.Should().Be(OtpVerificationStatus.CodeMismatch);
        result.AttemptsRemaining.Should().Be(4);
        await _resolver.DidNotReceive().StoreBindingAsync(Arg.Any<VerifiedIdentifierBinding>());
        // A subsequent correct code still works while attempts remain.
        (await _service.VerifyEmailAsync(TenantId, _user, RawEmail, code)).Status
            .Should().Be(OtpVerificationStatus.Verified);
    }

    [Fact]
    public async Task Expired_email_code_does_not_enroll()
    {
        var code = await StartEmailAndGetCodeAsync();
        _time.Advance(TimeSpan.FromMinutes(6)); // TTL is 5 minutes

        var result = await _service.VerifyEmailAsync(TenantId, _user, RawEmail, code);

        result.Status.Should().Be(OtpVerificationStatus.Expired);
        await _resolver.DidNotReceive().StoreBindingAsync(Arg.Any<VerifiedIdentifierBinding>());
        _challengeStore.Stored(NormalizedEmail).Should().BeNull();
    }

    [Fact]
    public async Task Email_attempt_limit_burns_the_challenge_and_never_enrolls()
    {
        var code = await StartEmailAndGetCodeAsync();
        var wrong = code == "000000" ? "111111" : "000000";

        OtpVerificationResult? last = null;
        for (var i = 0; i < 5; i++)
        {
            last = await _service.VerifyEmailAsync(TenantId, _user, RawEmail, wrong);
        }

        last!.Status.Should().Be(OtpVerificationStatus.CodeMismatch);
        last.AttemptsRemaining.Should().Be(0);
        _challengeStore.Stored(NormalizedEmail).Should().BeNull();

        // Even the correct code cannot enroll once the budget is exhausted — the challenge is gone.
        var afterBurn = await _service.VerifyEmailAsync(TenantId, _user, RawEmail, code);
        afterBurn.Status.Should().Be(OtpVerificationStatus.NoChallenge);
        await _resolver.DidNotReceive().StoreBindingAsync(Arg.Any<VerifiedIdentifierBinding>());
    }

    [Fact]
    public async Task Invalid_email_is_rejected_before_any_code_is_sent()
    {
        var result = await _service.StartEmailEnrollmentAsync(TenantId, _user, "not-an-email", TestContext.Current.CancellationToken);

        result.Status.Should().Be(StartEmailEnrollmentStatus.InvalidEmail);
        _emailDelivery.LastCode.Should().BeNull();
    }

    [Fact]
    public async Task An_email_owned_by_another_user_is_refused()
    {
        _resolver.ResolveAsync(RtIdentifierKindEnum.EmailAddress, NormalizedEmail, Arg.Any<RtTrustLevelEnum>())
            .Returns(new VerifiedIdentifierResolution(
                new RtUser { RtId = OctoObjectId.GenerateNewId(), UserName = "mallory" },
                OctoObjectId.GenerateNewId(), RtTrustLevelEnum.Strong, RtTrustLevelEnum.None, RtTrustLevelEnum.None));

        var result = await _service.StartEmailEnrollmentAsync(TenantId, _user, RawEmail, TestContext.Current.CancellationToken);

        result.Status.Should().Be(StartEmailEnrollmentStatus.AlreadyOwnedByAnotherUser);
        _emailDelivery.LastCode.Should().BeNull();
    }

    [Fact]
    public async Task An_email_delivery_failure_surfaces_and_never_enrolls()
    {
        var service = new SelfServiceIdentifierService(_resolver, _challengeStore,
            [new ThrowingDeliveryChannel(OtpDeliveryChannelKind.Email)], _time,
            Substitute.For<ILogger<SelfServiceIdentifierService>>());

        var act = async () => await service.StartEmailEnrollmentAsync(TenantId, _user, RawEmail,
            TestContext.Current.CancellationToken);

        await act.Should().ThrowAsync<InvalidOperationException>();
        await _resolver.DidNotReceive().StoreBindingAsync(Arg.Any<VerifiedIdentifierBinding>());
    }

    [Fact]
    public async Task A_valid_certificate_enrolls_Strong_with_its_not_after()
    {
        var (bytes, notAfter) = CreateCertificate(_time.GetUtcNow().UtcDateTime.AddDays(-1),
            _time.GetUtcNow().UtcDateTime.AddDays(30));

        var result = await _service.EnrollCertificateAsync(TenantId, _user, bytes);

        result.Status.Should().Be(CertificateEnrollmentStatus.Enrolled);
        result.Fingerprint.Should().NotBeNullOrWhiteSpace();
        await _resolver.Received(1).StoreBindingAsync(Arg.Is<VerifiedIdentifierBinding>(b =>
            b.IdentifierKind == RtIdentifierKindEnum.ClientCertificateFingerprint &&
            b.EnrollmentTrust == RtTrustLevelEnum.Strong &&
            b.Source == RtIdentifierSourceEnum.SelfService &&
            b.ValidUntil != null));
        result.ValidUntilUtc.Should().BeCloseTo(notAfter, TimeSpan.FromSeconds(2));
    }

    [Fact]
    public async Task An_expired_certificate_is_not_enrolled()
    {
        var (bytes, _) = CreateCertificate(_time.GetUtcNow().UtcDateTime.AddDays(-30),
            _time.GetUtcNow().UtcDateTime.AddDays(-1));

        var result = await _service.EnrollCertificateAsync(TenantId, _user, bytes);

        result.Status.Should().Be(CertificateEnrollmentStatus.NotValid);
        await _resolver.DidNotReceive().StoreBindingAsync(Arg.Any<VerifiedIdentifierBinding>());
    }

    private static (byte[] Bytes, DateTime NotAfter) CreateCertificate(DateTime notBefore, DateTime notAfter)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=ab5123-test", rsa, HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        using var cert = request.CreateSelfSigned(new DateTimeOffset(notBefore, TimeSpan.Zero),
            new DateTimeOffset(notAfter, TimeSpan.Zero));
        return (cert.Export(X509ContentType.Cert), cert.NotAfter.ToUniversalTime());
    }

    private sealed class InMemoryChallengeStore : IOtpChallengeStore
    {
        private readonly Dictionary<string, OtpChallenge> _byDestination = new();

        public OtpChallenge? Stored(string destination)
            => _byDestination.GetValueOrDefault(destination);

        public Task StoreAsync(RtUser user, OtpChallenge challenge)
        {
            _byDestination[challenge.Destination] = challenge;
            return Task.CompletedTask;
        }

        public Task<OtpChallenge?> GetAsync(RtUser user, string destination)
            => Task.FromResult(_byDestination.GetValueOrDefault(destination));

        public Task RemoveAsync(RtUser user, string destination)
        {
            _byDestination.Remove(destination);
            return Task.CompletedTask;
        }
    }

    private sealed class CapturingDeliveryChannel(OtpDeliveryChannelKind kind) : IOtpDeliveryChannel
    {
        public string? LastCode { get; private set; }
        public string? LastDestination { get; private set; }

        public OtpDeliveryChannelKind Kind => kind;

        public Task DeliverAsync(OtpDeliveryContext context, CancellationToken cancellationToken = default)
        {
            LastCode = context.Code;
            LastDestination = context.Destination;
            return Task.CompletedTask;
        }
    }

    private sealed class ThrowingDeliveryChannel(OtpDeliveryChannelKind kind) : IOtpDeliveryChannel
    {
        public OtpDeliveryChannelKind Kind => kind;

        public Task DeliverAsync(OtpDeliveryContext context, CancellationToken cancellationToken = default)
            => throw new InvalidOperationException("delivery failed");
    }

    private sealed class MutableTimeProvider(DateTime utcNow) : TimeProvider
    {
        private DateTimeOffset _now = new(utcNow, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => _now;
        public void Advance(TimeSpan by) => _now = _now.Add(by);
    }
}
