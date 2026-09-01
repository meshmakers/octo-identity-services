using Duende.IdentityServer;
using Duende.IdentityServer.Models;
using Duende.IdentityServer.Validation;
using FluentAssertions;
using IdentityServerPersistence.Services;
using Meshmakers.Octo.Backend.IdentityServices.Services;
using Meshmakers.Octo.Services.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Shared.TestUtilities.Fakes;
using Xunit;

namespace IdentityServices.UnitTests.Services;

/// <summary>
///     AB#5065 (step 3 of <c>docs/CONCEPT-PER-TENANT-MIRROR-SECRETS.md</c>) — pins that a successful
///     client-credentials authentication records <b>which</b> secret matched: the copy inherited from
///     the parent tenant, or the mirror's own.
/// </summary>
/// <remarks>
///     <para>
///         The inherited copy is what keeps a child credential a parent credential; it cannot be
///         dropped (step 4) before it is known that no caller still authenticates with it. This
///         measurement is that knowledge, so its two failure modes both have to be excluded: it must
///         not mislabel (a caller presenting the own secret must never be counted as inherited use,
///         and vice versa) and it must not cost anything for the clients it does not concern.
///     </para>
///     <para>
///         The tests drive the real Duende <see cref="SecretValidator" /> with the real
///         <see cref="HashedSharedSecretValidator" />, i.e. genuine SHA-256 credential matching, so
///         "which secret matched" is decided by the same code the token endpoint uses. The inner
///         validator is wrapped in a counting spy: "no additional path for an ordinary client" is
///         asserted as a call count, not by reading the implementation.
///     </para>
/// </remarks>
public class MirrorSecretUsageTelemetryTests
{
    private const string ClientId = "ci-deploy";
    private const string TenantId = "customer-a";
    private const string InheritedPlaintext = "the-parents-secret";
    private const string OwnPlaintext = "the-mirrors-own-secret";

    private readonly CapturingLogger<MirrorSecretUsageTelemetryValidator> _logger = new();
    private readonly HttpContextAccessor _httpContextAccessor = new();
    private readonly CountingSecretValidator _inner;

    public MirrorSecretUsageTelemetryTests()
    {
        _inner = new CountingSecretValidator(new SecretValidator(
            TimeProvider.System,
            [new HashedSharedSecretValidator(NullLogger<HashedSharedSecretValidator>.Instance)],
            NullLogger<ISecretsListValidator>.Instance));

        _httpContextAccessor.HttpContext = new DefaultHttpContext();
        _httpContextAccessor.HttpContext.Items[InfrastructureCommon.TenantIdName] = TenantId;
    }

    private MirrorSecretUsageTelemetryValidator CreateSut() =>
        new(_inner, _httpContextAccessor, _logger);

    /// <summary>
    ///     The headline case: the caller presents the secret the mirror inherited from its parent —
    ///     the credential that still makes the escalation possible — and it is recorded as such, at
    ///     Warning, with the client and the tenant it addressed.
    /// </summary>
    [Fact]
    public async Task InheritedSecret_IsRecordedAsInheritedUse()
    {
        var sut = CreateSut();

        var result = await sut.ValidateAsync(
            MirrorSecrets(), SharedSecret(InheritedPlaintext), TestContext.Current.CancellationToken);

        result.Success.Should().BeTrue("the inherited secret is still accepted until step 4 removes it");
        _logger.AllText.Should().Contain("MirrorSecretUsage");
        _logger.AllText.Should().Contain($"secretKind={MirrorSecretUsageTelemetryValidator.InheritedSecretKind}");
        _logger.AllText.Should().Contain($"clientId={ClientId}");
        _logger.AllText.Should().Contain($"tenantId={TenantId}");
        _logger.AllText.Should().Contain("[Warning]",
            "the inherited-use count is the number that has to reach zero, so it must be visible as a warning");
    }

    /// <summary>
    ///     The counter-case, and the one that proves the classification is a real measurement rather
    ///     than a constant: the same client, the same secret list, a different credential.
    /// </summary>
    [Fact]
    public async Task OwnSecret_IsRecordedAsOwnUse()
    {
        var sut = CreateSut();

        var result = await sut.ValidateAsync(
            MirrorSecrets(), SharedSecret(OwnPlaintext), TestContext.Current.CancellationToken);

        result.Success.Should().BeTrue();
        _logger.AllText.Should().Contain($"secretKind={MirrorSecretUsageTelemetryValidator.OwnSecretKind}");
        _logger.AllText.Should().Contain("[Information]");
        _logger.AllText.Should().NotContain($"secretKind={MirrorSecretUsageTelemetryValidator.InheritedSecretKind}");
    }

    /// <summary>
    ///     A client that is not a mirror has no two secrets to tell apart, and must not pay for the
    ///     distinction: no record, and — asserted as a call count — no second trip through the
    ///     validator.
    /// </summary>
    [Fact]
    public async Task OrdinaryClient_ProducesNoRecordAndNoExtraValidation()
    {
        var sut = CreateSut();

        var result = await sut.ValidateAsync(
            [HashedSecret(InheritedPlaintext, description: null)], SharedSecret(InheritedPlaintext),
            TestContext.Current.CancellationToken);

        result.Success.Should().BeTrue();
        _logger.Messages.Should().BeEmpty();
        _inner.CallCount.Should().Be(1, "an unmirrored client must not be validated twice");
    }

    /// <summary>
    ///     Same for the entity on the introspection endpoint: <see cref="ISecretsListValidator" /> is
    ///     shared with <c>ApiSecretValidator</c>, whose API-resource secrets never carry the marker.
    /// </summary>
    [Fact]
    public async Task ApiResourceSecret_ProducesNoRecord()
    {
        var sut = CreateSut();

        var result = await sut.ValidateAsync(
            [HashedSecret("api-secret", description: "the octoAPI resource secret")],
            SharedSecret("api-secret", id: "octoAPI"), TestContext.Current.CancellationToken);

        result.Success.Should().BeTrue();
        _logger.Messages.Should().BeEmpty();
        _inner.CallCount.Should().Be(1);
    }

    /// <summary>
    ///     🔴 The security property: no secret material reaches a sink. Asserted against the
    ///     <i>rendered</i> output, so a structured placeholder that interpolated a credential or a
    ///     stored hash would fail this test — reviewing the format strings would not catch that.
    /// </summary>
    [Fact]
    public async Task NeverWritesSecretMaterialToTheLog()
    {
        var sut = CreateSut();

        await sut.ValidateAsync(
            MirrorSecrets(), SharedSecret(InheritedPlaintext), TestContext.Current.CancellationToken);
        await sut.ValidateAsync(
            MirrorSecrets(), SharedSecret(OwnPlaintext), TestContext.Current.CancellationToken);

        _logger.Messages.Should().NotBeEmpty("otherwise this test would pass vacuously");

        var rendered = _logger.AllText;
        rendered.Should().NotContain(InheritedPlaintext);
        rendered.Should().NotContain(OwnPlaintext);
        rendered.Should().NotContain(ClientMirrorSecrets.Sha256(InheritedPlaintext));
        rendered.Should().NotContain(ClientMirrorSecrets.Sha256(OwnPlaintext));

        // Not even a fragment: a prefix long enough to be recognisable is still a disclosure.
        rendered.Should().NotContain(InheritedPlaintext[..8]);
        rendered.Should().NotContain(OwnPlaintext[..8]);
    }

    /// <summary>
    ///     A rejected credential behaves exactly as before — same result, no record, and no second
    ///     validation. A wrong guess says nothing about which secret was meant, and counting it would
    ///     poison the very number step 4 is decided on.
    /// </summary>
    [Fact]
    public async Task FailedAuthentication_IsUnchangedAndSilent()
    {
        var sut = CreateSut();

        var result = await sut.ValidateAsync(
            MirrorSecrets(), SharedSecret("not-the-secret"), TestContext.Current.CancellationToken);

        result.Success.Should().BeFalse();
        _logger.Messages.Should().BeEmpty();
        _inner.CallCount.Should().Be(1);
    }

    /// <summary>
    ///     A credential that is not a shared secret cannot be either of the two. Without this guard
    ///     it would be reported as inherited use — a false positive that would keep step 4 blocked
    ///     forever.
    /// </summary>
    [Fact]
    public async Task NonSharedSecretCredential_IsNotClassified()
    {
        // The credential has to actually *succeed*, or the failure branch would short-circuit first
        // and the type guard would never be reached — the test would pass without testing anything.
        var inner = new CountingSecretValidator(new SecretValidator(
            TimeProvider.System, [new AlwaysSucceedingSecretValidator()],
            NullLogger<ISecretsListValidator>.Instance));
        var sut = new MirrorSecretUsageTelemetryValidator(inner, _httpContextAccessor, _logger);

        var parsed = new ParsedSecret
        {
            Id = ClientId,
            Credential = new object(),
            Type = IdentityServerConstants.ParsedSecretTypes.JwtBearer
        };

        var result = await sut.ValidateAsync(
            MirrorSecrets(), parsed, TestContext.Current.CancellationToken);

        result.Success.Should().BeTrue("otherwise the failure branch, not the type guard, is under test");
        _logger.Messages.Should().BeEmpty();
        inner.CallCount.Should().Be(1);
    }

    /// <summary>
    ///     A <c>client_credentials</c> request without <c>acr_values</c> resolves to no tenant. It is
    ///     about to be refused by AB#5058 anyway, so the record must not silently attribute it to
    ///     some default tenant and inflate that tenant's count.
    /// </summary>
    [Fact]
    public async Task UnresolvedTenant_IsMarkedRatherThanGuessed()
    {
        _httpContextAccessor.HttpContext = new DefaultHttpContext();
        var sut = CreateSut();

        await sut.ValidateAsync(
            MirrorSecrets(), SharedSecret(InheritedPlaintext), TestContext.Current.CancellationToken);

        _logger.AllText.Should()
            .Contain($"tenantId={MirrorSecretUsageTelemetryValidator.UnresolvedTenantId}");
    }

    /// <summary>
    ///     Telemetry must never decide an authentication. If the classification throws, the caller
    ///     that authenticated correctly stays authenticated and the gap is reported as an error.
    /// </summary>
    [Fact]
    public async Task MeasurementFailure_DoesNotFailTheAuthentication()
    {
        _inner.ThrowOnCall = 2;
        var sut = CreateSut();

        var result = await sut.ValidateAsync(
            MirrorSecrets(), SharedSecret(InheritedPlaintext), TestContext.Current.CancellationToken);

        result.Success.Should().BeTrue();
        _logger.AllText.Should().Contain("[Error]");
        _logger.AllText.Should().Contain("measurement failed");
    }

    /// <summary>
    ///     The wiring, not the logic: the decorator has to be the <see cref="ISecretsListValidator" />
    ///     Duende actually resolves, and its inner validator has to be constructible from the same
    ///     container. Both would otherwise fail only at the token endpoint of a running service — and
    ///     a telemetry decorator that is registered but never reached is exactly the silent-zero
    ///     failure mode step 4 must not be decided on.
    /// </summary>
    [Fact]
    public void Registration_DecoratesDuendesOwnSecretsListValidator()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IHttpContextAccessor>(_httpContextAccessor);
        services.AddIdentityServer();

        services.AddMirrorSecretUsageTelemetry();

        using var provider = services.BuildServiceProvider();
        provider.GetRequiredService<ISecretsListValidator>().Should()
            .BeOfType<MirrorSecretUsageTelemetryValidator>();
    }

    /// <summary>The secret list of a mirror after AB#5061: the parent's copy plus its own.</summary>
    private static List<Secret> MirrorSecrets() =>
    [
        HashedSecret(InheritedPlaintext, description: null),
        HashedSecret(OwnPlaintext, ClientMirrorSecrets.OwnSecretDescription)
    ];

    private static Secret HashedSecret(string plaintext, string? description) => new()
    {
        Type = IdentityServerConstants.SecretTypes.SharedSecret,
        Value = ClientMirrorSecrets.Sha256(plaintext),
        Description = description
    };

    private static ParsedSecret SharedSecret(string plaintext, string id = ClientId) => new()
    {
        Id = id,
        Credential = plaintext,
        Type = IdentityServerConstants.ParsedSecretTypes.SharedSecret
    };

    /// <summary>
    ///     Stands in for a validator of a non-shared-secret credential type (private key JWT, mTLS),
    ///     which the default chain in these tests does not carry. Only used to make such a credential
    ///     genuinely succeed, so the type guard is the thing under test.
    /// </summary>
    private sealed class AlwaysSucceedingSecretValidator : ISecretValidator
    {
        public Task<SecretValidationResult> ValidateAsync(IEnumerable<Secret> secrets,
            ParsedSecret parsedSecret, CancellationToken cancellationToken = default) =>
            Task.FromResult(new SecretValidationResult { Success = true });
    }

    /// <summary>
    ///     Delegates to the real validator and counts the calls, so "the ordinary client is not
    ///     validated a second time" is a behavioural assertion rather than a reading of the code.
    /// </summary>
    private sealed class CountingSecretValidator(ISecretsListValidator inner) : ISecretsListValidator
    {
        public int CallCount { get; private set; }

        /// <summary>1-based index of the call that should throw; 0 disables it.</summary>
        public int ThrowOnCall { get; set; }

        public Task<SecretValidationResult> ValidateAsync(IEnumerable<Secret> secrets,
            ParsedSecret parsedSecret, CancellationToken cancellationToken = default)
        {
            CallCount++;
            if (ThrowOnCall == CallCount)
            {
                throw new InvalidOperationException("simulated measurement failure");
            }

            return inner.ValidateAsync(secrets, parsedSecret, cancellationToken);
        }
    }
}
