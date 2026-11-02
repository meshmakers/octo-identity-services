using FluentAssertions;
using IdentityServerPersistence.Services;
using Meshmakers.Octo.Backend.IdentityServices.OpenIddict;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Infrastructure;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using OpenIddict.Abstractions;
using OpenIddict.Core;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Shared.TestUtilities.Builders;
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
///         <b>Seat change from the pre-migration version.</b> The measurement used to decorate
///         Duende's <c>ISecretsListValidator</c>. OpenIddict has no such service — client
///         authentication runs through <c>OpenIddictApplicationManager.ValidateClientSecretAsync</c>,
///         so the tests drive the real <see cref="OctoApplicationManager" /> with genuine SHA-256
///         matching against real <see cref="RtClient" /> records. "Which secret matched" is therefore
///         decided by the very code the token endpoint uses.
///     </para>
/// </remarks>
public class MirrorSecretUsageTelemetryTests
{
    private const string ClientId = "ci-deploy";
    private const string TenantId = "customer-a";
    private const string InheritedPlaintext = "the-parents-secret";
    private const string OwnPlaintext = "the-mirrors-own-secret";

    private readonly CapturingLogger<MirrorSecretUsageTelemetry> _logger = new();
    private readonly HttpContextAccessor _httpContextAccessor = new();

    public MirrorSecretUsageTelemetryTests()
    {
        _httpContextAccessor.HttpContext = new DefaultHttpContext();
        _httpContextAccessor.HttpContext.Items[InfrastructureCommon.TenantIdName] = TenantId;
    }

    private OctoApplicationManager CreateManager(IMirrorSecretUsageTelemetry? telemetry = null)
    {
        var options = Substitute.For<IOptionsMonitor<OpenIddictCoreOptions>>();
        options.CurrentValue.Returns(new OpenIddictCoreOptions());

        return new OctoApplicationManager(
            Substitute.For<IOpenIddictApplicationCache<RtClient>>(),
            NullLogger<OpenIddictApplicationManager<RtClient>>.Instance,
            options,
            Substitute.For<IOpenIddictApplicationStore<RtClient>>(),
            telemetry ?? new MirrorSecretUsageTelemetry(_httpContextAccessor, _logger));
    }

    /// <summary>
    ///     The headline case: the caller presents the secret the mirror inherited from its parent —
    ///     the credential that still makes the escalation possible — and it is recorded as such, at
    ///     Warning, with the client and the tenant it addressed.
    /// </summary>
    [Fact]
    public async Task InheritedSecret_IsRecordedAsInheritedUse()
    {
        var accepted = await CreateManager().ValidateClientSecretAsync(
            MirrorClient(), InheritedPlaintext, TestContext.Current.CancellationToken);

        accepted.Should().BeTrue("the inherited secret is still accepted until step 4 removes it");
        _logger.AllText.Should().Contain("MirrorSecretUsage");
        _logger.AllText.Should().Contain($"secretKind={MirrorSecretUsageTelemetry.InheritedSecretKind}");
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
        var accepted = await CreateManager().ValidateClientSecretAsync(
            MirrorClient(), OwnPlaintext, TestContext.Current.CancellationToken);

        accepted.Should().BeTrue();
        _logger.AllText.Should().Contain($"secretKind={MirrorSecretUsageTelemetry.OwnSecretKind}");
        _logger.AllText.Should().Contain("[Information]");
        _logger.AllText.Should().NotContain($"secretKind={MirrorSecretUsageTelemetry.InheritedSecretKind}");
    }

    /// <summary>
    ///     🔴 The regression the OpenIddict migration made possible and this port has to close:
    ///     OpenIddict's application model carries exactly ONE client secret, and the store projection
    ///     returns the FIRST record. Without the manager's own loop, whichever of a mirror's two
    ///     secrets happened to be second would silently stop authenticating — which of the two is a
    ///     matter of list order, so the failure would look random.
    /// </summary>
    [Fact]
    public async Task SecondStoredSecret_StillAuthenticates()
    {
        var client = MirrorClient();
        client.ClientSecrets!.Count.Should().Be(2, "otherwise this test would pass vacuously");

        var bySecond = await CreateManager().ValidateClientSecretAsync(
            client, OwnPlaintext, TestContext.Current.CancellationToken);
        var byFirst = await CreateManager().ValidateClientSecretAsync(
            client, InheritedPlaintext, TestContext.Current.CancellationToken);

        bySecond.Should().BeTrue();
        byFirst.Should().BeTrue();
    }

    /// <summary>An expired record must not authenticate, whichever position it holds.</summary>
    [Fact]
    public async Task ExpiredSecret_IsNotAccepted()
    {
        var client = ClientWithSecrets(
            Secret(InheritedPlaintext, description: null, expiration: DateTime.UtcNow.AddMinutes(-1)));

        var accepted = await CreateManager().ValidateClientSecretAsync(
            client, InheritedPlaintext, TestContext.Current.CancellationToken);

        accepted.Should().BeFalse();
    }

    /// <summary>
    ///     A client that is not a mirror has no two secrets to tell apart, and must not pay for the
    ///     distinction — nor show up in the count.
    /// </summary>
    [Fact]
    public async Task OrdinaryClient_ProducesNoRecord()
    {
        var accepted = await CreateManager().ValidateClientSecretAsync(
            ClientWithSecrets(Secret(InheritedPlaintext, description: null)), InheritedPlaintext,
            TestContext.Current.CancellationToken);

        accepted.Should().BeTrue();
        _logger.Messages.Should().BeEmpty();
    }

    /// <summary>
    ///     A description that is not the mirror marker is not the marker. Guards against a
    ///     "has any description ⇒ own secret" shortcut, which would count ordinary rotations.
    /// </summary>
    [Fact]
    public async Task ClientWithADifferentSecretDescription_ProducesNoRecord()
    {
        var accepted = await CreateManager().ValidateClientSecretAsync(
            ClientWithSecrets(Secret(InheritedPlaintext, "rotated by the ops runbook")),
            InheritedPlaintext, TestContext.Current.CancellationToken);

        accepted.Should().BeTrue();
        _logger.Messages.Should().BeEmpty();
    }

    /// <summary>
    ///     🔴 The security property: no secret material reaches a sink. Asserted against the
    ///     <i>rendered</i> output, so a structured placeholder that interpolated a credential or a
    ///     stored hash would fail this test — reviewing the format strings would not catch that.
    /// </summary>
    [Fact]
    public async Task NeverWritesSecretMaterialToTheLog()
    {
        var manager = CreateManager();
        await manager.ValidateClientSecretAsync(MirrorClient(), InheritedPlaintext,
            TestContext.Current.CancellationToken);
        await manager.ValidateClientSecretAsync(MirrorClient(), OwnPlaintext,
            TestContext.Current.CancellationToken);

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
    ///     A rejected credential behaves exactly as before — same result and no record. A wrong guess
    ///     says nothing about which secret was meant, and counting it would poison the very number
    ///     step 4 is decided on.
    /// </summary>
    [Fact]
    public async Task FailedAuthentication_IsUnchangedAndSilent()
    {
        var accepted = await CreateManager().ValidateClientSecretAsync(
            MirrorClient(), "not-the-secret", TestContext.Current.CancellationToken);

        accepted.Should().BeFalse();
        _logger.Messages.Should().BeEmpty();
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

        await CreateManager().ValidateClientSecretAsync(
            MirrorClient(), InheritedPlaintext, TestContext.Current.CancellationToken);

        _logger.AllText.Should().Contain($"tenantId={MirrorSecretUsageTelemetry.UnresolvedTenantId}");
    }

    /// <summary>
    ///     Telemetry must never decide an authentication. If the measurement throws, the caller that
    ///     authenticated correctly stays authenticated and the gap is reported as an error.
    /// </summary>
    [Fact]
    public async Task MeasurementFailure_DoesNotFailTheAuthentication()
    {
        var telemetry = new MirrorSecretUsageTelemetry(
            _httpContextAccessor, new ThrowingLogger<MirrorSecretUsageTelemetry>(_logger));

        var accepted = await CreateManager(telemetry).ValidateClientSecretAsync(
            MirrorClient(), InheritedPlaintext, TestContext.Current.CancellationToken);

        accepted.Should().BeTrue();
        _logger.AllText.Should().Contain("[Error]");
        _logger.AllText.Should().Contain("measurement failed");
    }

    /// <summary>The secret list of a mirror after AB#5061: the parent's copy plus its own.</summary>
    private static RtClient MirrorClient() => ClientWithSecrets(
        Secret(InheritedPlaintext, description: null),
        Secret(OwnPlaintext, ClientMirrorSecrets.OwnSecretDescription));

    private static RtClient ClientWithSecrets(params RtSecretRecord[] secrets)
    {
        var client = new RtClientBuilder()
            .WithClientId(ClientId)
            .WithGrantTypes("client_credentials")
            .Build();
        client.RequireClientSecret = true;
        var list = new AttributeRecordValueList<RtSecretRecord>();
        foreach (var secret in secrets)
        {
            list.Add(secret);
        }

        client.ClientSecrets = list;
        return client;
    }

    private static RtSecretRecord Secret(string plaintext, string? description,
        DateTime? expiration = null) => new()
    {
        Type = ClientMirrorSecrets.SharedSecretType,
        Value = ClientMirrorSecrets.Sha256(plaintext),
        Description = description,
        ExpirationDateTime = expiration
    };

    /// <summary>
    ///     Fails the measurement from the inside: every non-error level throws, so the guard in
    ///     <see cref="MirrorSecretUsageTelemetry" /> is what is under test, while the error it writes
    ///     still reaches the capturing sink.
    /// </summary>
    private sealed class ThrowingLogger<T>(CapturingLogger<T> inner) : ILogger<T>
    {
        public IDisposable BeginScope<TState>(TState state) where TState : notnull =>
            inner.BeginScope(state);

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (logLevel != LogLevel.Error)
            {
                throw new InvalidOperationException("simulated measurement failure");
            }

            inner.Log(logLevel, eventId, state, exception, formatter);
        }
    }
}
