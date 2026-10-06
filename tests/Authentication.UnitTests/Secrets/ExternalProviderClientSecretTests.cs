using System.Security.Cryptography;
using System.Text;
using FluentAssertions;
using Meshmakers.Octo.Backend.Authentication.DynamicAuth;
using Meshmakers.Octo.Backend.Authentication.Secrets;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Runtime.Contracts.Secrets;
using Meshmakers.Octo.Runtime.Engine.Repositories.Query;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Facebook;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.MicrosoftAccount;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Shared.TestUtilities.Fakes;
using Xunit;

namespace Authentication.UnitTests.Secrets;

/// <summary>
///     AB#5540: the identity-provider ClientSecret is a Secret attribute. The external provider setup
///     (DynamicAuthSchemeService → scheme creators) must hand the handler options the plaintext,
///     decrypted through ISecretAttributeProtector, for every stored form: enc:v2 envelope, legacy
///     clear text (before the encrypt sweep) and enc:v1 (older instance-secret format). A value that
///     cannot be decrypted skips only that provider. All keys are generated per test run.
/// </summary>
public sealed class ExternalProviderClientSecretTests : IDisposable
{
    private const string TenantId = "secret-test-tenant";

    private readonly byte[] _key = RandomNumberGenerator.GetBytes(32);
    private readonly ServiceProvider _serviceProvider;
    private readonly ITenantRepository _tenantRepository = Substitute.For<ITenantRepository>();
    private readonly FakeOctoSession _session = new();

    public ExternalProviderClientSecretTests()
    {
        _serviceProvider = BuildServiceProvider(new Dictionary<string, string?>
        {
            ["SecretEncryption:Keys:k1"] = Convert.ToBase64String(_key),
            ["SecretEncryption:ActiveKeyId"] = "k1",
            ["SecretEncryption:LegacyV1Key"] = Convert.ToBase64String(_key)
        });
    }

    public void Dispose()
    {
        _serviceProvider.Dispose();
    }

    private ServiceProvider BuildServiceProvider(Dictionary<string, string?> configurationValues,
        Action<IServiceCollection>? configure = null)
    {
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(configurationValues).Build();

        var systemContext = Substitute.For<ISystemContext>();
        systemContext.FindTenantRepositoryAsync(TenantId).Returns(Task.FromResult(_tenantRepository));
        _tenantRepository.GetSessionAsync().Returns(Task.FromResult<IOctoSession>(_session));

        var services = new ServiceCollection();
        services.AddSingleton<IConfiguration>(configuration);
        services.AddLogging();
        services.AddDataProtection();
        services.AddAuthenticationCore();
        services.AddRuntimeEngine();
        services.AddSingleton(systemContext);
        services.AddDynamicAuthentication()
            .AddGoogle()
            .AddFacebook()
            .AddMicrosoft()
            .AddAzureEntraId();
        configure?.Invoke(services);
        return services.BuildServiceProvider();
    }

    private ISecretAttributeProtector Protector => _serviceProvider.GetRequiredService<ISecretAttributeProtector>();

    private void GivenStoredProviders(params RtIdentityProvider[] providers)
    {
        IResultSet<RtIdentityProvider> resultSet =
            new ResultSet<RtIdentityProvider>(providers, providers.Length, null, null);
        _tenantRepository.GetRtEntitiesByTypeAsync<RtIdentityProvider>(_session, Arg.Any<RtEntityQueryOptions>())
            .Returns(Task.FromResult(resultSet));
    }

    private async Task ConfigureTenantAsync(IServiceProvider serviceProvider)
    {
        using var scope = serviceProvider.CreateScope();
        await scope.ServiceProvider.GetRequiredService<IDynamicAuthSchemeService>().ConfigureAsync(TenantId);
    }

    private static RtGoogleIdentityProvider Google(string name, RtSecretValue? secret) => new()
    {
        RtId = OctoObjectId.GenerateNewId(), Name = name, IsEnabled = true, ClientId = "google-client",
        ClientSecret = secret
    };

    // Mirrors the enc:v1 instance-secret format (AES-256-GCM, nonce ‖ tag ‖ ciphertext, base64).
    private static string EncryptV1(byte[] key, string plaintext)
    {
        var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        var nonce = RandomNumberGenerator.GetBytes(SecretEnvelope.NonceLength);
        var ciphertext = new byte[plaintextBytes.Length];
        var tag = new byte[SecretEnvelope.TagLength];
        using (var aes = new AesGcm(key, SecretEnvelope.TagLength))
        {
            aes.Encrypt(nonce, plaintextBytes, ciphertext, tag);
        }

        return SecretEnvelope.PrefixV1 + Convert.ToBase64String([.. nonce, .. tag, .. ciphertext]);
    }

    [Fact]
    public async Task ConfigureAsync_EncryptedSecret_HandlerOptionsGetDecryptedPlaintext()
    {
        var plaintext = $"google-{Guid.NewGuid():N}";
        var envelope = Protector.Protect(plaintext);
        envelope.IsProtected.Should().BeTrue();
        GivenStoredProviders(Google("Google", envelope));

        await ConfigureTenantAsync(_serviceProvider);

        var options = _serviceProvider.GetRequiredService<IOptionsMonitor<GoogleOptions>>()
            .Get($"{TenantId}:Google");
        options.ClientSecret.Should().Be(plaintext);
        options.ClientId.Should().Be("google-client");
    }

    [Fact]
    public async Task ConfigureAsync_LegacyPlaintextSecret_StillWorksBeforeTheSweep()
    {
        var provider = Google("Google", null);
        // A String found in the Secret slot (stored before the model change).
        provider.SetAttributeRawValue("ClientSecret", "legacy-clear-text");
        GivenStoredProviders(provider);

        await ConfigureTenantAsync(_serviceProvider);

        _serviceProvider.GetRequiredService<IOptionsMonitor<GoogleOptions>>()
            .Get($"{TenantId}:Google").ClientSecret.Should().Be("legacy-clear-text");
    }

    [Fact]
    public async Task ConfigureAsync_EncV1Secret_DecryptedWithLegacyKey()
    {
        var provider = new RtFacebookIdentityProvider
        {
            RtId = OctoObjectId.GenerateNewId(), Name = "Facebook", IsEnabled = true, ClientId = "fb-client",
            ClientSecret = RtSecretValue.LegacyPlaintext(EncryptV1(_key, "fb-from-v1"))
        };
        GivenStoredProviders(provider);

        await ConfigureTenantAsync(_serviceProvider);

        _serviceProvider.GetRequiredService<IOptionsMonitor<FacebookOptions>>()
            .Get($"{TenantId}:Facebook").AppSecret.Should().Be("fb-from-v1");
    }

    [Fact]
    public async Task ConfigureAsync_UndecryptableSecret_SkipsOnlyThatProvider()
    {
        // Encrypted with a key id this host does not know (e.g. restored from another environment).
        var foreignEnvelope = RtSecretValue.Protected(
            "enc:v2:k9:" + System.Buffers.Text.Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(48)));
        var microsoft = new RtMicrosoftIdentityProvider
        {
            RtId = OctoObjectId.GenerateNewId(), Name = "Microsoft", IsEnabled = true, ClientId = "ms-client",
            ClientSecret = Protector.Protect("ms-secret")
        };
        GivenStoredProviders(Google("Google", foreignEnvelope), microsoft);

        await ConfigureTenantAsync(_serviceProvider);

        var schemeProvider = _serviceProvider.GetRequiredService<IAuthenticationSchemeProvider>();
        (await schemeProvider.GetSchemeAsync($"{TenantId}:Google")).Should().BeNull();
        (await schemeProvider.GetSchemeAsync($"{TenantId}:Microsoft")).Should().NotBeNull();
        _serviceProvider.GetRequiredService<IOptionsMonitor<MicrosoftAccountOptions>>()
            .Get($"{TenantId}:Microsoft").ClientSecret.Should().Be("ms-secret");
    }

    [Fact]
    public async Task ConfigureAsync_NoKeyRing_LegacyPlaintextWorks_EncryptedSkipped()
    {
        using var withoutKeys = BuildServiceProvider(new Dictionary<string, string?>());
        withoutKeys.GetRequiredService<ISecretAttributeProtector>().IsConfigured.Should().BeFalse();

        var legacy = Google("Legacy", null);
        legacy.SetAttributeRawValue("ClientSecret", "legacy-clear-text");
        GivenStoredProviders(legacy, Google("Encrypted", Protector.Protect("needs-a-key")));

        await ConfigureTenantAsync(withoutKeys);

        var schemeProvider = withoutKeys.GetRequiredService<IAuthenticationSchemeProvider>();
        (await schemeProvider.GetSchemeAsync($"{TenantId}:Legacy")).Should().NotBeNull();
        (await schemeProvider.GetSchemeAsync($"{TenantId}:Encrypted")).Should().BeNull();
    }

    [Fact]
    public async Task ConfigureAsync_StrictMode_LegacyPlaintextSkipped_OthersRegistered()
    {
        // Strict mode (concept decision 10) rejects legacy clear text. That must skip only the
        // affected provider; an escaping exception would abort the tenant's scheme setup (and the
        // startup initializer for every following tenant).
        using var strict = BuildServiceProvider(new Dictionary<string, string?>
        {
            ["SecretEncryption:Keys:k1"] = Convert.ToBase64String(_key),
            ["SecretEncryption:ActiveKeyId"] = "k1",
            ["SecretEncryption:StrictMode"] = "true"
        });
        var strictProtector = strict.GetRequiredService<ISecretAttributeProtector>();
        strictProtector.IsStrictMode.Should().BeTrue();

        var legacy = Google("Legacy", null);
        legacy.SetAttributeRawValue("ClientSecret", "legacy-clear-text");
        GivenStoredProviders(legacy, Google("Encrypted", strictProtector.Protect("encrypted-secret")));

        await ConfigureTenantAsync(strict);

        var schemeProvider = strict.GetRequiredService<IAuthenticationSchemeProvider>();
        (await schemeProvider.GetSchemeAsync($"{TenantId}:Legacy")).Should().BeNull();
        (await schemeProvider.GetSchemeAsync($"{TenantId}:Encrypted")).Should().NotBeNull();
        strict.GetRequiredService<IOptionsMonitor<GoogleOptions>>()
            .Get($"{TenantId}:Encrypted").ClientSecret.Should().Be("encrypted-secret");
    }

    [Fact]
    public void SecretReader_ProviderWithoutSecret_ReturnsNull()
    {
        var reader = _serviceProvider.GetRequiredService<IIdentityProviderSecretReader>();

        reader.GetClientSecret(Google("Google", null), TenantId).Should().BeNull();
        reader.GetClientSecret(new RtOpenLdapIdentityProvider { Name = "Ldap" }, TenantId).Should().BeNull();
    }

    private static RtSecretValue ForeignEnvelope(string keyId = "k9")
        => RtSecretValue.Protected($"enc:v2:{keyId}:" +
                                   System.Buffers.Text.Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(48)));

    [Fact]
    public void SecretReader_UnknownKeyId_IsNotSet_LogsErrorWithoutValue()
    {
        // Decision r2-2: an unknown key id reads as "not set" (null) with an error log; the
        // ciphertext stays stored and becomes readable once the key is added to the ring.
        var logger = new CapturingLogger<IdentityProviderSecretReader>();
        var reader = new IdentityProviderSecretReader(Protector, logger);
        var envelope = ForeignEnvelope();

        reader.GetClientSecret(Google("Google", envelope), TenantId).Should().BeNull();

        logger.Messages.Should().ContainSingle().Which.Should().StartWith($"[{LogLevel.Error}]")
            .And.Contain("k9").And.Contain("Google").And.NotContain(envelope.Envelope!);
    }

    [Fact]
    public void SecretReader_GetClientSecretState_FromStoredFormOnly()
    {
        var reader = _serviceProvider.GetRequiredService<IIdentityProviderSecretReader>();
        var legacy = Google("Legacy", null);
        legacy.SetAttributeRawValue("ClientSecret", "legacy-clear-text");

        reader.GetClientSecretState(Google("Known", Protector.Protect("s"))).Should()
            .Be(IdentityProviderSecretState.Set);
        reader.GetClientSecretState(Google("Upper", ForeignEnvelope("K1"))).Should()
            .Be(IdentityProviderSecretState.Set, "key ids are case-insensitive");
        reader.GetClientSecretState(legacy).Should().Be(IdentityProviderSecretState.Set);
        reader.GetClientSecretState(Google("Pending", RtSecretValue.Pending("p"))).Should()
            .Be(IdentityProviderSecretState.Set);
        reader.GetClientSecretState(Google("Foreign", ForeignEnvelope())).Should()
            .Be(IdentityProviderSecretState.KeyMissing);
        reader.GetClientSecretState(Google("None", null)).Should().Be(IdentityProviderSecretState.NotSet);
        reader.GetClientSecretState(Google("Empty", RtSecretValue.Pending(string.Empty))).Should()
            .Be(IdentityProviderSecretState.NotSet);
        reader.GetClientSecretState(new RtOpenLdapIdentityProvider { Name = "Ldap" }).Should()
            .Be(IdentityProviderSecretState.NotSet);
    }

    [Fact]
    public async Task ConfigureAsync_UnknownKeyId_SkipsProviderWithoutDecrypting()
    {
        var protector = Substitute.For<ISecretAttributeProtector>();
        protector.IsKnownKeyId(Arg.Any<string?>()).Returns(false);
        using var withFakeProtector = BuildServiceProvider(new Dictionary<string, string?>(),
            services => services.Replace(ServiceDescriptor.Singleton(protector)));
        GivenStoredProviders(Google("Google", ForeignEnvelope()));

        await ConfigureTenantAsync(withFakeProtector);

        (await withFakeProtector.GetRequiredService<IAuthenticationSchemeProvider>()
            .GetSchemeAsync($"{TenantId}:Google")).Should().BeNull();
        protector.DidNotReceiveWithAnyArgs().Unprotect(default(RtSecretValue)!, default);
    }

    [Fact]
    public void RtSecretValue_NeverRendersThePlaintext()
    {
        var provider = Google("Google", RtSecretValue.Pending("do-not-log-me"));

        provider.ClientSecret!.ToString().Should().Be(RtSecretValue.Mask);
    }
}
