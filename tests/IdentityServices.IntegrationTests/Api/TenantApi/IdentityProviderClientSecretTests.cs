using System.Net;
using System.Net.Http.Json;
using FluentAssertions;
using IdentityServices.IntegrationTests.Infrastructure;
using Meshmakers.Octo.Backend.Authentication.DynamicAuth;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.TenantApi;

/// <summary>
///     AB#5540 end to end over HTTP and real MongoDB: the identity-provider ClientSecret (CK value type
///     Secret) is stored as an enc:v2 envelope, never returned by the REST API, kept on a replace
///     without a new secret, and decrypted for the external-provider scheme. The host's key ring is
///     generated per test run (<see cref="CustomWebApplicationFactory.TestSecretEncryptionKey" />).
/// </summary>
public class IdentityProviderClientSecretTests : IntegrationTestBase
{
    public IdentityProviderClientSecretTests(CustomWebApplicationFactory factory) : base(factory)
    {
    }

    private async Task<RtGoogleIdentityProvider?> LoadStoredAsync(OctoObjectId rtId)
    {
        var systemContext = Factory.Services.GetRequiredService<ISystemContext>();
        var repository = await systemContext.FindTenantRepositoryAsync(NormalizedSystemTenantId);
        var session = await repository.GetSessionAsync();
        session.StartTransaction();
        var entity = await repository.GetRtEntityByRtIdAsync<RtGoogleIdentityProvider>(session, rtId);
        await session.CommitTransactionAsync();
        return entity;
    }

    // The write-only field may appear as null (default serializer settings) but never with a value.
    private static void AssertNoClientSecretValue(string body)
        => body.Should().NotMatchRegex("\"clientSecret\"\\s*:\\s*\"");

    [Fact]
    public async Task ClientSecret_IsEncrypted_WriteOnly_Preserved_AndDecryptedForTheScheme()
    {
        var ct = TestContext.Current.CancellationToken;
        var name = $"google-{Guid.NewGuid():N}";
        var plaintext = $"secret-{Guid.NewGuid():N}";

        // Create
        IdentityProviderDto create = new GoogleIdentityProviderDto
        {
            Name = name, IsEnabled = true, ClientId = "google-client-id", ClientSecret = plaintext
        };
        var createResponse = await Client.PostAsJsonAsync(TenantApiUrl("identityProviders"), create, ct);
        var createBody = await createResponse.Content.ReadAsStringAsync(ct);
        createResponse.StatusCode.Should().Be(HttpStatusCode.OK, createBody);
        createBody.Should().NotContain(plaintext).And.NotContain("enc:v");
        var created = (await createResponse.Content.ReadFromJsonAsync<IdentityProviderDto>(ct))
            .Should().BeOfType<GoogleIdentityProviderDto>().Subject;
        created.ClientSecret.Should().BeNull();
        created.ClientSecretIsSet.Should().BeTrue();
        createBody.Should().Contain("\"clientSecretIsSet\":true");
        AssertNoClientSecretValue(createBody);
        var rtId = created.RtId!.Value;

        try
        {
            // Stored as an envelope of the active key, not as the plaintext
            var stored = await LoadStoredAsync(rtId);
            stored!.ClientSecret.Should().NotBeNull();
            stored.ClientSecret!.IsProtected.Should().BeTrue();
            stored.ClientSecret.KeyId.Should().Be("k1");
            var envelope = stored.ClientSecret.Envelope;
            envelope.Should().StartWith("enc:v2:k1:").And.NotContain(plaintext);

            // Read endpoints never return it
            var listBody = await Client.GetStringAsync(TenantApiUrl("identityProviders"), ct);
            listBody.Should().Contain(name).And.NotContain(plaintext).And.NotContain("enc:v");
            listBody.Should().Contain("\"clientSecretIsSet\":true");
            AssertNoClientSecretValue(listBody);
            var byIdBody = await Client.GetStringAsync(TenantApiUrl($"identityProviders/{rtId}"), ct);
            byIdBody.Should().NotContain(plaintext).And.NotContain("enc:v");
            byIdBody.Should().Contain("\"clientSecretIsSet\":true");
            AssertNoClientSecretValue(byIdBody);

            // Replace without a secret keeps the stored one (same ciphertext, not re-entered)
            IdentityProviderDto replace = new GoogleIdentityProviderDto
            {
                Name = name, IsEnabled = true, ClientId = "google-client-id-2", ClientSecret = ""
            };
            var replaceResponse =
                await Client.PutAsJsonAsync(TenantApiUrl($"identityProviders/{rtId}"), replace, ct);
            var replaceBody = await replaceResponse.Content.ReadAsStringAsync(ct);
            replaceResponse.StatusCode.Should().Be(HttpStatusCode.OK, replaceBody);
            replaceBody.Should().NotContain("enc:v");
            // The stored secret was carried over, so the response still reports it as set
            replaceBody.Should().Contain("\"clientSecretIsSet\":true");
            AssertNoClientSecretValue(replaceBody);
            var afterReplace = await LoadStoredAsync(rtId);
            afterReplace!.ClientId.Should().Be("google-client-id-2");
            afterReplace.ClientSecret!.Envelope.Should().Be(envelope);

            // The external-provider setup hands the handler the decrypted plaintext
            using (var scope = Factory.Services.CreateScope())
            {
                await scope.ServiceProvider.GetRequiredService<IDynamicAuthSchemeService>()
                    .ConfigureAsync(NormalizedSystemTenantId);
            }

            Factory.Services.GetRequiredService<IOptionsMonitor<GoogleOptions>>()
                .Get($"{NormalizedSystemTenantId}:{name}").ClientSecret.Should().Be(plaintext);

            // A placeholder is rejected and does not clear the stored secret
            IdentityProviderDto placeholder = new GoogleIdentityProviderDto
            {
                Name = name, IsEnabled = true, ClientId = "google-client-id-2",
                ClientSecret = "TODO_SET_GOOGLE_CLIENT_SECRET"
            };
            var placeholderResponse =
                await Client.PutAsJsonAsync(TenantApiUrl($"identityProviders/{rtId}"), placeholder, ct);
            placeholderResponse.StatusCode.Should().Be(HttpStatusCode.BadRequest);
            (await LoadStoredAsync(rtId))!.ClientSecret!.Envelope.Should().Be(envelope);
        }
        finally
        {
            await Client.DeleteAsync(TenantApiUrl($"identityProviders/{rtId}"), ct);
        }
    }

    [Fact]
    public async Task ClientSecret_LegacyValueWrittenByAnEngineCaller_IsEncryptedAndConfiguresTheScheme()
    {
        // A legacy (clear-text) value handed to the engine by an internal caller is re-encrypted on
        // write when a key ring is configured (concept §3.6); the scheme still gets the plaintext.
        // Reading a String that is still stored in the Secret slot is covered by the unit tests
        // (ExternalProviderClientSecretTests) and by the engine's MongoDB tests.
        var name = $"google-legacy-{Guid.NewGuid():N}";
        var systemContext = Factory.Services.GetRequiredService<ISystemContext>();
        var repository = await systemContext.FindTenantRepositoryAsync(NormalizedSystemTenantId);
        var provider = new RtGoogleIdentityProvider
        {
            RtId = OctoObjectId.GenerateNewId(), Name = name, IsEnabled = true, ClientId = "legacy-client",
            ClientSecret = RtSecretValue.LegacyPlaintext("legacy-clear-text")
        };

        var session = await repository.GetSessionAsync();
        session.StartTransaction();
        await repository.InsertOneRtEntityAsync(session, provider);
        await session.CommitTransactionAsync();

        try
        {
            (await LoadStoredAsync(provider.RtId))!.ClientSecret!.IsProtected.Should().BeTrue();

            using (var scope = Factory.Services.CreateScope())
            {
                await scope.ServiceProvider.GetRequiredService<IDynamicAuthSchemeService>()
                    .ConfigureAsync(NormalizedSystemTenantId);
            }

            Factory.Services.GetRequiredService<IOptionsMonitor<GoogleOptions>>()
                .Get($"{NormalizedSystemTenantId}:{name}").ClientSecret.Should().Be("legacy-clear-text");
        }
        finally
        {
            await Client.DeleteAsync(TenantApiUrl($"identityProviders/{provider.RtId}"),
                TestContext.Current.CancellationToken);
        }
    }
}
