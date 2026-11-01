using System.Buffers.Text;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using FluentAssertions;
using IdentityServerPersistence.SystemStores;
using IdentityServices.IntegrationTests.Infrastructure;
using Meshmakers.Common.Shared;
using Meshmakers.Octo.Backend.IdentityServices.OpenIddict;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.TenantApi;

/// <summary>
///     AB#6258: creating a client or API resource secret must work with the request the shipped octo-cli
///     sends (no <c>valueEncrypted</c>). Everything runs through the real MVC pipeline (model binding and
///     validation, authorization policies, controller, stores, token endpoint) against MongoDB; only the
///     caller's token is simulated by <see cref="TestAuthHandler" />.
/// </summary>
public class ApiSecretsControllerTests : IntegrationTestBase
{
    private const string NonAdministrativeRole = "DashboardViewer";

    public ApiSecretsControllerTests(CustomWebApplicationFactory factory) : base(factory)
    {
    }

    // ---------------------------------------------------------------- create client secret

    [Fact]
    public async Task PostClientSecret_WithTheRequestTheShippedCliSends_GeneratesSecretAndTokenRequestSucceeds()
    {
        var ct = TestContext.Current.CancellationToken;
        var clientId = await CreateMachineClientAsync();

        // The shipped CLI serialises a whole ApiSecretDto: valueEncrypted is null.
        var response = await Client.PostAsJsonAsync(SecretsUrl("client", clientId),
            new { valueEncrypted = (string?)null, valueClearText = (string?)null, expirationDate = (DateTime?)null, description = "cli" },
            ct);

        response.StatusCode.Should().Be(HttpStatusCode.OK, await response.Content.ReadAsStringAsync(ct));
        var dto = (await response.Content.ReadFromJsonAsync<JsonObject>(ct))!;
        var clearText = dto["valueClearText"]!.GetValue<string>();
        var stored = dto["valueEncrypted"]!.GetValue<string>();
        dto["description"]!.GetValue<string>().Should().Be("cli");

        // At least 256 bit from the CSPRNG, stored as Base64(SHA-256) in the existing format.
        Base64Url.DecodeFromChars(clearText).Length.Should().BeGreaterThanOrEqualTo(32);
        stored.Should().Be(Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(clearText))));

        (await RequestTokenAsync(clientId, clearText)).StatusCode.Should().Be(HttpStatusCode.OK);
        (await RequestTokenAsync(clientId, clearText + "x")).StatusCode.Should().Be(HttpStatusCode.Unauthorized);

        // A later GET exposes only the stored hash, never the clear text.
        var list = await Client.GetAsync(SecretsUrl("client", clientId), ct);
        var raw = await list.Content.ReadAsStringAsync(ct);
        list.StatusCode.Should().Be(HttpStatusCode.OK);
        raw.Should().Contain(stored).And.NotContain(clearText);
        raw.Should().Contain("\"cli\"", "the description of the request is persisted");
    }

    [Fact]
    public async Task PostClientSecret_WithMinimalBody_IsAccepted()
    {
        var clientId = await CreateMachineClientAsync();

        var response = await Client.PostAsJsonAsync(SecretsUrl("client", clientId), new { },
            TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task PostClientSecret_IgnoresClientSuppliedHashAndClearText()
    {
        var ct = TestContext.Current.CancellationToken;
        var clientId = await CreateMachineClientAsync();
        const string evilHash = "ZXZpbC1oYXNoLXRoZS1jYWxsZXItd2FudHMtc3RvcmVk";
        const string evilClear = "caller-chosen-weak-secret";

        var response = await Client.PostAsJsonAsync(SecretsUrl("client", clientId),
            new { valueEncrypted = evilHash, valueClearText = evilClear, unknownField = 1 }, ct);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var dto = (await response.Content.ReadFromJsonAsync<JsonObject>(ct))!;
        dto["valueClearText"]!.GetValue<string>().Should().NotBe(evilClear);
        dto["valueEncrypted"]!.GetValue<string>().Should().NotBe(evilHash);

        var stored = await GetStoredClientSecretsAsync(clientId);
        stored.Should().NotContain(evilHash);
        (await RequestTokenAsync(clientId, evilClear)).StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task PostClientSecret_TwoCalls_GenerateDifferentSecrets()
    {
        var ct = TestContext.Current.CancellationToken;
        var clientId = await CreateMachineClientAsync();

        var first = await CreateClientSecretAsync(clientId);
        var second = await CreateClientSecretAsync(clientId);

        first.Should().NotBe(second);
        (await RequestTokenAsync(clientId, first)).StatusCode.Should().Be(HttpStatusCode.OK, "first secret stays valid");
        (await RequestTokenAsync(clientId, second)).StatusCode.Should().Be(HttpStatusCode.OK);
        (await GetStoredClientSecretsAsync(clientId)).Should().HaveCount(2);
        ct.IsCancellationRequested.Should().BeFalse();
    }

    [Fact]
    public async Task PostClientSecret_NextToExistingSha256AndSha512Secrets_AllKeepValidating()
    {
        var clientId = await CreateMachineClientAsync(builder => builder
            .WithSecret("SharedSecret", Sha(SHA256.HashData, "legacy-sha256"))
            .WithSecret("SharedSecret", Sha(SHA512.HashData, "legacy-sha512")));

        var generated = await CreateClientSecretAsync(clientId);

        (await RequestTokenAsync(clientId, "legacy-sha256")).StatusCode.Should().Be(HttpStatusCode.OK);
        (await RequestTokenAsync(clientId, "legacy-sha512")).StatusCode.Should().Be(HttpStatusCode.OK);
        (await RequestTokenAsync(clientId, generated)).StatusCode.Should().Be(HttpStatusCode.OK);
        (await RequestTokenAsync(clientId, "legacy-sha512x")).StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task PostClientSecret_UnknownClient_Is404()
    {
        var response = await Client.PostAsJsonAsync(SecretsUrl("client", $"missing-{Guid.NewGuid():N}"),
            new { description = "x" }, TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task PostClientSecret_WithoutWritePermission_Is403_AndStoresNothing()
    {
        var clientId = await CreateMachineClientAsync();

        var response = await CreateAuthenticatedClient(userId: $"nobody-{Guid.NewGuid():N}",
                roles: [NonAdministrativeRole])
            .PostAsJsonAsync(SecretsUrl("client", clientId), new { description = "x" },
                TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await GetStoredClientSecretsAsync(clientId)).Should().BeEmpty();
    }

    // ---------------------------------------------------------------- create API resource secret

    [Fact]
    public async Task PostApiResourceSecret_WithTheRequestTheShippedCliSends_GeneratesSecret()
    {
        var ct = TestContext.Current.CancellationToken;
        var name = await CreateApiResourceAsync();

        var response = await Client.PostAsJsonAsync(SecretsUrl("apiResource", name),
            new { valueEncrypted = (string?)null, description = "res" }, ct);

        response.StatusCode.Should().Be(HttpStatusCode.OK, await response.Content.ReadAsStringAsync(ct));
        var dto = (await response.Content.ReadFromJsonAsync<JsonObject>(ct))!;
        var clearText = dto["valueClearText"]!.GetValue<string>();
        var stored = dto["valueEncrypted"]!.GetValue<string>();
        Base64Url.DecodeFromChars(clearText).Length.Should().BeGreaterThanOrEqualTo(32);
        OctoSecretHasher.Matches(clearText, stored).Should().BeTrue();

        var list = await Client.GetAsync(SecretsUrl("apiResource", name), ct);
        var raw = await list.Content.ReadAsStringAsync(ct);
        raw.Should().Contain(stored).And.NotContain(clearText);
    }

    [Fact]
    public async Task PostApiResourceSecret_UnknownResource_Is404_AndWithoutPermission_Is403()
    {
        var ct = TestContext.Current.CancellationToken;
        var name = await CreateApiResourceAsync();

        var missing = await Client.PostAsJsonAsync(SecretsUrl("apiResource", $"missing-{Guid.NewGuid():N}"),
            new { }, ct);
        var denied = await CreateAuthenticatedClient(userId: $"nobody-{Guid.NewGuid():N}",
                roles: [NonAdministrativeRole])
            .PostAsJsonAsync(SecretsUrl("apiResource", name), new { }, ct);

        missing.StatusCode.Should().Be(HttpStatusCode.NotFound);
        denied.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    // ---------------------------------------------------------------- hash verification

    [Theory]
    [InlineData("sha256")]
    [InlineData("sha512")]
    public void OctoSecretHasher_Matches_StoredSha256AndSha512(string algorithm)
    {
        var stored = algorithm == "sha256"
            ? Sha(SHA256.HashData, "s3cret")
            : Sha(SHA512.HashData, "s3cret");

        OctoSecretHasher.Matches("s3cret", stored).Should().BeTrue();
        OctoSecretHasher.Matches("s3cret ", stored).Should().BeFalse();
        OctoSecretHasher.Matches("", stored).Should().BeFalse();
    }

    // ---------------------------------------------------------------- update

    [Theory]
    [InlineData("client")]
    [InlineData("apiResource")]
    public async Task PutSecret_WithoutValueEncrypted_Is400_NotFound404Stays_ForUnknownValue(string kind)
    {
        var ct = TestContext.Current.CancellationToken;
        var target = kind == "client" ? await CreateMachineClientAsync() : await CreateApiResourceAsync();
        var url = SecretsUrl(kind, target);

        var missing = await Client.PutAsJsonAsync(url, new { description = "x" }, ct);
        var empty = await Client.PutAsJsonAsync(url, new { valueEncrypted = "", description = "x" }, ct);
        var blank = await Client.PutAsJsonAsync(url, new { valueEncrypted = "   ", description = "x" }, ct);
        var unknown = await Client.PutAsJsonAsync(url, new { valueEncrypted = "bm90LXN0b3JlZA==" }, ct);

        missing.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        empty.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        blank.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        unknown.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task PutClientSecret_WithStoredHash_UpdatesDescription()
    {
        var ct = TestContext.Current.CancellationToken;
        var clientId = await CreateMachineClientAsync();
        await CreateClientSecretAsync(clientId);
        var stored = (await GetStoredClientSecretsAsync(clientId)).Single();

        var response = await Client.PutAsJsonAsync(SecretsUrl("client", clientId),
            new { valueEncrypted = stored, description = "renamed" }, ct);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        (await Client.GetStringAsync(SecretsUrl("client", clientId), ct)).Should().Contain("renamed");
    }

    [Fact]
    public async Task PutApiResourceSecret_WithStoredHash_PersistsTheUpdate()
    {
        var ct = TestContext.Current.CancellationToken;
        var name = await CreateApiResourceAsync();
        var (_, stored) = await CreateSecretAsync("apiResource", name);

        var response = await Client.PutAsJsonAsync(SecretsUrl("apiResource", name),
            new { valueEncrypted = stored, description = "renamed" }, ct);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var secret = (await GetStoredApiResourceSecretsAsync(name)).Single();
        secret.Value.Should().Be(stored);
        secret.Description.Should().Be("renamed");
    }

    // ---------------------------------------------------------------- delete (AB#7989)

    [Fact]
    public async Task DeleteClientSecret_RemovesOnlyThatSecret_AndItNoLongerAuthenticates()
    {
        var ct = TestContext.Current.CancellationToken;
        var clientId = await CreateMachineClientAsync();
        var (revokedClearText, revokedHash) = await CreateSecretAsync("client", clientId);
        var (keptClearText, keptHash) = await CreateSecretAsync("client", clientId);
        (await RequestTokenAsync(clientId, revokedClearText)).StatusCode.Should().Be(HttpStatusCode.OK);

        // The client is loaded from the database by the endpoint, as for octo-cli DeleteApiSecretClient,
        // which sends the stored hash Base64-encoded in the path.
        var response = await Client.DeleteAsync(DeleteUrl("client", clientId, revokedHash), ct);

        response.StatusCode.Should().Be(HttpStatusCode.OK, await response.Content.ReadAsStringAsync(ct));
        (await GetStoredClientSecretsAsync(clientId)).Should().Equal(keptHash);
        (await RequestTokenAsync(clientId, revokedClearText)).StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        (await RequestTokenAsync(clientId, keptClearText)).StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task DeleteClientSecret_OfSeededLegacySecret_RemovesIt_AndItNoLongerAuthenticates()
    {
        var ct = TestContext.Current.CancellationToken;
        var legacyHash = Sha(SHA512.HashData, "legacy-to-revoke");
        var clientId = await CreateMachineClientAsync(builder => builder
            .WithSecret("SharedSecret", legacyHash)
            .WithSecret("SharedSecret", Sha(SHA256.HashData, "legacy-to-keep")));

        var response = await Client.DeleteAsync(DeleteUrl("client", clientId, legacyHash), ct);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        (await GetStoredClientSecretsAsync(clientId)).Should().Equal(Sha(SHA256.HashData, "legacy-to-keep"));
        (await RequestTokenAsync(clientId, "legacy-to-revoke")).StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        (await RequestTokenAsync(clientId, "legacy-to-keep")).StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task DeleteApiResourceSecret_RemovesOnlyThatSecret()
    {
        var ct = TestContext.Current.CancellationToken;
        var name = await CreateApiResourceAsync();
        var (_, revokedHash) = await CreateSecretAsync("apiResource", name);
        var (_, keptHash) = await CreateSecretAsync("apiResource", name);

        var response = await Client.DeleteAsync(DeleteUrl("apiResource", name, revokedHash), ct);

        response.StatusCode.Should().Be(HttpStatusCode.OK, await response.Content.ReadAsStringAsync(ct));
        (await GetStoredApiResourceSecretsAsync(name)).Select(s => s.Value).Should().Equal(keptHash);
        (await Client.GetStringAsync(SecretsUrl("apiResource", name), ct)).Should().NotContain(revokedHash);
    }

    [Theory]
    [InlineData("client")]
    [InlineData("apiResource")]
    public async Task DeleteSecret_UnknownSecret_Is404_WithoutEchoingTheValue_AndKeepsTheOthers(string kind)
    {
        var ct = TestContext.Current.CancellationToken;
        var target = kind == "client" ? await CreateMachineClientAsync() : await CreateApiResourceAsync();
        var (_, keptHash) = await CreateSecretAsync(kind, target);
        var unknownHash = Sha(SHA256.HashData, $"never-stored-{Guid.NewGuid():N}");

        var response = await Client.DeleteAsync(DeleteUrl(kind, target, unknownHash), ct);
        var body = await response.Content.ReadAsStringAsync(ct);

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
        body.Should().NotContain(unknownHash).And.NotContain(unknownHash.EncodeBase64());
        (await GetStoredSecretValuesAsync(kind, target)).Should().Equal(keptHash);

        // Deleting the same secret twice: the second call finds nothing.
        (await Client.DeleteAsync(DeleteUrl(kind, target, keptHash), ct)).StatusCode.Should().Be(HttpStatusCode.OK);
        (await Client.DeleteAsync(DeleteUrl(kind, target, keptHash), ct)).StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    [Theory]
    [InlineData("client")]
    [InlineData("apiResource")]
    public async Task DeleteSecret_UnknownOwner_Is404(string kind)
    {
        var response = await Client.DeleteAsync(
            DeleteUrl(kind, $"missing-{Guid.NewGuid():N}", Sha(SHA256.HashData, "x")),
            TestContext.Current.CancellationToken);

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    [Theory]
    [InlineData("client")]
    [InlineData("apiResource")]
    public async Task DeleteSecret_WithoutWritePermission_Is403_AndKeepsTheSecret(string kind)
    {
        var ct = TestContext.Current.CancellationToken;
        var target = kind == "client" ? await CreateMachineClientAsync() : await CreateApiResourceAsync();
        var (_, hash) = await CreateSecretAsync(kind, target);

        var response = await CreateAuthenticatedClient(userId: $"nobody-{Guid.NewGuid():N}",
                roles: [NonAdministrativeRole])
            .DeleteAsync(DeleteUrl(kind, target, hash), ct);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await GetStoredSecretValuesAsync(kind, target)).Should().Equal(hash);
    }

    [Theory]
    [InlineData("client")]
    [InlineData("apiResource")]
    public async Task ConcurrentSecretWrites_LoseNoUpdate_AndNeverBringADeletedSecretBack(string kind)
    {
        var ct = TestContext.Current.CancellationToken;
        var target = kind == "client" ? await CreateMachineClientAsync() : await CreateApiResourceAsync();
        var revoked = new List<(string ClearText, string Hash)>();
        for (var i = 0; i < 4; i++)
        {
            revoked.Add(await CreateSecretAsync(kind, target));
        }

        // Four deletes and six creates for the same owner at once: every write reads the owner first, so an
        // unversioned replace would write back secrets another request removed, or drop one another request added.
        var deletes = revoked.Select(r => Client.DeleteAsync(DeleteUrl(kind, target, r.Hash), ct)).ToList();
        var creates = Enumerable.Range(0, 6).Select(_ => Client.PostAsJsonAsync(SecretsUrl(kind, target), new { }, ct)).ToList();
        var responses = await Task.WhenAll(deletes.Concat(creates));

        responses.Select(r => r.StatusCode).Should().AllBeEquivalentTo(HttpStatusCode.OK);
        var created = new List<string>();
        foreach (var response in responses.Skip(deletes.Count))
        {
            created.Add((await response.Content.ReadFromJsonAsync<JsonObject>(ct))!["valueEncrypted"]!.GetValue<string>());
        }

        (await GetStoredSecretValuesAsync(kind, target)).Should().BeEquivalentTo(created);
        if (kind == "client")
        {
            foreach (var (clearText, _) in revoked)
            {
                (await RequestTokenAsync(target, clearText)).StatusCode.Should().Be(HttpStatusCode.Unauthorized);
            }
        }
    }

    // ---------------------------------------------------------------- no secret in the logs

    [Fact]
    public async Task CreatingSecrets_WritesNeitherSecretNorHashToTheLogs()
    {
        var ct = TestContext.Current.CancellationToken;
        var loggerFactory = Factory.Services.GetRequiredService<ILoggerFactory>();
        using var capture = new CapturingLoggerProvider();
        loggerFactory.AddProvider(capture);

        var clientId = await CreateMachineClientAsync();
        var resource = await CreateApiResourceAsync();
        var clientResponse = await Client.PostAsJsonAsync(SecretsUrl("client", clientId), new { }, ct);
        var resourceResponse = await Client.PostAsJsonAsync(SecretsUrl("apiResource", resource), new { }, ct);
        var secrets = new List<string>();
        foreach (var response in new[] { clientResponse, resourceResponse })
        {
            var dto = (await response.Content.ReadFromJsonAsync<JsonObject>(ct))!;
            secrets.Add(dto["valueClearText"]!.GetValue<string>());
            secrets.Add(dto["valueEncrypted"]!.GetValue<string>());
        }

        // A rejected create (unknown client) must not leak anything either.
        await Client.PostAsJsonAsync(SecretsUrl("client", "missing"), new { valueEncrypted = "leak-me-hash" }, ct);

        // The clear text must not show up at any level. The stored hash must not show up at the levels a
        // deployment runs with (Information and above); the MongoDB driver's Debug command log carries
        // whole documents - including every stored hash - and is off outside local debugging.
        var everything = string.Join('\n', capture.Messages.Select(m => m.Text));
        var deployed = string.Join('\n', capture.Messages.Where(m => m.Level >= LogLevel.Information).Select(m => m.Text));
        secrets[0].Should().NotBeNullOrEmpty();
        foreach (var clearText in new[] { secrets[0], secrets[2] })
        {
            everything.Should().NotContain(clearText);
        }

        foreach (var secret in secrets.Append("leak-me-hash"))
        {
            deployed.Should().NotContain(secret);
        }
    }

    [Fact]
    public async Task DeletingAndUpdatingSecrets_WritesNeitherHashNorEncodedHashToTheLogs()
    {
        var ct = TestContext.Current.CancellationToken;
        var loggerFactory = Factory.Services.GetRequiredService<ILoggerFactory>();
        var clientId = await CreateMachineClientAsync();
        var resource = await CreateApiResourceAsync();
        var (clientClear, clientHash) = await CreateSecretAsync("client", clientId);
        var (resourceClear, resourceHash) = await CreateSecretAsync("apiResource", resource);
        var unknownHash = Sha(SHA256.HashData, $"never-stored-{Guid.NewGuid():N}");

        using var capture = new CapturingLoggerProvider();
        loggerFactory.AddProvider(capture);
        await Client.PutAsJsonAsync(SecretsUrl("client", clientId), new { valueEncrypted = clientHash }, ct);
        await Client.PutAsJsonAsync(SecretsUrl("apiResource", resource), new { valueEncrypted = resourceHash }, ct);
        await Client.DeleteAsync(DeleteUrl("client", clientId, unknownHash), ct);
        (await Client.DeleteAsync(DeleteUrl("client", clientId, clientHash), ct)).StatusCode.Should().Be(HttpStatusCode.OK);
        (await Client.DeleteAsync(DeleteUrl("apiResource", resource, resourceHash), ct)).StatusCode.Should().Be(HttpStatusCode.OK);

        // Levels as deployed (nlog.config): own namespaces from Information, frameworks (Microsoft.*, the
        // request log with the path) from Warning. The clear text must not show up at any level.
        var deployed = string.Join('\n', capture.Messages
            .Where(m => m.Level >= (m.Category.StartsWith("Microsoft.", StringComparison.Ordinal) || m.Category.StartsWith("System.", StringComparison.Ordinal)
                ? LogLevel.Warning
                : LogLevel.Information))
            .Select(m => m.Text));
        var everything = string.Join('\n', capture.Messages.Select(m => m.Text));
        everything.Should().NotContain(clientClear).And.NotContain(resourceClear);
        foreach (var hash in new[] { clientHash, resourceHash, unknownHash })
        {
            deployed.Should().NotContain(hash).And.NotContain(hash.EncodeBase64());
        }
    }

    // ---------------------------------------------------------------- helpers

    private string SecretsUrl(string kind, string id) => TenantApiUrl($"apiSecrets/{kind}/{id}");

    // The path segment octo-cli (IdentityServicesClient) sends: the stored hash, Base64-encoded, URL-escaped.
    private string DeleteUrl(string kind, string id, string storedHash)
        => TenantApiUrl($"apiSecrets/{kind}/{id}/{Uri.EscapeDataString(storedHash.EncodeBase64())}");

    private async Task<(string ClearText, string Hash)> CreateSecretAsync(string kind, string id)
    {
        var ct = TestContext.Current.CancellationToken;
        var response = await Client.PostAsJsonAsync(SecretsUrl(kind, id), new { }, ct);
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var dto = (await response.Content.ReadFromJsonAsync<JsonObject>(ct))!;
        return (dto["valueClearText"]!.GetValue<string>(), dto["valueEncrypted"]!.GetValue<string>());
    }

    private async Task<List<RtSecretRecord>> GetStoredApiResourceSecretsAsync(string name)
    {
        using var scope = CreateScope();
        var resource = await scope.ServiceProvider.GetRequiredService<IOctoResourceStore>()
            .GetApiResourceByNameAsync(name);
        return resource!.ApiSecrets?.ToList() ?? [];
    }

    private async Task<List<string>> GetStoredSecretValuesAsync(string kind, string id)
        => kind == "client"
            ? await GetStoredClientSecretsAsync(id)
            : (await GetStoredApiResourceSecretsAsync(id)).Select(s => s.Value!).ToList();

    private async Task<string> CreateMachineClientAsync(Action<RtClientBuilder>? configure = null)
    {
        var clientId = $"apisecret-{Guid.NewGuid():N}";
        var builder = new RtClientBuilder()
            .WithClientId(clientId)
            .WithClientName(clientId)
            .WithGrantTypes("client_credentials")
            .WithScopes("openid")
            .RequireClientSecret()
            .RequirePkce(false);
        configure?.Invoke(builder);

        using var scope = CreateScope();
        await scope.ServiceProvider.GetRequiredService<IOctoClientStore>().CreateAsync(builder.Build());
        return clientId;
    }

    private async Task<string> CreateApiResourceAsync()
    {
        var name = $"apisecret-res-{Guid.NewGuid():N}";
        using var scope = CreateScope();
        await scope.ServiceProvider.GetRequiredService<IOctoResourceStore>().CreateApiResourceAsync(
            new RtApiResource
            {
                RtId = OctoObjectId.GenerateNewId(),
                Name = name,
                DisplayName = name,
                Enabled = true,
                ShowInDiscoveryDocument = true,
                Claims = new AttributeStringValueList(),
                Scopes = new AttributeStringValueList()
            });
        return name;
    }

    private async Task<string> CreateClientSecretAsync(string clientId)
    {
        var ct = TestContext.Current.CancellationToken;
        var response = await Client.PostAsJsonAsync(SecretsUrl("client", clientId), new { }, ct);
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var dto = (await response.Content.ReadFromJsonAsync<JsonObject>(ct))!;
        return dto["valueClearText"]!.GetValue<string>();
    }

    private async Task<List<string>> GetStoredClientSecretsAsync(string clientId)
    {
        using var scope = CreateScope();
        var client = await scope.ServiceProvider.GetRequiredService<IOctoClientStore>()
            .FindRtClientByIdAsync(clientId);
        return client!.ClientSecrets.Select(s => s.Value!).ToList();
    }

    private Task<HttpResponseMessage> RequestTokenAsync(string clientId, string secret)
        => CreateAnonymousClient().PostAsync("/connect/token", new FormUrlEncodedContent(
            new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = clientId,
                ["client_secret"] = secret,
                ["acr_values"] = $"tenant:{NormalizedSystemTenantId}"
            }), TestContext.Current.CancellationToken);

    private static string Sha(Func<byte[], byte[]> hash, string value)
        => Convert.ToBase64String(hash(Encoding.UTF8.GetBytes(value)));

    private sealed class CapturingLoggerProvider : ILoggerProvider
    {
        public ConcurrentQueue<(LogLevel Level, string Text, string Category)> Messages { get; } = new();

        public ILogger CreateLogger(string categoryName) => new CapturingLogger(this, categoryName);

        public void Dispose()
        {
        }

        private sealed class CapturingLogger(CapturingLoggerProvider owner, string category) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
                Func<TState, Exception?, string> formatter)
                => owner.Messages.Enqueue((logLevel, formatter(state, exception) + exception, category));
        }
    }
}
