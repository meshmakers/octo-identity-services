using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using FluentAssertions;
using IdentityServerPersistence.SystemStores;
using IdentityServices.IntegrationTests.Infrastructure;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.TenantApi;

/// <summary>
///     AB#7781 — credential guard regression tests of the identity service's REST API (tenant API v1): the user, group and
///     client endpoints never return a password hash, security stamp, two-factor token or client secret, and their writes
///     cannot set one. A user whose credential attributes hold fixed dummy values (never real credentials) is written the
///     way the identity store writes it; every response, and every log line the host writes during the test (Debug and
///     above, the MongoDB command log included), must not contain one of the dummy values. Real MVC pipeline, real stores,
///     real MongoDB; only the caller's token is simulated by <see cref="TestAuthHandler" /> (administrator roles).
/// </summary>
/// <remarks>
///     The secrets endpoints (<c>apiSecrets/client/{id}</c> and its <c>lookup</c>) return the stored hash of a client secret
///     by design: it is the handle an administrator uses to look up and delete a secret (AB#8008). They are tested to never
///     return the clear text and never a user credential.
/// </remarks>
public class IdentityCredentialGuardRestTests : IntegrationTestBase, IDisposable
{
    private const string DummyPasswordHash = "DUMMY-HASH-7781";
    private const string DummySecurityStamp = "DUMMY-STAMP-7781";
    private const string DummyAuthenticatorKey = "DUMMY-TOKEN-7781";
    private const string DummyRecoveryCode = "DUMMY-RECOVERY-7781";
    private const string DummyClientSecret = "DUMMY-CLIENT-SECRET-7781";
    private const string TokenLoginProvider = "[AspNetUserStore]";

    private static readonly string[] UserDummyValues =
        [DummyPasswordHash, DummySecurityStamp, DummyAuthenticatorKey, DummyRecoveryCode];

    private readonly WebApplicationFactory<Program> _host;
    private readonly CapturingLoggerProvider _logs = new();

    public IdentityCredentialGuardRestTests(CustomWebApplicationFactory factory) : base(factory)
    {
        _host = factory.WithWebHostBuilder(b => b.ConfigureTestServices(services => services.AddLogging(l =>
        {
            l.AddProvider(_logs);
            // Debug for this provider only: it carries the MongoDB command log of every store write.
            l.AddFilter<CapturingLoggerProvider>(null, LogLevel.Debug);
        })));
    }

    /// <summary>An undisposed derived host keeps its configuration file watchers (inotify limit on the CI agents).</summary>
    public void Dispose() => _host.Dispose();

    // ------------------------------------------------------------------------------------------------------------ users

    [Fact]
    public async Task UserReads_NeverReturnACredential()
    {
        var ct = TestContext.Current.CancellationToken;
        var user = await SeedUserWithDummyCredentialsAsync();
        var admin = Admin();

        var bodies = new List<string>();
        foreach (var path in new[]
                 {
                     "users", "users/GetPaged?skip=0&take=10000", $"users/{user.UserName}", $"users/{user.Email}",
                     $"users/{user.RtId}", $"users/directory?search={user.UserName}", $"users/{user.UserName}/roles",
                     $"users/{user.UserName}/directRoles"
                 })
        {
            var response = await admin.GetAsync(TenantApiUrl(path), ct);
            var body = await response.Content.ReadAsStringAsync(ct);
            response.StatusCode.Should().Be(HttpStatusCode.OK, $"GET {path}: {body}");
            bodies.Add(body);
            AssertNoUserCredential(body, $"GET {path}");
        }

        // Positive control: the list and the single-user reads do return the seeded user.
        bodies[0].Should().Contain(user.UserName);
        bodies[2].Should().Contain(user.UserName);
        AssertNoCredentialInLogs(user);
    }

    [Fact]
    public async Task UserDto_HasNoCredentialMember()
    {
        var ct = TestContext.Current.CancellationToken;
        var user = await SeedUserWithDummyCredentialsAsync();

        var response = await Admin().GetAsync(TenantApiUrl($"users/{user.UserName}"), ct);
        var dto = (await response.Content.ReadFromJsonAsync<JsonObject>(ct))!;

        dto.Select(p => p.Key.ToLowerInvariant()).Should().NotContain(
            ["passwordhash", "securitystamp", "usertokens", "password", "authenticatorkey", "recoverycodes", "tokens"]);
    }

    [Fact]
    public async Task UserUpdate_WithCredentialFields_ChangesNoCredential()
    {
        var ct = TestContext.Current.CancellationToken;
        var user = await SeedUserWithDummyCredentialsAsync();

        var response = await Admin().PutAsJsonAsync(TenantApiUrl($"users/{user.UserName}"), new
        {
            name = user.UserName,
            email = user.Email,
            firstName = "Updated",
            password = "Evil-Password-7781!",
            passwordHash = "EVIL-HASH-7781",
            securityStamp = "EVIL-STAMP-7781",
            userTokens = new[] { new { loginProvider = "[AspNetUserStore]", name = "AuthenticatorKey", value = "EVIL-TOKEN-7781" } },
            twoFactorEnabled = false
        }, ct);

        var body = await response.Content.ReadAsStringAsync(ct);
        response.StatusCode.Should().Be(HttpStatusCode.OK, body);
        AssertNoUserCredential(body, "PUT users");
        var stored = await LoadUserAsync(user.UserName!);
        stored.FirstName.Should().Be("Updated", "the update itself is applied");
        stored.PasswordHash.Should().Be(DummyPasswordHash);
        stored.SecurityStamp.Should().Be(DummySecurityStamp);
        StoredTokenValues(stored).Should().BeEquivalentTo(DummyAuthenticatorKey, DummyRecoveryCode);
        stored.TwoFactorEnabled.Should().BeTrue("2FA is switched off only by the identity method/REST endpoint");
        AssertNoCredentialInLogs(user);
    }

    [Fact]
    public async Task UserCreate_WithCredentialFields_StoresNoCallerChosenCredential()
    {
        var ct = TestContext.Current.CancellationToken;
        var userName = $"cred-create-{Guid.NewGuid():N}";

        var response = await Admin().PostAsJsonAsync(TenantApiUrl("users"), new
        {
            name = userName,
            email = $"{userName}@example.invalid",
            password = "Valid-Pass-7781!",
            passwordHash = "EVIL-HASH-7781",
            securityStamp = "EVIL-STAMP-7781",
            userTokens = new[] { new { loginProvider = "[AspNetUserStore]", name = "AuthenticatorKey", value = "EVIL-TOKEN-7781" } }
        }, ct);

        response.StatusCode.Should().Be(HttpStatusCode.OK, await response.Content.ReadAsStringAsync(ct));
        var stored = await LoadUserAsync(userName);
        stored.PasswordHash.Should().NotBeNullOrEmpty("the given password is hashed by the user manager")
            .And.NotBe("EVIL-HASH-7781", "a caller-supplied hash is never taken");
        stored.SecurityStamp.Should().NotBe("EVIL-STAMP-7781").And.NotBeNullOrEmpty();
        StoredTokenValues(stored).Should().BeEmpty();
    }

    // ----------------------------------------------------------------------------------------------------------- groups

    [Fact]
    public async Task GroupReads_WithTheUserAsMember_NeverReturnACredential()
    {
        var ct = TestContext.Current.CancellationToken;
        var user = await SeedUserWithDummyCredentialsAsync();
        var admin = Admin();
        var groupName = $"cred-group-{Guid.NewGuid():N}";
        var created = await admin.PostAsJsonAsync(TenantApiUrl("groups"), new { groupName }, ct);
        created.StatusCode.Should().Be(HttpStatusCode.Created, await created.Content.ReadAsStringAsync(ct));
        var groupId = (await created.Content.ReadFromJsonAsync<JsonObject>(ct))!["id"]!.GetValue<string>();
        (await admin.PutAsync(TenantApiUrl($"groups/{groupId}/members/users/{user.RtId}"), null, ct))
            .StatusCode.Should().Be(HttpStatusCode.OK);

        foreach (var path in new[]
                 {
                     "groups", "groups/GetPaged?skip=0&take=10000", $"groups/{groupId}", $"groups/names/{groupName}",
                     $"groups/{groupId}/members/users", $"groups/{groupId}/roles"
                 })
        {
            var response = await admin.GetAsync(TenantApiUrl(path), ct);
            var body = await response.Content.ReadAsStringAsync(ct);
            response.StatusCode.Should().Be(HttpStatusCode.OK, $"GET {path}: {body}");
            AssertNoUserCredential(body, $"GET {path}");
        }

        var members = await (await admin.GetAsync(TenantApiUrl($"groups/{groupId}/members/users"), ct)).Content
            .ReadAsStringAsync(ct);
        members.Should().Contain(user.RtId.ToString(), "positive control: the member is listed by id");
        AssertNoCredentialInLogs(user);
    }

    // ---------------------------------------------------------------------------------------------------------- clients

    [Fact]
    public async Task ClientReads_NeverReturnTheSecretOrItsHash_AndTheSecretsEndpointsNeverTheClearText()
    {
        var ct = TestContext.Current.CancellationToken;
        var admin = Admin();
        var clientId = $"cred-client-{Guid.NewGuid():N}";
        var created = await admin.PostAsJsonAsync(TenantApiUrl("clients"), new
        {
            clientId,
            clientName = clientId,
            isEnabled = true,
            allowedGrantTypes = new[] { "client_credentials" },
            requireClientSecret = true,
            clientSecret = DummyClientSecret
        }, ct);
        created.StatusCode.Should().Be(HttpStatusCode.OK, await created.Content.ReadAsStringAsync(ct));
        var storedHash = (await LoadClientSecretValuesAsync(clientId)).Should().ContainSingle().Subject;
        storedHash.Should().NotBe(DummyClientSecret, "only the hash is stored");

        foreach (var path in new[]
                 {
                     "clients", "clients/GetPaged?skip=0&take=10000", $"clients/{clientId}", $"clients/{clientId}/roles",
                     $"clients/{clientId}/actors"
                 })
        {
            var response = await admin.GetAsync(TenantApiUrl(path), ct);
            var body = await response.Content.ReadAsStringAsync(ct);
            response.StatusCode.Should().Be(HttpStatusCode.OK, $"GET {path}: {body}");
            body.Should().NotContain(DummyClientSecret, $"GET {path}").And.NotContain(storedHash, $"GET {path}");
        }

        var dto = (await (await admin.GetAsync(TenantApiUrl($"clients/{clientId}"), ct)).Content
            .ReadFromJsonAsync<JsonObject>(ct))!;
        dto["clientSecret"]?.GetValue<string?>().Should().BeNull("the secret member of the DTO is write-only");

        var list = await (await admin.GetAsync(TenantApiUrl($"apiSecrets/client/{clientId}"), ct)).Content
            .ReadAsStringAsync(ct);
        var lookup = await admin.PostAsJsonAsync(TenantApiUrl($"apiSecrets/client/{clientId}/lookup"),
            new { valueEncrypted = storedHash }, ct);
        var lookupBody = await lookup.Content.ReadAsStringAsync(ct);
        lookup.StatusCode.Should().Be(HttpStatusCode.OK, lookupBody);
        foreach (var body in new[] { list, lookupBody })
        {
            body.Should().NotContain(DummyClientSecret);
            body.Should().Contain(storedHash, "the stored hash is the handle of the secret (by design)");
        }

        _logs.Messages.Should().Contain(m => IsMongoCommandNaming(m, clientId),
            "the MongoDB command log of the client write must reach the capture (non-vacuous check)");
        AssertNoLogContains(DummyClientSecret, storedHash);
    }

    [Fact]
    public async Task ClientUpdate_WithASecretRecord_CannotPlantAHash_AndTheClearTextIsStoredHashed()
    {
        var ct = TestContext.Current.CancellationToken;
        var admin = Admin();
        var clientId = $"cred-client-{Guid.NewGuid():N}";
        (await admin.PostAsJsonAsync(TenantApiUrl("clients"),
                new { clientId, clientName = clientId, isEnabled = true, allowedGrantTypes = new[] { "client_credentials" } }, ct))
            .StatusCode.Should().Be(HttpStatusCode.OK);

        var planted = await admin.PutAsJsonAsync(TenantApiUrl($"clients/{clientId}"), new
        {
            clientId,
            clientSecrets = new[] { new { value = "EVIL-HASH-7781", type = "SharedSecret" } },
            secrets = new[] { new { value = "EVIL-HASH-7781" } }
        }, ct);
        planted.StatusCode.Should().Be(HttpStatusCode.OK, await planted.Content.ReadAsStringAsync(ct));
        (await LoadClientSecretValuesAsync(clientId)).Should().BeEmpty("a secret record in the body is not bound");

        var set = await admin.PutAsJsonAsync(TenantApiUrl($"clients/{clientId}"),
            new { clientId, clientSecret = DummyClientSecret }, ct);
        var setBody = await set.Content.ReadAsStringAsync(ct);
        set.StatusCode.Should().Be(HttpStatusCode.OK, setBody);
        var stored = (await LoadClientSecretValuesAsync(clientId)).Should().ContainSingle().Subject;
        stored.Should().NotBe(DummyClientSecret, "the clear text is stored hashed");
        setBody.Should().NotContain(DummyClientSecret).And.NotContain(stored);
        _logs.Messages.Should().Contain(m => IsMongoCommandNaming(m, clientId),
            "the MongoDB command log of the client write must reach the capture (non-vacuous check)");
        AssertNoLogContains(DummyClientSecret, stored);
    }

    // ---------------------------------------------------------------------------------------------------------- helpers

    private HttpClient Admin()
    {
        var client = _host.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "test-token");
        client.DefaultRequestHeaders.Add(TestAuthHandler.UserIdHeader, $"admin-{Guid.NewGuid():N}");
        foreach (var role in TestAuthDefaults.AdministratorRoles)
        {
            client.DefaultRequestHeaders.Add(TestAuthHandler.RoleHeader, role);
        }

        return client;
    }

    /// <summary>
    ///     A user with dummy credentials, written through the user manager and the user store of the host — the way the
    ///     identity service writes them. The values are read back as a positive control.
    /// </summary>
    private async Task<RtUser> SeedUserWithDummyCredentialsAsync()
    {
        var userName = $"cred-user-{Guid.NewGuid():N}";
        using (var scope = _host.Services.CreateScope())
        {
            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();
            var user = new RtUserBuilder()
                .WithUserName(userName)
                .WithEmail($"{userName}@example.invalid")
                .WithEmailConfirmed()
                .WithTwoFactorEnabled()
                .WithPasswordHash(DummyPasswordHash)
                .Build();
            var created = await userManager.CreateAsync(user);
            created.Succeeded.Should().BeTrue(string.Join(", ", created.Errors.Select(e => e.Description)));
            (await userManager.SetAuthenticationTokenAsync(user, TokenLoginProvider, "AuthenticatorKey",
                DummyAuthenticatorKey)).Succeeded.Should().BeTrue();
            (await userManager.SetAuthenticationTokenAsync(user, TokenLoginProvider, "RecoveryCodes", DummyRecoveryCode))
                .Succeeded.Should().BeTrue();

            // The user manager sets a fresh security stamp on create; write the dummy one through the store.
            var stored = await userManager.FindByNameAsync(userName);
            stored!.SecurityStamp = DummySecurityStamp;
            var store = scope.ServiceProvider.GetRequiredService<IUserStore<RtUser>>();
            (await store.UpdateAsync(stored, CancellationToken.None)).Succeeded.Should().BeTrue();
        }

        var seeded = await LoadUserAsync(userName);
        seeded.PasswordHash.Should().Be(DummyPasswordHash);
        seeded.SecurityStamp.Should().Be(DummySecurityStamp);
        StoredTokenValues(seeded).Should().Contain(DummyAuthenticatorKey);
        return seeded;
    }

    private async Task<RtUser> LoadUserAsync(string userName)
    {
        using var scope = _host.Services.CreateScope();
        var user = await scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>().FindByNameAsync(userName);
        user.Should().NotBeNull();
        return user!;
    }

    private static IEnumerable<string> StoredTokenValues(RtUser user) =>
        (user.UserTokens?.AsEnumerable() ?? []).SelectMany(t => (t.Value ?? string.Empty).Split(';'))
        .Where(v => v.Length > 0);

    private async Task<IReadOnlyList<string>> LoadClientSecretValuesAsync(string clientId)
    {
        using var scope = _host.Services.CreateScope();
        var client = await scope.ServiceProvider.GetRequiredService<IOctoClientStore>().FindRtClientByIdAsync(clientId);
        client.Should().NotBeNull();
        return client!.ClientSecrets.Select(s => s.Value!).ToList();
    }

    private static void AssertNoUserCredential(string body, string because)
    {
        foreach (var dummy in UserDummyValues)
        {
            body.Should().NotContain(dummy, because);
        }
    }

    /// <summary>
    ///     No captured line carries a user credential. Non-vacuous: the MongoDB command log (Debug) of the seed write names the
    ///     user, so it must have been captured.
    /// </summary>
    private void AssertNoCredentialInLogs(RtUser seeded)
    {
        _logs.Messages.Should().Contain(m => IsMongoCommandNaming(m, seeded.UserName!),
            "the MongoDB command log of the seed write must reach the capture (non-vacuous check)");
        AssertNoLogContains(UserDummyValues);
    }

    /// <summary>A rendered MongoDB command (Debug command log) that names <paramref name="value" />.</summary>
    private static bool IsMongoCommandNaming(string message, string value) =>
        message.Contains("\"$db\"", StringComparison.Ordinal) && message.Contains(value, StringComparison.Ordinal);

    private void AssertNoLogContains(params string[] values)
    {
        _logs.Messages.Where(m => values.Any(v => m.Contains(v, StringComparison.Ordinal))).Should()
            .BeEmpty("no log line may carry a credential");
    }

    private sealed class CapturingLoggerProvider : ILoggerProvider
    {
        public ConcurrentQueue<string> Messages { get; } = new();

        public ILogger CreateLogger(string categoryName) => new CapturingLogger(this);

        public void Dispose()
        {
        }

        private sealed class CapturingLogger(CapturingLoggerProvider owner) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
                Func<TState, Exception?, string> formatter)
                => owner.Messages.Enqueue(formatter(state, exception) + exception);
        }
    }
}
