using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using FluentAssertions;
using IdentityServerPersistence.SystemStores;
using IdentityServices.IntegrationTests.Infrastructure;
using Microsoft.AspNetCore.Hosting;
using Meshmakers.Common.Shared;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.TenantApi;

/// <summary>
///     AB#8008: no credential value in a request URL and none in any log line, at any level.
///     <list type="bullet">
///         <item>The admin password reset takes the new password only in the body; the query form is refused (400).</item>
///         <item>The audit line names the client of a client-credentials caller.</item>
///         <item>Secret delete and lookup take the stored value in the body; the path variants still work for one
///             release, log a WARN without the value, and the value is masked in the request log.</item>
///     </list>
///     The host of this class logs everything at <see cref="LogLevel.Trace" /> (incl. the ASP.NET Core request log and
///     the TRACE log of the action arguments) into a capturing provider behind the service's real logger factory.
/// </summary>
public class CredentialsNotInUrlTests : IntegrationTestBase
{
    private const string OldPassword = "Test123!";

    private readonly WebApplicationFactory<Program> _traceHost;
    private readonly CapturingLoggerProvider _logs = new();
    private readonly HttpClient _client;

    public CredentialsNotInUrlTests(CustomWebApplicationFactory factory) : base(factory)
    {
        _traceHost = factory.WithWebHostBuilder(b => b.ConfigureLogging(l =>
        {
            l.SetMinimumLevel(LogLevel.Trace);
            l.AddFilter("Microsoft", LogLevel.Trace);
            l.AddFilter("Microsoft.AspNetCore", LogLevel.Trace);
            l.AddFilter("System", LogLevel.Trace);
            l.AddProvider(_logs);
        }));
        _client = _traceHost.CreateClient();
        _client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "test-token");
    }

    // ---------------------------------------------------------------- admin password reset

    [Fact]
    public async Task ResetPassword_WithBody_SetsThePassword_AndThePasswordIsInNoLogLine()
    {
        var ct = TestContext.Current.CancellationToken;
        var userName = NewUserName();
        await CreateTestUserAsync(userName, password: OldPassword);
        var newPassword = NewPassword();

        var response = await _client.PostAsJsonAsync(TenantApiUrl("users/ResetPassword"),
            new { userName, password = newPassword }, ct);

        response.StatusCode.Should().Be(HttpStatusCode.OK, await response.Content.ReadAsStringAsync(ct));
        (await LoginAndGetAuthenticatedClientAsync(userName, newPassword, ct)).Should().NotBeNull();
        _logs.AllText.Should().Contain("users/ResetPassword", "the request log runs at TRACE in this host");
        _logs.AllText.Should().Contain("Executing action method", "the TRACE log of the action arguments is on");
        _logs.AllText.Should().NotContain(newPassword);
    }

    [Fact]
    public async Task ResetPassword_WithPasswordInQuery_Is400WithUpdateHint_ChangesNothing_AndMasksThePasswordInTheLog()
    {
        var ct = TestContext.Current.CancellationToken;
        var userName = NewUserName();
        await CreateTestUserAsync(userName, password: OldPassword);
        var newPassword = NewPassword();

        // The request the shipped octo-cli/SDK and Refinery Studio sent before AB#8008: POST without a body.
        var response = await _client.PostAsync(TenantApiUrl(
                $"users/ResetPassword?userName={Uri.EscapeDataString(userName)}&password={Uri.EscapeDataString(newPassword)}"),
            null, ct);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        var body = await response.Content.ReadAsStringAsync(ct);
        body.Should().Contain("request body").And.Contain("octo-cli").And.NotContain(newPassword);
        (await LoginAndGetAuthenticatedClientAsync(userName, OldPassword, ct)).Should().NotBeNull("nothing changed");
        _logs.AllText.Should().Contain("password=***", "the request log keeps the parameter name, masks the value");
        _logs.AllText.Should().NotContain(newPassword).And.NotContain(Uri.EscapeDataString(newPassword));
    }

    [Fact]
    public async Task ResetPassword_WithBodyAndPasswordInQuery_IsRefusedToo()
    {
        var ct = TestContext.Current.CancellationToken;
        var userName = NewUserName();
        await CreateTestUserAsync(userName, password: OldPassword);
        var newPassword = NewPassword();

        var response = await _client.PostAsJsonAsync(TenantApiUrl($"users/ResetPassword?password={Uri.EscapeDataString(newPassword)}"),
            new { userName, password = newPassword }, ct);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await LoginAndGetAuthenticatedClientAsync(userName, OldPassword, ct)).Should().NotBeNull();
        _logs.AllText.Should().NotContain(newPassword);
    }

    [Fact]
    public async Task ResetPassword_WithPasswordInQuery_WithoutPermission_Is403_NotTheHint()
    {
        var ct = TestContext.Current.CancellationToken;
        var client = _traceHost.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "test-token");
        client.DefaultRequestHeaders.Add(TestAuthHandler.RoleHeader, "DashboardViewer");

        var response = await client.PostAsync(TenantApiUrl("users/ResetPassword?userName=x&password=y"), null, ct);

        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task ResetPassword_ByClientCredentialsCaller_AuditNamesTheClient()
    {
        var ct = TestContext.Current.CancellationToken;
        var userName = NewUserName();
        await CreateTestUserAsync(userName, password: OldPassword);
        var serviceClientId = $"svc-{Guid.NewGuid():N}";
        var client = _traceHost.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "test-token");
        client.DefaultRequestHeaders.Add(TestAuthHandler.ClientCredentialsHeader, serviceClientId);
        client.DefaultRequestHeaders.Add(TestAuthHandler.RoleHeader, "UserManagement");

        var response = await client.PostAsJsonAsync(TenantApiUrl("users/ResetPassword"),
            new { userName, password = NewPassword() }, ct);

        response.StatusCode.Should().Be(HttpStatusCode.OK, await response.Content.ReadAsStringAsync(ct));
        var audit = _logs.Lines.Select(l => l.Text).Where(t => t.StartsWith("Password changed:", StringComparison.Ordinal))
            .Should().ContainSingle(t => t.Contains("AdminResetPassword")).Subject;
        audit.Should().Contain($"acting user 'client {serviceClientId}'").And.NotContain("anonymous");
    }

    [Fact]
    public async Task ResetPassword_ByUser_AuditNamesTheUser()
    {
        var ct = TestContext.Current.CancellationToken;
        var userName = NewUserName();
        await CreateTestUserAsync(userName, password: OldPassword);
        var client = _traceHost.CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "test-token");
        client.DefaultRequestHeaders.Add(TestAuthHandler.CliUserTokenHeader, "true");
        client.DefaultRequestHeaders.Add(TestAuthHandler.UserNameHeader, "admin-8008");
        client.DefaultRequestHeaders.Add(TestAuthHandler.RoleHeader, "UserManagement");

        var response = await client.PostAsJsonAsync(TenantApiUrl("users/ResetPassword"),
            new { userName, password = NewPassword() }, ct);

        response.StatusCode.Should().Be(HttpStatusCode.OK, await response.Content.ReadAsStringAsync(ct));
        _logs.Lines.Select(l => l.Text)
            .Should().Contain(t => t.StartsWith("Password changed:", StringComparison.Ordinal) &&
                                   t.Contains("acting user 'admin-8008'"));
    }

    // ---------------------------------------------------------------- secret delete and lookup

    [Theory]
    [InlineData("client")]
    [InlineData("apiResource")]
    public async Task SecretLookupAndDelete_WithValueInBody_Work_AndTheValueIsInNoLogLine(string kind)
    {
        var ct = TestContext.Current.CancellationToken;
        var owner = kind == "client" ? await CreateMachineClientAsync() : await CreateApiResourceAsync();
        var (clear, hash) = await CreateSecretAsync(kind, owner);
        var (_, keptHash) = await CreateSecretAsync(kind, owner);
        _logs.Clear();

        var lookup = await _client.PostAsJsonAsync(TenantApiUrl($"apiSecrets/{kind}/{owner}/lookup"),
            new { valueEncrypted = hash }, ct);
        lookup.StatusCode.Should().Be(HttpStatusCode.OK);
        (await lookup.Content.ReadFromJsonAsync<JsonObject>(ct))!["valueEncrypted"]!.GetValue<string>().Should().Be(hash);

        var delete = await _client.PostAsJsonAsync(TenantApiUrl($"apiSecrets/{kind}/{owner}/delete"),
            new { valueEncrypted = hash }, ct);
        delete.StatusCode.Should().Be(HttpStatusCode.OK);

        var again = await _client.PostAsJsonAsync(TenantApiUrl($"apiSecrets/{kind}/{owner}/delete"),
            new { valueEncrypted = hash }, ct);
        again.StatusCode.Should().Be(HttpStatusCode.NotFound);
        (await again.Content.ReadAsStringAsync(ct)).Should().NotContain(hash);

        (await GetStoredSecretValuesAsync(kind, owner)).Should().BeEquivalentTo([keptHash]);
        _logs.AllText.Should().Contain($"apiSecrets/{kind}/{owner}/delete", "the request log runs at TRACE in this host");
        _logs.AllText.Should().NotContain(clear);
        _logs.AllText.Should().NotContain(hash).And.NotContain(hash.EncodeBase64());
        _logs.Lines.Should().NotContain(l => l.Text.StartsWith("Deprecated API secret request"));
    }

    [Theory]
    [InlineData("client")]
    [InlineData("apiResource")]
    public async Task SecretBodyVariants_WithoutValue_Are400(string kind)
    {
        var ct = TestContext.Current.CancellationToken;
        var owner = kind == "client" ? await CreateMachineClientAsync() : await CreateApiResourceAsync();

        (await _client.PostAsJsonAsync(TenantApiUrl($"apiSecrets/{kind}/{owner}/delete"), new { }, ct))
            .StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await _client.PostAsJsonAsync(TenantApiUrl($"apiSecrets/{kind}/{owner}/lookup"), new { }, ct))
            .StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Theory]
    [InlineData("client")]
    [InlineData("apiResource")]
    public async Task SecretBodyVariants_WithoutWritePermission_DeleteIs403_AndKeepsTheSecret(string kind)
    {
        var ct = TestContext.Current.CancellationToken;
        var owner = kind == "client" ? await CreateMachineClientAsync() : await CreateApiResourceAsync();
        var (_, hash) = await CreateSecretAsync(kind, owner);
        var reader = _traceHost.CreateClient();
        reader.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", "test-token");
        reader.DefaultRequestHeaders.Add(TestAuthHandler.RoleHeader, "DashboardViewer");

        (await reader.PostAsJsonAsync(TenantApiUrl($"apiSecrets/{kind}/{owner}/delete"), new { valueEncrypted = hash }, ct))
            .StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await GetStoredSecretValuesAsync(kind, owner)).Should().Contain(hash);
    }

    [Theory]
    [InlineData("client")]
    [InlineData("apiResource")]
    public async Task DeprecatedPathVariants_StillWork_WarnWithoutTheValue_AndTheValueIsMaskedInTheLog(string kind)
    {
        var ct = TestContext.Current.CancellationToken;
        var owner = kind == "client" ? await CreateMachineClientAsync() : await CreateApiResourceAsync();
        var (clear, hash) = await CreateSecretAsync(kind, owner);
        _logs.Clear();
        var segment = Uri.EscapeDataString(hash.EncodeBase64());

        // What octo-cli / the SDK before AB#8008 send.
        var get = await _client.GetAsync(TenantApiUrl($"apiSecrets/{kind}/{owner}/{segment}"), ct);
        get.StatusCode.Should().Be(HttpStatusCode.OK);
        var delete = await _client.DeleteAsync(TenantApiUrl($"apiSecrets/{kind}/{owner}/{segment}"), ct);
        delete.StatusCode.Should().Be(HttpStatusCode.OK);
        (await GetStoredSecretValuesAsync(kind, owner)).Should().NotContain(hash);

        var warnings = _logs.Lines.Where(l => l.Level == LogLevel.Warning && l.Text.StartsWith("Deprecated API secret request"))
            .ToList();
        warnings.Should().HaveCount(2);
        warnings.Should().OnlyContain(w => w.Text.Contains(owner));
        _logs.AllText.Should().Contain($"apiSecrets/{kind}/{owner}/***");
        _logs.Lines.Should().Contain(l => l.Text.StartsWith("scope: ") && l.Text.Contains($"RequestPath=/") &&
                                          l.Text.Contains($"apiSecrets/{kind}/{owner}/***"),
            "the hosting scope carries the masked request path");
        _logs.AllText.Should().NotContain(clear);
        _logs.AllText.Should().NotContain(hash).And.NotContain(hash.EncodeBase64()).And.NotContain(segment);
    }

    // ---------------------------------------------------------------- helpers

    private static string NewUserName() => $"cred8008_{Guid.NewGuid():N}";

    // A throwaway password per test; never written anywhere but the request body.
    private static string NewPassword() => $"Tw!{Convert.ToBase64String(RandomNumberGenerator.GetBytes(12))}9a";

    private async Task<(string ClearText, string Hash)> CreateSecretAsync(string kind, string owner)
    {
        var ct = TestContext.Current.CancellationToken;
        var response = await _client.PostAsJsonAsync(TenantApiUrl($"apiSecrets/{kind}/{owner}"), new { }, ct);
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var dto = (await response.Content.ReadFromJsonAsync<JsonObject>(ct))!;
        return (dto["valueClearText"]!.GetValue<string>(), dto["valueEncrypted"]!.GetValue<string>());
    }

    private async Task<List<string>> GetStoredSecretValuesAsync(string kind, string owner)
    {
        using var scope = CreateScope();
        if (kind == "client")
        {
            var client = await scope.ServiceProvider.GetRequiredService<IOctoClientStore>().FindRtClientByIdAsync(owner);
            return client!.ClientSecrets.Select(s => s.Value!).ToList();
        }

        var resource = await scope.ServiceProvider.GetRequiredService<IOctoResourceStore>().GetApiResourceByNameAsync(owner);
        return resource!.ApiSecrets?.Select(s => s.Value!).ToList() ?? [];
    }

    private async Task<string> CreateMachineClientAsync()
    {
        var clientId = $"cred8008-{Guid.NewGuid():N}";
        var client = new RtClientBuilder()
            .WithClientId(clientId)
            .WithClientName(clientId)
            .WithGrantTypes("client_credentials")
            .WithScopes("openid")
            .RequireClientSecret()
            .RequirePkce(false)
            .Build();
        using var scope = CreateScope();
        await scope.ServiceProvider.GetRequiredService<IOctoClientStore>().CreateAsync(client);
        return clientId;
    }

    private async Task<string> CreateApiResourceAsync()
    {
        var name = $"cred8008-res-{Guid.NewGuid():N}";
        using var scope = CreateScope();
        await scope.ServiceProvider.GetRequiredService<IOctoResourceStore>().CreateApiResourceAsync(
            new global::Persistence.IdentityCkModel.Generated.System.Identity.v3.RtApiResource
            {
                RtId = Meshmakers.Octo.ConstructionKit.Contracts.OctoObjectId.GenerateNewId(),
                Name = name,
                DisplayName = name,
                Enabled = true,
                ShowInDiscoveryDocument = true,
                Claims = new Meshmakers.Octo.Runtime.Contracts.RepositoryEntities.AttributeStringValueList(),
                Scopes = new Meshmakers.Octo.Runtime.Contracts.RepositoryEntities.AttributeStringValueList()
            });
        return name;
    }

    private sealed class CapturingLoggerProvider : ILoggerProvider
    {
        private readonly ConcurrentQueue<(LogLevel Level, string Text, string Category)> _lines = new();

        public IReadOnlyList<(LogLevel Level, string Text, string Category)> Lines => _lines.ToArray();

        // Message text, every structured value and the exception, as any provider could write them.
        public string AllText => string.Join('\n', _lines.Select(l => l.Text));

        public void Clear() => _lines.Clear();

        public ILogger CreateLogger(string categoryName) => new CapturingLogger(this, categoryName);

        public void Dispose()
        {
        }

        private sealed class CapturingLogger(CapturingLoggerProvider owner, string category) : ILogger
        {
            // Scopes are recorded as lines too: the hosting scope (RequestPath) is rendered into every record by nlog.config.
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull
            {
                var values = state is IEnumerable<KeyValuePair<string, object?>> list
                    ? string.Join("; ", list.Select(v => $"{v.Key}={v.Value}"))
                    : state.ToString();
                owner._lines.Enqueue((LogLevel.None, "scope: " + values, category));
                return null;
            }

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
                var values = state is IEnumerable<KeyValuePair<string, object?>> list
                    ? " | " + string.Join("; ", list.Select(v => $"{v.Key}={v.Value}"))
                    : string.Empty;
                owner._lines.Enqueue((logLevel, formatter(state, exception) + values + exception, category));
            }
        }
    }
}
