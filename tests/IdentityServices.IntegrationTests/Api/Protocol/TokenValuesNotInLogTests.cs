using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using FluentAssertions;
using IdentityServerPersistence.SystemStores;
using IdentityServices.IntegrationTests.Infrastructure;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.Protocol;

/// <summary>
///     AB#8324: an issued token never reaches a log line, also at log level Trace. OpenIddict writes EventId 6013
///     (<i>"A new '{Type}' JSON Web Token was successfully created: {Payload}."</i>) at Trace with the complete signed
///     token. The host of this class logs everything at <see cref="LogLevel.Trace" /> into a capturing provider behind the
///     service's real (redacting) logger factory, issues a real <c>client_credentials</c> token and searches the message
///     text, every structured value and every scope for the token, its signature and the client secret.
/// </summary>
/// <remarks>
///     The token is only compared, never printed: the assertions are booleans, so a red run does not write the token
///     (or the captured log) into the test output.
/// </remarks>
public class TokenValuesNotInLogTests : IntegrationTestBase, IDisposable
{
    private const string ApiScope = "token-log-redaction-api";
    private const int JwtCreatedEventId = 6013;

    private readonly WebApplicationFactory<Program> _traceHost;
    private readonly CapturingLoggerProvider _logs = new();

    public TokenValuesNotInLogTests(CustomWebApplicationFactory factory) : base(factory)
    {
        _traceHost = factory.WithWebHostBuilder(b => b.ConfigureLogging(l =>
        {
            l.SetMinimumLevel(LogLevel.Trace);
            l.AddFilter("OpenIddict", LogLevel.Trace);
            l.AddFilter("Microsoft", LogLevel.Trace);
            l.AddFilter("System", LogLevel.Trace);
            l.AddProvider(_logs);
        }));
    }

    public void Dispose()
    {
        _traceHost.Dispose();
        GC.SuppressFinalize(this);
    }

    [Fact]
    public async Task ClientCredentialsToken_AtTrace_IsInNoLogLine_AndTheJwtCreatedLineStaysMasked()
    {
        var ct = TestContext.Current.CancellationToken;
        var clientId = $"ab8324-{Guid.NewGuid():N}";
        var secret = $"FAKE-secret-AB8324-{Guid.NewGuid():N}";
        await EnsureApiScopeAsync();
        await CreateClientAsync(clientId, secret);

        using var http = _traceHost.CreateClient();
        var response = await http.PostAsync("/connect/token", new FormUrlEncodedContent(
            new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = clientId,
                ["client_secret"] = secret,
                ["scope"] = ApiScope,
                ["acr_values"] = $"tenant:{NormalizedSystemTenantId}"
            }), ct);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var accessToken = JsonNode.Parse(await response.Content.ReadAsStringAsync(ct))!["access_token"]!
            .GetValue<string>();
        accessToken.Split('.').Should().HaveCount(3, "a plain signed JWT (DisableAccessTokenEncryption)");
        var signature = accessToken.Split('.')[2];

        var lines = _logs.Lines;
        lines.Any(l => l.EventId == JwtCreatedEventId).Should()
            .BeTrue("OpenIddict logs the created token at Trace (EventId 6013) - the test must see that line");
        lines.Where(l => l.EventId == JwtCreatedEventId)
            .All(l => l.Text.Contains("JSON Web Token was successfully created: " + "***", StringComparison.Ordinal))
            .Should().BeTrue("the line stays, with the token masked");

        var all = _logs.AllText;
        all.Contains(accessToken, StringComparison.Ordinal).Should().BeFalse("the access token must not be logged");
        all.Contains(signature, StringComparison.Ordinal).Should().BeFalse("the token signature must not be logged");
        all.Contains(secret, StringComparison.Ordinal).Should().BeFalse("the client secret must not be logged");
    }

    private async Task EnsureApiScopeAsync()
    {
        using var scope = CreateScope();
        var resourceStore = scope.ServiceProvider.GetRequiredService<IOctoResourceStore>();
        if (await resourceStore.GetApiScopeByNameAsync(ApiScope) == null)
        {
            await resourceStore.CreateApiScopeAsync(new RtApiScope
            {
                RtId = OctoObjectId.GenerateNewId(),
                Name = ApiScope,
                DisplayName = "Token log redaction API",
                Enabled = true,
                ShowInDiscoveryDocument = true,
                Claims = new AttributeStringValueList(),
                IsEmphasized = false,
                IsRequired = false
            });
        }
    }

    private async Task CreateClientAsync(string clientId, string secret)
    {
        using var scope = CreateScope();
        var client = new RtClientBuilder()
            .WithClientId(clientId)
            .WithClientName(clientId)
            .WithGrantTypes("client_credentials")
            .WithScopes(ApiScope)
            .WithSecret("SharedSecret", Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(secret))))
            .RequireClientSecret()
            .RequirePkce(false)
            .Build();
        await scope.ServiceProvider.GetRequiredService<IOctoClientStore>().CreateAsync(client);
    }

    private sealed class CapturingLoggerProvider : ILoggerProvider
    {
        private readonly ConcurrentQueue<(int EventId, string Text)> _lines = new();

        public IReadOnlyList<(int EventId, string Text)> Lines => _lines.ToArray();

        // Message text, every structured value, every scope and the exception, as any provider could write them.
        public string AllText => string.Join('\n', _lines.Select(l => l.Text));

        public ILogger CreateLogger(string categoryName) => new CapturingLogger(this);

        public void Dispose()
        {
        }

        private sealed class CapturingLogger(CapturingLoggerProvider owner) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull
            {
                var values = state is IEnumerable<KeyValuePair<string, object?>> list
                    ? string.Join("; ", list.Select(v => $"{v.Key}={v.Value}"))
                    : state.ToString();
                owner._lines.Enqueue((0, "scope: " + values));
                return null;
            }

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
                var values = state is IEnumerable<KeyValuePair<string, object?>> list
                    ? " | " + string.Join("; ", list.Select(v => $"{v.Key}={v.Value}"))
                    : string.Empty;
                owner._lines.Enqueue((eventId.Id, formatter(state, exception) + values + exception));
            }
        }
    }
}
