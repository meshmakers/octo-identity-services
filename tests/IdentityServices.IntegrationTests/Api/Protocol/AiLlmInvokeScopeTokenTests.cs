using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using System.Web;
using FluentAssertions;
using IdentityServerPersistence.SystemStores;
using IdentityServices.IntegrationTests.Infrastructure;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Shared.TestUtilities.Builders;
using Xunit;
using YamlDotNet.RepresentationModel;

namespace IdentityServices.IntegrationTests.Api.Protocol;

/// <summary>
///     The LLM gateway scope <c>ai.llm.invoke</c> on the wire: a client-credentials client that allows it (the shape of a
///     pipeline service account and of the AI service's client-credentials client) gets it when it asks for it, with the
///     audience the AI service validates (<c>octoAPI</c>); a client that does not allow it (every client of
///     <c>System.Identity.Bootstrap</c>, so every user login) is refused when it asks for it. Scope and resource are
///     created from the shipped seed files, because the HTTP fixture does not apply the blueprint.
/// </summary>
public class AiLlmInvokeScopeTokenTests : IntegrationTestBase
{
    private const string LlmScope = "ai.llm.invoke";
    private const string PlatformScope = "octo_api";
    private const string Audience = "octoAPI";
    private const string MachineSecret = "llm-invoke-machine-secret";
    private const string RedirectUri = "https://llm-invoke.example/callback";

    public AiLlmInvokeScopeTokenTests(CustomWebApplicationFactory factory) : base(factory)
    {
    }

    [Theory]
    [InlineData("octo-pipeline-sa-llm-invoke-test")]
    [InlineData("octo-ai-adapter")]
    public async Task ClientCredentials_ClientThatAllowsTheScope_GetsItWithTheAiServiceAudience(string clientId)
    {
        var ct = TestContext.Current.CancellationToken;
        await EnsureSeededScopeAndResourceAsync();
        await EnsureMachineClientAsync(clientId, PlatformScope, LlmScope);

        var response = await RequestClientCredentialsTokenAsync(clientId, $"{PlatformScope} {LlmScope}", ct);

        var raw = await response.Content.ReadAsStringAsync(ct);
        response.StatusCode.Should().Be(HttpStatusCode.OK, "token request failed: {0}", raw);
        var token = ReadAccessToken(raw);
        Scopes(token).Should().Contain([LlmScope, PlatformScope]);
        token.Audiences.Should().Contain(Audience, "the AI service validates the audience octoAPI");
        token.TryGetClaim("tenant_id", out var tenant).Should().BeTrue("the gateway takes the tenant from the token");
        tenant.Value.Should().Be(NormalizedSystemTenantId);
    }

    [Fact]
    public async Task ClientCredentials_ClientThatAllowsTheScope_DoesNotGetItWithoutAskingForIt()
    {
        var ct = TestContext.Current.CancellationToken;
        await EnsureSeededScopeAndResourceAsync();
        const string clientId = "octo-pipeline-sa-llm-invoke-unasked";
        await EnsureMachineClientAsync(clientId, PlatformScope, LlmScope);

        var response = await RequestClientCredentialsTokenAsync(clientId, PlatformScope, ct);

        var raw = await response.Content.ReadAsStringAsync(ct);
        response.StatusCode.Should().Be(HttpStatusCode.OK, "token request failed: {0}", raw);
        Scopes(ReadAccessToken(raw)).Should().NotContain(LlmScope,
            "a token carries the gateway scope only when the client asks for it");
    }

    [Fact]
    public async Task ClientCredentials_ClientWithoutTheScope_IsRefusedWhenItAsksForIt()
    {
        var ct = TestContext.Current.CancellationToken;
        await EnsureSeededScopeAndResourceAsync();
        const string clientId = "llm-invoke-platform-only-machine";
        await EnsureMachineClientAsync(clientId, PlatformScope);

        var response = await RequestClientCredentialsTokenAsync(clientId, $"{PlatformScope} {LlmScope}", ct);

        response.IsSuccessStatusCode.Should().BeFalse();
        await AssertScopeNotPermittedAsync(response, ct);
    }

    /// <summary>
    ///     The consumers that grant the scope (Communication Controller, AI service) may roll out before the identity
    ///     service that registers it: a client that allows a scope not registered yet still gets its other scopes, and
    ///     only a request for the missing scope is refused.
    /// </summary>
    [Fact]
    public async Task ClientCredentials_AllowedScopeNotRegisteredYet_LeavesTheOtherScopesWorking()
    {
        var ct = TestContext.Current.CancellationToken;
        await EnsureSeededScopeAndResourceAsync();
        const string unregistered = "ai.llm.not-registered";
        const string clientId = "octo-pipeline-sa-llm-invoke-early";
        await EnsureMachineClientAsync(clientId, PlatformScope, unregistered);

        var platformOnly = await RequestClientCredentialsTokenAsync(clientId, PlatformScope, ct);
        var withMissing = await RequestClientCredentialsTokenAsync(clientId, $"{PlatformScope} {unregistered}", ct);

        platformOnly.StatusCode.Should().Be(HttpStatusCode.OK, await platformOnly.Content.ReadAsStringAsync(ct));
        (await ReadProtocolErrorAsync(withMissing, ct)).Should().Be("invalid_scope");
    }

    /// <summary>
    ///     A user logs in only through an interactive client of the blueprint. Each such client keeps its seeded scope
    ///     list, so an authorize request that asks for the gateway scope is refused before a code is issued.
    /// </summary>
    [Theory]
    [InlineData("refinery-studio.yaml", "octo-data-refinery-studio")]
    [InlineData("identity-swagger.yaml", "octo-idenityServices-swagger")]
    [InlineData("mcp.yaml", "octo-mcpServices-swagger")]
    [InlineData("platform-swagger.yaml", "octo-platformServices-swagger")]
    public async Task UserLogin_ThroughASeededInteractiveClient_CannotObtainTheScope(string seedFile, string seedClientId)
    {
        var ct = TestContext.Current.CancellationToken;
        await EnsureSeededScopeAndResourceAsync();
        var seededScopes = SeededClientScopes(seedFile, seedClientId);
        var clientId = $"llm-invoke-{seedClientId}";
        await EnsureInteractiveClientAsync(clientId, seededScopes);
        var browser = await LoginAsync(ct);

        var refused = await browser.GetAsync(AuthorizeUrl(clientId, $"openid {PlatformScope} {LlmScope}"), ct);
        var allowed = await browser.GetAsync(AuthorizeUrl(clientId, $"openid {PlatformScope}"), ct);

        await AssertScopeNotPermittedAsync(refused, ct);
        (await ReadProtocolErrorAsync(allowed, ct)).Should().BeNull(
            "the same client still issues its seeded scopes, so the refusal above is about the gateway scope");
    }

    /// <summary>The device flow of octo-cli and of the MCP device client refuses the scope as well.</summary>
    [Theory]
    [InlineData("octo-tool.yaml", "octo-cli")]
    [InlineData("mcp.yaml", "octo-mcpServices-device")]
    public async Task DeviceFlow_ThroughASeededDeviceClient_CannotObtainTheScope(string seedFile, string seedClientId)
    {
        var ct = TestContext.Current.CancellationToken;
        await EnsureSeededScopeAndResourceAsync();
        var clientId = $"llm-invoke-{seedClientId}";
        await EnsureDeviceClientAsync(clientId, SeededClientScopes(seedFile, seedClientId));

        var response = await CreateAnonymousClient().PostAsync("/connect/deviceauthorization",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["client_id"] = clientId,
                ["scope"] = $"openid {PlatformScope} {LlmScope}",
                ["acr_values"] = $"tenant:{NormalizedSystemTenantId}"
            }), ct);

        await AssertScopeNotPermittedAsync(response, ct);
    }

    #region Arrange helpers

    /// <summary>
    ///     Creates <c>ai.llm.invoke</c>, <c>octo_api</c> and <c>octoAPI</c> as the shipped seed defines them (an
    ///     existing <c>octoAPI</c> gets the seeded scope list). Idempotent per factory.
    /// </summary>
    private async Task EnsureSeededScopeAndResourceAsync()
    {
        using var scope = CreateScope();
        var store = scope.ServiceProvider.GetRequiredService<IOctoResourceStore>();

        foreach (var name in new[] { PlatformScope, LlmScope })
        {
            var seeded = SeedEntity("api-scopes.yaml", name);
            if (await store.GetApiScopeByNameAsync(name) == null)
            {
                await store.CreateApiScopeAsync(new RtApiScope
                {
                    RtId = new OctoObjectId(Scalar(seeded, "rtId")!),
                    Name = name,
                    DisplayName = AttributeScalar(seeded, "System/DisplayName"),
                    Enabled = AttributeScalar(seeded, "System/Enabled") == "true",
                    ShowInDiscoveryDocument = AttributeScalar(seeded, "System.Identity/ShowInDiscoveryDocument") == "true",
                    Claims = new AttributeStringValueList(),
                    IsEmphasized = false,
                    IsRequired = false
                });
            }
        }

        var seededScopes = AttributeList(SeedEntity("api-resources.yaml", Audience), "System.Identity/Scopes");
        seededScopes.Should().Contain(LlmScope, "the shipped seed attaches the scope to octoAPI");
        if (await store.GetApiResourceByNameAsync(Audience) == null)
        {
            await store.CreateApiResourceAsync(new RtApiResource
            {
                RtId = OctoObjectId.GenerateNewId(),
                Name = Audience,
                DisplayName = Audience,
                Enabled = true,
                ShowInDiscoveryDocument = true,
                Claims = new AttributeStringValueList(),
                Scopes = new AttributeStringValueList(seededScopes)
            });
        }
        else
        {
            await store.MutateApiResourceAsync(Audience, resource =>
            {
                resource.Scopes = new AttributeStringValueList(seededScopes);
                return true;
            });
        }
    }

    private async Task EnsureMachineClientAsync(string clientId, params string[] scopes)
    {
        await EnsureClientAsync(clientId, builder => builder
            .WithGrantTypes("client_credentials")
            .WithScopes(scopes)
            .WithSecret("SharedSecret", Sha256Base64(MachineSecret))
            .RequireClientSecret()
            .RequirePkce(false));
    }

    private async Task EnsureInteractiveClientAsync(string clientId, IReadOnlyList<string> scopes)
    {
        await EnsureClientAsync(clientId, builder => builder
            .WithGrantTypes("authorization_code")
            .WithScopes(scopes.ToArray())
            .WithRedirectUris(RedirectUri)
            .RequirePkce());
    }

    private async Task EnsureDeviceClientAsync(string clientId, IReadOnlyList<string> scopes)
    {
        await EnsureClientAsync(clientId, builder => builder
            .WithGrantTypes("urn:ietf:params:oauth:grant-type:device_code")
            .WithScopes(scopes.ToArray()));
    }

    private async Task EnsureClientAsync(string clientId, Action<RtClientBuilder> configure)
    {
        using var scope = CreateScope();
        var clientStore = scope.ServiceProvider.GetRequiredService<IOctoClientStore>();
        if (await clientStore.FindRtClientByIdAsync(clientId) != null)
        {
            return;
        }

        var builder = new RtClientBuilder().WithClientId(clientId).WithClientName(clientId);
        configure(builder);
        await clientStore.CreateAsync(builder.Build());
    }

    private async Task<HttpClient> LoginAsync(CancellationToken ct)
    {
        const string userName = "llminvokeuser";
        using (var scope = CreateScope())
        {
            var userStore = scope.ServiceProvider.GetRequiredService<Microsoft.AspNetCore.Identity.UserManager<RtUser>>();
            if (await userStore.FindByNameAsync(userName) == null)
            {
                await CreateTestUserAsync(userName, $"{userName}@example.com");
            }
        }

        var browser = await LoginAndGetAuthenticatedClientAsync(userName, DefaultPassword, ct);
        browser.Should().NotBeNull("cookie login must succeed to drive the authorize flow");
        return browser!;
    }

    private Task<HttpResponseMessage> RequestClientCredentialsTokenAsync(string clientId, string scope,
        CancellationToken ct) =>
        CreateAnonymousClient().PostAsync("/connect/token", new FormUrlEncodedContent(
            new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = clientId,
                ["client_secret"] = MachineSecret,
                ["scope"] = scope,
                ["acr_values"] = $"tenant:{NormalizedSystemTenantId}"
            }), ct);

    private string AuthorizeUrl(string clientId, string scope) =>
        "/connect/authorize" +
        $"?client_id={clientId}" +
        $"&redirect_uri={Uri.EscapeDataString(RedirectUri)}" +
        "&response_type=code" +
        $"&scope={Uri.EscapeDataString(scope)}" +
        "&state=llm-invoke-state" +
        "&nonce=llm-invoke-nonce" +
        $"&code_challenge={Base64UrlSha256("llm-invoke-code-verifier-0123456789-0123456789")}" +
        "&code_challenge_method=S256" +
        $"&acr_values={Uri.EscapeDataString($"tenant:{NormalizedSystemTenantId}")}";

    #endregion

    #region Reading

    /// <summary>
    ///     OpenIddict refuses a registered scope the client has no permission for with <c>invalid_request</c> and the
    ///     description "not allowed to use the specified scope" (an unregistered scope gives <c>invalid_scope</c>).
    /// </summary>
    private static async Task AssertScopeNotPermittedAsync(HttpResponseMessage response, CancellationToken ct)
    {
        (await ReadProtocolErrorAsync(response, ct)).Should().Be("invalid_request");
        (await ReadProtocolErrorDescriptionAsync(response, ct)).Should().Contain("not allowed to use the specified scope");
    }

    private static async Task<string?> ReadProtocolErrorDescriptionAsync(HttpResponseMessage response,
        CancellationToken ct)
    {
        if (response.Headers.Location is { } location)
        {
            return HttpUtility.ParseQueryString(location.Query)["error_description"];
        }

        var raw = await response.Content.ReadAsStringAsync(ct);
        if (raw.TrimStart().StartsWith('{'))
        {
            return JsonNode.Parse(raw)?["error_description"]?.GetValue<string>();
        }

        var line = raw.Split('\n')
            .FirstOrDefault(l => l.StartsWith("error_description:", StringComparison.Ordinal));
        return line?["error_description:".Length..].Trim() ?? raw;
    }

    private static JsonWebToken ReadAccessToken(string tokenResponse) =>
        new JsonWebTokenHandler().ReadJsonWebToken(JsonNode.Parse(tokenResponse)!["access_token"]!.GetValue<string>());

    private static IReadOnlyList<string> Scopes(JsonWebToken token) =>
        token.Claims.Where(c => c.Type == "scope")
            .SelectMany(c => c.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            .ToList();

    /// <summary>The OAuth error of a response, from a JSON body or the redirect query; <c>null</c> when not refused.</summary>
    private static async Task<string?> ReadProtocolErrorAsync(HttpResponseMessage response, CancellationToken ct)
    {
        if (response.Headers.Location is { } location)
        {
            return HttpUtility.ParseQueryString(location.Query)["error"];
        }

        var raw = await response.Content.ReadAsStringAsync(ct);
        if (string.IsNullOrWhiteSpace(raw))
        {
            return response.IsSuccessStatusCode ? null : $"<{(int)response.StatusCode}> (empty body)";
        }

        if (raw.TrimStart().StartsWith('{'))
        {
            return JsonNode.Parse(raw)?["error"]?.GetValue<string>();
        }

        var errorLine = raw.Split('\n').FirstOrDefault(line => line.StartsWith("error:", StringComparison.Ordinal));
        return errorLine is not null
            ? errorLine["error:".Length..].Trim()
            : $"<{(int)response.StatusCode}> {raw}";
    }

    private static IReadOnlyList<string> SeededClientScopes(string seedFile, string clientId)
    {
        var client = Entities(Path.Combine("clients", seedFile))
            .Single(e => AttributeScalar(e, "System.Identity/ClientId") == clientId);
        var scopes = AttributeList(client, "System.Identity/AllowedScopes");
        scopes.Should().Contain(PlatformScope).And.NotContain(LlmScope);
        return scopes;
    }

    private static YamlMappingNode SeedEntity(string seedFile, string wellKnownName) =>
        Entities(seedFile).Single(e => Scalar(e, "rtWellKnownName") == wellKnownName);

    private static IEnumerable<YamlMappingNode> Entities(string seedFile)
    {
        using var reader = new StreamReader(Path.Combine(SeedDirectory(), seedFile));
        var stream = new YamlStream();
        stream.Load(reader);
        var root = (YamlMappingNode)stream.Documents[0].RootNode;
        return ((YamlSequenceNode)root.Children[new YamlScalarNode("entities")]).Children.OfType<YamlMappingNode>()
            .ToList();
    }

    private static YamlNode? Attribute(YamlMappingNode entity, string attributeId) =>
        ((YamlSequenceNode)entity.Children[new YamlScalarNode("attributes")]).Children.OfType<YamlMappingNode>()
        .Where(a => Scalar(a, "id") == attributeId)
        .Select(a => a.Children[new YamlScalarNode("value")])
        .SingleOrDefault();

    private static string? AttributeScalar(YamlMappingNode entity, string attributeId) =>
        (Attribute(entity, attributeId) as YamlScalarNode)?.Value;

    private static List<string> AttributeList(YamlMappingNode entity, string attributeId) =>
        Attribute(entity, attributeId) is YamlSequenceNode sequence
            ? sequence.Children.OfType<YamlScalarNode>().Select(n => n.Value!).ToList()
            : [];

    private static string? Scalar(YamlMappingNode node, string key) =>
        node.Children.TryGetValue(new YamlScalarNode(key), out var value) ? (value as YamlScalarNode)?.Value : null;

    private static string SeedDirectory()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null && !File.Exists(Path.Combine(dir.FullName, "Octo.Identity.sln")))
        {
            dir = dir.Parent;
        }

        return dir == null
            ? throw new FileNotFoundException("Octo.Identity.sln not found above the test binaries.")
            : Path.Combine(dir.FullName, "src", "Persistence.IdentityCkModel", "Blueprints", "System.Identity.Bootstrap",
                "seed-data");
    }

    private static string Sha256Base64(string value) =>
        Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    private static string Base64UrlSha256(string value) =>
        Convert.ToBase64String(SHA256.HashData(Encoding.ASCII.GetBytes(value)))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');

    #endregion
}
