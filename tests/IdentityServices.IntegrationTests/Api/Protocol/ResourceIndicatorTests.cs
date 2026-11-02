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
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.Protocol;

/// <summary>
///     AB#5193: RFC 8707 resource indicators on all three endpoints that accept them — authorize,
///     pushed authorize and token. OpenIddict 7.x validates the <c>resource</c> parameter against
///     a static allow-list that a multi-tenant server cannot fill, so every indicator was rejected
///     with <c>invalid_target</c> and interactive MCP clients could not log in at all. These tests
///     pin the store-backed replacement: a resource registered for the tenant is accepted (in
///     either slash spelling), an unregistered or disabled one is still refused.
/// </summary>
public class ResourceIndicatorTests : IntegrationTestBase
{
    private const string ApiScopeName = "resource-indicator-api";

    /// <summary>Seeded WITH a trailing slash, like <c>System.Identity.Bootstrap</c> seeds the MCP resource.</summary>
    private const string RegisteredResource = "https://resource-indicator.example/mcp/";

    private const string RegisteredResourceWithoutSlash = "https://resource-indicator.example/mcp";
    private const string DisabledResource = "https://resource-indicator.example/disabled/";
    private const string UnknownResource = "https://resource-indicator.example/nope/";

    private const string ClientId = "resource-indicator-spa";
    private const string RedirectUri = "https://resource-indicator.example/callback";

    public ResourceIndicatorTests(CustomWebApplicationFactory factory) : base(factory)
    {
    }

    [Theory]
    [InlineData(RegisteredResource)]
    [InlineData(RegisteredResourceWithoutSlash)]
    public async Task Authorize_WithRegisteredResource_IssuesCode(string resource)
    {
        var ct = TestContext.Current.CancellationToken;
        var browser = await PrepareInteractiveClientAsync(ct);

        var response = await browser.GetAsync(AuthorizeUrl(resource), ct);

        (await ReadProtocolErrorAsync(response, ct)).Should().BeNull(
            "the resource is registered for this tenant — in either slash spelling");
        response.Headers.Location!.ToString().Should().StartWith(RedirectUri);
        HttpUtility.ParseQueryString(response.Headers.Location!.Query)["code"].Should().NotBeNullOrEmpty();
    }

    [Theory]
    [InlineData(UnknownResource)]
    [InlineData(DisabledResource)]
    public async Task Authorize_WithUnusableResource_IsRejected(string resource)
    {
        var ct = TestContext.Current.CancellationToken;
        var browser = await PrepareInteractiveClientAsync(ct);

        var response = await browser.GetAsync(AuthorizeUrl(resource), ct);

        (await ReadProtocolErrorAsync(response, ct)).Should().Be("invalid_target",
            "unregistered and disabled resources must stay refused");
    }

    /// <summary>
    ///     An indicator narrows the request to an API resource, so it must relate to the scopes
    ///     being asked for — the pre-migration rule, and what replaces OpenIddict's per-client
    ///     resource permission (ID2192), which the CK model cannot express.
    /// </summary>
    [Fact]
    public async Task Authorize_WithResourceUnrelatedToRequestedScopes_IsRejected()
    {
        var ct = TestContext.Current.CancellationToken;
        var browser = await PrepareInteractiveClientAsync(ct);

        var response = await browser.GetAsync(AuthorizeUrl(RegisteredResource, scope: "openid"), ct);

        (await ReadProtocolErrorAsync(response, ct)).Should().Be("invalid_target",
            "the registered resource carries none of the requested scopes");
    }

    [Fact]
    public async Task PushedAuthorization_WithRegisteredResource_IsAccepted()
    {
        var ct = TestContext.Current.CancellationToken;
        await PrepareInteractiveClientAsync(ct);

        var response = await CreateAnonymousClient().PostAsync("/connect/par",
            new FormUrlEncodedContent(PushedRequest(RegisteredResource)), ct);

        var raw = await response.Content.ReadAsStringAsync(ct);
        response.StatusCode.Should().Be(HttpStatusCode.Created, "pushing the request must not fail: {0}", raw);
        JsonNode.Parse(raw)!["request_uri"].Should().NotBeNull();
    }

    [Fact]
    public async Task PushedAuthorization_WithUnknownResource_IsRejected()
    {
        var ct = TestContext.Current.CancellationToken;
        await PrepareInteractiveClientAsync(ct);

        var response = await CreateAnonymousClient().PostAsync("/connect/par",
            new FormUrlEncodedContent(PushedRequest(UnknownResource)), ct);

        (await ReadProtocolErrorAsync(response, ct)).Should().Be("invalid_target");
    }

    /// <summary>
    ///     The failure Claude Code actually hit: an existing session dies at the next silent
    ///     renewal because the refresh request carries the resource indicator too.
    /// </summary>
    [Fact]
    public async Task TokenAndRefresh_WithRegisteredResource_Succeed()
    {
        var ct = TestContext.Current.CancellationToken;
        var browser = await PrepareInteractiveClientAsync(ct);

        var authorizeResponse = await browser.GetAsync(AuthorizeUrl(RegisteredResource), ct);
        var code = HttpUtility.ParseQueryString(authorizeResponse.Headers.Location!.Query)["code"];
        code.Should().NotBeNullOrEmpty("the authorize step must succeed before the token step can be tested");

        var tokenClient = CreateAnonymousClient();
        var tokenResponse = await tokenClient.PostAsync("/connect/token", new FormUrlEncodedContent(
            new Dictionary<string, string>
            {
                ["grant_type"] = "authorization_code",
                ["client_id"] = ClientId,
                ["code"] = code!,
                ["redirect_uri"] = RedirectUri,
                ["code_verifier"] = Pkce.Verifier,
                ["resource"] = RegisteredResource
            }), ct);

        var raw = await tokenResponse.Content.ReadAsStringAsync(ct);
        tokenResponse.StatusCode.Should().Be(HttpStatusCode.OK, "code redemption failed: {0}", raw);
        var refreshToken = JsonNode.Parse(raw)!["refresh_token"]!.GetValue<string>();

        var refreshResponse = await tokenClient.PostAsync("/connect/token", new FormUrlEncodedContent(
            new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["client_id"] = ClientId,
                ["refresh_token"] = refreshToken,
                ["resource"] = RegisteredResource,
                ["acr_values"] = $"tenant:{NormalizedSystemTenantId}"
            }), ct);

        var refreshRaw = await refreshResponse.Content.ReadAsStringAsync(ct);
        refreshResponse.StatusCode.Should().Be(HttpStatusCode.OK,
            "the silent renewal must not fail on the resource indicator: {0}", refreshRaw);
        JsonNode.Parse(refreshRaw)!["access_token"].Should().NotBeNull();
    }

    [Fact]
    public async Task Token_WithUnknownResource_IsRejected()
    {
        var ct = TestContext.Current.CancellationToken;
        await PrepareInteractiveClientAsync(ct);

        var response = await CreateAnonymousClient().PostAsync("/connect/token", new FormUrlEncodedContent(
            new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["client_id"] = ClientId,
                ["refresh_token"] = "does-not-matter-rejected-before-redemption",
                ["resource"] = UnknownResource,
                ["acr_values"] = $"tenant:{NormalizedSystemTenantId}"
            }), ct);

        (await ReadProtocolErrorAsync(response, ct)).Should().Be("invalid_target");
    }

    [Fact]
    public async Task Authorize_WithoutResourceParameter_IsUnaffected()
    {
        var ct = TestContext.Current.CancellationToken;
        var browser = await PrepareInteractiveClientAsync(ct);

        var response = await browser.GetAsync(AuthorizeUrl(resource: null), ct);

        (await ReadProtocolErrorAsync(response, ct)).Should().BeNull(
            "flows without a resource indicator (octo-cli device flow, Refinery Studio) must stay untouched");
    }

    /// <summary>
    ///     Without <c>acr_values</c> the tenant-resolution middleware answers with a redirect back
    ///     to the authorize endpoint, so every request here carries the tenant explicitly.
    /// </summary>
    private string AuthorizeUrl(string? resource, string? scope = null)
        => "/connect/authorize" +
           $"?client_id={ClientId}" +
           $"&redirect_uri={Uri.EscapeDataString(RedirectUri)}" +
           "&response_type=code" +
           $"&scope={Uri.EscapeDataString(scope ?? $"openid offline_access {ApiScopeName}")}" +
           "&state=resource-indicator-state" +
           "&nonce=resource-indicator-nonce" +
           $"&code_challenge={Pkce.Challenge}" +
           "&code_challenge_method=S256" +
           (resource is null ? string.Empty : $"&resource={Uri.EscapeDataString(resource)}") +
           $"&acr_values={Uri.EscapeDataString($"tenant:{NormalizedSystemTenantId}")}";

    private Dictionary<string, string> PushedRequest(string resource) => new()
    {
        ["client_id"] = ClientId,
        ["redirect_uri"] = RedirectUri,
        ["response_type"] = "code",
        ["scope"] = $"openid offline_access {ApiScopeName}",
        ["state"] = "resource-indicator-state",
        ["nonce"] = "resource-indicator-nonce",
        ["code_challenge"] = Pkce.Challenge,
        ["code_challenge_method"] = "S256",
        ["resource"] = resource,
        ["acr_values"] = $"tenant:{NormalizedSystemTenantId}"
    };

    /// <summary>
    ///     Reads the OAuth error of a response regardless of how the endpoint delivers it — as a
    ///     JSON body, or in the query of the redirect back to the client. Returns <c>null</c> when
    ///     the request was not rejected.
    /// </summary>
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

        // The authorize endpoint renders its errors as plain "key:value" lines when it cannot
        // redirect them back to the client.
        var errorLine = raw.Split('\n').FirstOrDefault(line => line.StartsWith("error:", StringComparison.Ordinal));
        return errorLine is not null
            ? errorLine["error:".Length..].Trim()
            : $"<{(int)response.StatusCode}> {raw}";
    }

    /// <summary>Seeds scope, resources, client and user, then logs the user in. Idempotent per factory.</summary>
    private async Task<HttpClient> PrepareInteractiveClientAsync(CancellationToken ct)
    {
        using (var scope = CreateScope())
        {
            var resourceStore = scope.ServiceProvider.GetRequiredService<IOctoResourceStore>();

            if (await resourceStore.GetApiScopeByNameAsync(ApiScopeName) == null)
            {
                await resourceStore.CreateApiScopeAsync(new RtApiScope
                {
                    RtId = OctoObjectId.GenerateNewId(),
                    Name = ApiScopeName,
                    DisplayName = "Resource Indicator API",
                    Enabled = true,
                    ShowInDiscoveryDocument = true,
                    Claims = new AttributeStringValueList(),
                    IsEmphasized = false,
                    IsRequired = false
                });
            }

            await EnsureApiResourceAsync(resourceStore, RegisteredResource, enabled: true);
            await EnsureApiResourceAsync(resourceStore, DisabledResource, enabled: false);
        }

        using (var scope = CreateScope())
        {
            var clientStore = scope.ServiceProvider.GetRequiredService<IOctoClientStore>();
            if (await clientStore.FindRtClientByIdAsync(ClientId) == null)
            {
                await clientStore.CreateAsync(new RtClientBuilder()
                    .WithClientId(ClientId)
                    .WithClientName(ClientId)
                    .WithGrantTypes("authorization_code", "refresh_token")
                    .WithScopes("openid", "offline_access", ApiScopeName)
                    .WithRedirectUris(RedirectUri)
                    .WithAllowOfflineAccess()
                    .RequirePkce()
                    .Build());
            }
        }

        const string userName = "resourceindicatoruser";
        if (await GetUserAsync(userName) == null)
        {
            await CreateTestUserAsync(userName, $"{userName}@example.com");
        }

        var browser = await LoginAndGetAuthenticatedClientAsync(userName, DefaultPassword, ct);
        browser.Should().NotBeNull("cookie login must succeed to drive the authorize flow");
        return browser!;
    }

    private static async Task EnsureApiResourceAsync(IOctoResourceStore resourceStore, string name, bool enabled)
    {
        if (await resourceStore.GetApiResourceByNameAsync(name) != null)
        {
            return;
        }

        await resourceStore.CreateApiResourceAsync(new RtApiResource
        {
            RtId = OctoObjectId.GenerateNewId(),
            Name = name,
            DisplayName = name,
            Enabled = enabled,
            ShowInDiscoveryDocument = true,
            Claims = new AttributeStringValueList(),
            Scopes = new AttributeStringValueList { ApiScopeName }
        });
    }

    private async Task<RtUser?> GetUserAsync(string userName)
    {
        using var scope = CreateScope();
        var userManager = scope.ServiceProvider
            .GetRequiredService<Microsoft.AspNetCore.Identity.UserManager<RtUser>>();
        return await userManager.FindByNameAsync(userName);
    }

    private static class Pkce
    {
        public const string Verifier = "resource-indicator-verifier-resource-indicator-verifier-1";

        public static string Challenge { get; } = Base64Url(SHA256.HashData(Encoding.UTF8.GetBytes(Verifier)));

        private static string Base64Url(byte[] value)
            => Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }
}
