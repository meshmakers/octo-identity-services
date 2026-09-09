using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using FluentAssertions;
using IdentityServices.IntegrationTests.Infrastructure;
using Xunit;

namespace IdentityServices.IntegrationTests.Api;

/// <summary>
///     AB#4989: the grants page lists clients holding live refresh tokens for the user.
///     OpenIddict persists <c>RtOAuthToken.TokenType</c> in the URN form
///     (<c>urn:ietf:params:oauth:token-type:refresh_token</c>), not the short
///     <c>TokenTypeHints</c> form — a short-form-only comparison silently yields an
///     empty grants page (same trap as <c>GenerateTokenContext.TokenType</c>).
/// </summary>
public class GrantsApiTests : IntegrationTestBase
{
    public GrantsApiTests(CustomWebApplicationFactory factory) : base(factory)
    {
    }

    [Fact]
    public async Task GetGrants_RefreshTokenStoredWithUrnType_IsListed()
    {
        var ct = TestContext.Current.CancellationToken;
        const string password = "Test123$abc";
        var user = await CreateTestUserAsync("grantsurnuser", password: password);
        var subjectId = user.RtId.ToString();

        await CreateTestClientAsync("grants-urn-client", clientName: "Grants URN Client",
            grantTypes: ["authorization_code"], allowedScopes: ["openid", "offline_access"]);

        // Production shape: the URN token type, exactly as OpenIddict persists it.
        await CreateOAuthTokenAsync(subjectId, "grants-urn-client",
            tokenType: "urn:ietf:params:oauth:token-type:refresh_token");

        var client = await LoginAndGetAuthenticatedClientAsync("grantsurnuser", password, ct);
        client.Should().NotBeNull();

        var response = await client!.GetAsync($"/{NormalizedSystemTenantId}/api/grants", ct);
        var raw = await response.Content.ReadAsStringAsync(ct);
        response.StatusCode.Should().Be(HttpStatusCode.OK, "grants request failed: {0}", raw);

        var grants = JsonNode.Parse(raw)!.AsArray();
        grants.Select(g => g!["clientId"]!.GetValue<string>())
            .Should().Contain("grants-urn-client",
                "a live refresh token stored with the URN token type must appear as a grant");
    }
}
