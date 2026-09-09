using FluentAssertions;
using Meshmakers.Octo.Backend.IdentityServices.Middleware;
using Meshmakers.Octo.Backend.IdentityServices.Services;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Configuration;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace IdentityServices.UnitTests.Middleware;

public class OidcTenantResolutionMiddlewareTests
{
    [Fact]
    public void ParseTenantFromAcrValues_WithTenantValue_ReturnsTenantId()
    {
        var result = OidcTenantResolutionMiddleware.ParseTenantFromAcrValues("tenant:sbeg");

        result.Should().Be("sbeg");
    }

    [Fact]
    public void ParseTenantFromAcrValues_WithMultipleValues_ReturnsTenantId()
    {
        var result = OidcTenantResolutionMiddleware.ParseTenantFromAcrValues("idp:local tenant:sbeg");

        result.Should().Be("sbeg");
    }

    [Fact]
    public void ParseTenantFromAcrValues_WithNoTenantValue_ReturnsNull()
    {
        var result = OidcTenantResolutionMiddleware.ParseTenantFromAcrValues("idp:local");

        result.Should().BeNull();
    }

    [Fact]
    public void ParseTenantFromAcrValues_WithEmptyString_ReturnsNull()
    {
        var result = OidcTenantResolutionMiddleware.ParseTenantFromAcrValues("");

        result.Should().BeNull();
    }

    [Fact]
    public void ParseTenantFromAcrValues_WithEmptyTenantValue_ReturnsNull()
    {
        var result = OidcTenantResolutionMiddleware.ParseTenantFromAcrValues("tenant:");

        result.Should().BeNull();
    }

    [Fact]
    public void ParseTenantFromAcrValues_CaseInsensitivePrefix()
    {
        var result = OidcTenantResolutionMiddleware.ParseTenantFromAcrValues("Tenant:sbeg");

        result.Should().Be("sbeg");
    }

    [Fact]
    public void ExtractTenantFromJwtPayload_WithValidJwt_ReturnsTenantId()
    {
        // Create a JWT with tenant_id claim in the payload
        // Header: {"alg":"RS256","typ":"JWT"}
        // Payload: {"sub":"user1","tenant_id":"sbeg"}
        var header = Base64UrlEncode("{\"alg\":\"RS256\",\"typ\":\"JWT\"}");
        var payload = Base64UrlEncode("{\"sub\":\"user1\",\"tenant_id\":\"sbeg\"}");
        var jwt = $"{header}.{payload}.signature";

        var result = OidcTenantResolutionMiddleware.ExtractTenantFromJwtPayload(jwt);

        result.Should().Be("sbeg");
    }

    [Fact]
    public void ExtractTenantFromJwtPayload_WithNoTenantClaim_ReturnsNull()
    {
        var header = Base64UrlEncode("{\"alg\":\"RS256\",\"typ\":\"JWT\"}");
        var payload = Base64UrlEncode("{\"sub\":\"user1\"}");
        var jwt = $"{header}.{payload}.signature";

        var result = OidcTenantResolutionMiddleware.ExtractTenantFromJwtPayload(jwt);

        result.Should().BeNull();
    }

    [Fact]
    public void ExtractTenantFromJwtPayload_WithMalformedJwt_ReturnsNull()
    {
        var result = OidcTenantResolutionMiddleware.ExtractTenantFromJwtPayload("not-a-jwt");

        result.Should().BeNull();
    }

    [Fact]
    public void ExtractTenantFromJwtPayload_WithEmptyString_ReturnsNull()
    {
        var result = OidcTenantResolutionMiddleware.ExtractTenantFromJwtPayload("");

        result.Should().BeNull();
    }

    [Fact]
    public void ExtractTenantFromJwtPayload_WithInvalidBase64_ReturnsNull()
    {
        var result = OidcTenantResolutionMiddleware.ExtractTenantFromJwtPayload("header.!!!invalid!!!.signature");

        result.Should().BeNull();
    }

    [Fact]
    public void ExtractCodeFromRedirectUri_WithAbsoluteUri_ReturnsCode()
    {
        var result = OidcTenantResolutionMiddleware.ExtractCodeFromRedirectUri(
            "https://localhost:4200/callback?code=ABC123&state=xyz");

        result.Should().Be("ABC123");
    }

    [Fact]
    public void ExtractCodeFromRedirectUri_WithRelativeUri_ReturnsCode()
    {
        var result = OidcTenantResolutionMiddleware.ExtractCodeFromRedirectUri(
            "/callback?code=DEF456&state=xyz");

        result.Should().Be("DEF456");
    }

    [Fact]
    public void ExtractCodeFromRedirectUri_WithNoCodeParam_ReturnsNull()
    {
        var result = OidcTenantResolutionMiddleware.ExtractCodeFromRedirectUri(
            "https://localhost:4200/callback?state=xyz");

        result.Should().BeNull();
    }

    [Fact]
    public void ExtractCodeFromRedirectUri_WithNoQueryString_ReturnsNull()
    {
        var result = OidcTenantResolutionMiddleware.ExtractCodeFromRedirectUri(
            "https://localhost:4200/callback");

        result.Should().BeNull();
    }

    [Fact]
    public void ExtractCodeFromRedirectUri_WithNull_ReturnsNull()
    {
        var result = OidcTenantResolutionMiddleware.ExtractCodeFromRedirectUri(null);

        result.Should().BeNull();
    }

    [Fact]
    public void ExtractCodeFromRedirectUri_WithEmptyString_ReturnsNull()
    {
        var result = OidcTenantResolutionMiddleware.ExtractCodeFromRedirectUri("");

        result.Should().BeNull();
    }

    [Fact]
    public void ExtractCodeFromFormPostBody_WithStandardFormPost_ReturnsCode()
    {
        var html = """
            <html><body>
            <form method='post' action='https://localhost:5001/signin-oidc'>
                <input type='hidden' name='code' value='AUTH_CODE_123' />
                <input type='hidden' name='state' value='some_state' />
            </form>
            </body></html>
            """;
        using var stream = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(html));

        var result = OidcTenantResolutionMiddleware.ExtractCodeFromFormPostBody(stream);

        result.Should().Be("AUTH_CODE_123");
    }

    [Fact]
    public void ExtractCodeFromFormPostBody_WithDoubleQuotes_ReturnsCode()
    {
        var html = """
            <form method="post" action="https://localhost:5001/signin-oidc">
                <input type="hidden" name="code" value="MY_CODE_456" />
            </form>
            """;
        using var stream = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(html));

        var result = OidcTenantResolutionMiddleware.ExtractCodeFromFormPostBody(stream);

        result.Should().Be("MY_CODE_456");
    }

    [Fact]
    public void ExtractCodeFromFormPostBody_WithNoCodeField_ReturnsNull()
    {
        var html = """
            <form method='post' action='https://localhost:5001/signin-oidc'>
                <input type='hidden' name='state' value='some_state' />
            </form>
            """;
        using var stream = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(html));

        var result = OidcTenantResolutionMiddleware.ExtractCodeFromFormPostBody(stream);

        result.Should().BeNull();
    }

    [Fact]
    public void ExtractCodeFromFormPostBody_WithEmptyBody_ReturnsNull()
    {
        using var stream = new MemoryStream();

        var result = OidcTenantResolutionMiddleware.ExtractCodeFromFormPostBody(stream);

        result.Should().BeNull();
    }

    /// <summary>
    ///     AB#5026 — the delegation grant must resolve its tenant from <c>acr_values</c> like
    ///     <c>client_credentials</c> and token-exchange do.
    /// </summary>
    /// <remarks>
    ///     The if/else chain in <c>ResolveTenantFromTokenRequestAsync</c> is a closed list of known
    ///     grant types; an unlisted one falls through to <c>null</c>, no tenant is wired into
    ///     <c>HttpContext.Items</c>, and every per-tenant store silently reads the SYSTEM tenant —
    ///     which for delegation means resolving the service account, the user and both role sets
    ///     from the wrong database. This test is the guard against re-introducing that gap.
    /// </remarks>
    [Fact]
    public async Task ResolveTenantFromTokenRequest_OnBehalfOfGrant_ResolvesTenantFromAcrValues()
    {
        var context = TokenRequest(DelegationConstants.OnBehalfOfGrantType, "tenant:sbeg");

        var result = await CreateMiddleware().ResolveTenantFromTokenRequestAsync(context);

        result.Should().Be("sbeg");
    }

    [Fact]
    public async Task ResolveTenantFromTokenRequest_OnBehalfOfGrantWithoutAcrValues_ReturnsNull()
    {
        // The grant validator then fails closed on the missing target tenant.
        var context = TokenRequest(DelegationConstants.OnBehalfOfGrantType, acrValues: null);

        var result = await CreateMiddleware().ResolveTenantFromTokenRequestAsync(context);

        result.Should().BeNull();
    }

    [Fact]
    public async Task ResolveTenantFromTokenRequest_UnknownGrantType_ReturnsNull()
    {
        // Pins the fall-through the delegation branch exists to avoid.
        var context = TokenRequest("urn:example:grant-type:unknown", "tenant:sbeg");

        var result = await CreateMiddleware().ResolveTenantFromTokenRequestAsync(context);

        result.Should().BeNull();
    }

    private static OidcTenantResolutionMiddleware CreateMiddleware() =>
        new(_ => Task.CompletedTask,
            NullLogger<OidcTenantResolutionMiddleware>.Instance,
            Options.Create(new OctoSystemConfiguration()));

    private static DefaultHttpContext TokenRequest(string grantType, string? acrValues)
    {
        var form = $"grant_type={Uri.EscapeDataString(grantType)}";
        if (acrValues != null)
        {
            form += $"&acr_values={Uri.EscapeDataString(acrValues)}";
        }

        var bytes = System.Text.Encoding.UTF8.GetBytes(form);
        var context = new DefaultHttpContext();
        context.Request.Method = "POST";
        context.Request.Path = "/connect/token";
        context.Request.ContentType = "application/x-www-form-urlencoded";
        context.Request.ContentLength = bytes.Length;
        context.Request.Body = new MemoryStream(bytes);
        return context;
    }

    private static string Base64UrlEncode(string input)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(input);
        return Convert.ToBase64String(bytes)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');
    }
}
