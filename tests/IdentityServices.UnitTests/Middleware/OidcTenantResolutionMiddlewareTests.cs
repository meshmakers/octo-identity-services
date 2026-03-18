using FluentAssertions;
using Meshmakers.Octo.Backend.IdentityServices.Middleware;
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

    private static string Base64UrlEncode(string input)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(input);
        return Convert.ToBase64String(bytes)
            .Replace('+', '-')
            .Replace('/', '_')
            .TrimEnd('=');
    }
}
