using FluentAssertions;
using Meshmakers.Octo.Backend.IdentityServices.Middleware;
using Xunit;

namespace IdentityServices.UnitTests.Middleware;

/// <summary>
///     AB#7891/AB#7892: device codes, authorization codes, refresh tokens and PAR request_uris carry their tenant, so
///     the follow-up request needs no server-side state.
/// </summary>
public class OidcTenantMarkerTests
{
    [Theory]
    [InlineData("child-a", "abc_DEF-123")]
    [InlineData("octosystem", "eyJhbGciOi.eyJ6aXAiOi.c2lnbmF0dXJl")]
    [InlineData("t_1", "code:with:colons")]
    public void EncodeThenDecode_ReturnsTenantAndOriginalCode(string tenantId, string deviceCode)
    {
        var marked = OidcTenantMarker.Encode(tenantId, deviceCode);

        OidcTenantMarker.TryDecode(marked, out var decodedTenant, out var decodedCode).Should().BeTrue();
        decodedTenant.Should().Be(tenantId);
        decodedCode.Should().Be(deviceCode);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("unmarked-device-code")]
    [InlineData(":code")]
    [InlineData("tenant:")]
    [InlineData("bad.tenant:code")]
    [InlineData("bad tenant:code")]
    [InlineData("../x:code")]
    public void TryDecode_WithoutWellFormedTenantPrefix_ReturnsFalse(string? value)
    {
        OidcTenantMarker.TryDecode(value, out var tenantId, out var deviceCode).Should().BeFalse();
        tenantId.Should().BeEmpty();
        deviceCode.Should().BeEmpty();
    }

    [Fact]
    public void TryDecode_TenantIdLongerThanAllowed_ReturnsFalse()
    {
        var marked = OidcTenantMarker.Encode(new string('a', 65), "code");

        OidcTenantMarker.TryDecode(marked, out _, out _).Should().BeFalse();
    }

    private const string RequestUri = "urn:ietf:params:oauth:request_uri:Abc_DEF-123";

    [Fact]
    public void RequestUri_WithTenant_StaysAUrnAndRoundTrips()
    {
        var marked = OidcTenantMarker.EncodeRequestUri(RequestUri, "child-a", null);

        marked.Should().Be("urn:ietf:params:oauth:request_uri:child-a:Abc_DEF-123");
        OidcTenantMarker.TryDecodeRequestUri(marked, out var tenantId, out var scope, out var original).Should().BeTrue();
        tenantId.Should().Be("child-a");
        scope.Should().BeNull();
        original.Should().Be(RequestUri);
    }

    [Fact]
    public void RequestUri_WithScopeOnly_IsNeverReadAsATenant()
    {
        var marked = OidcTenantMarker.EncodeRequestUri(RequestUri, null, "accounting");

        OidcTenantMarker.TryDecodeRequestUri(marked, out var tenantId, out var scope, out var original).Should().BeTrue();
        tenantId.Should().BeNull();
        scope.Should().Be("accounting");
        original.Should().Be(RequestUri);
        OidcTenantMarker.TryDecode(marked, out _, out _).Should().BeTrue(
            "the generic decoder would read 'urn' — which is why request_uris have their own decoder");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("urn:ietf:params:oauth:request_uri:unmarked")]
    [InlineData("urn:ietf:params:oauth:request_uri:bad.tenant:ref")]
    [InlineData("urn:ietf:params:oauth:request_uri:tenant_scope.bad scope:ref")]
    [InlineData("urn:other:child-a:ref")]
    public void TryDecodeRequestUri_UnmarkedOrForeign_ReturnsFalse(string? value)
    {
        OidcTenantMarker.TryDecodeRequestUri(value, out var tenantId, out var scope, out var original).Should().BeFalse();
        tenantId.Should().BeNull();
        scope.Should().BeNull();
        original.Should().BeEmpty();
    }

    [Theory]
    [InlineData("urn:other:ref", "child-a", null)]
    [InlineData(RequestUri, null, null)]
    public void EncodeRequestUri_ForeignValueOrNothingToMark_ReturnsNull(string requestUri, string? tenantId,
        string? scope)
    {
        OidcTenantMarker.EncodeRequestUri(requestUri, tenantId, scope).Should().BeNull();
    }
}
