using FluentAssertions;
using Meshmakers.Octo.Backend.IdentityServices.Middleware;
using Xunit;

namespace IdentityServices.UnitTests.Middleware;

/// <summary>AB#7891: the device_code carries its tenant, so the token poll needs no server-side state.</summary>
public class DeviceCodeTenantMarkerTests
{
    [Theory]
    [InlineData("child-a", "abc_DEF-123")]
    [InlineData("octosystem", "eyJhbGciOi.eyJ6aXAiOi.c2lnbmF0dXJl")]
    [InlineData("t_1", "code:with:colons")]
    public void EncodeThenDecode_ReturnsTenantAndOriginalCode(string tenantId, string deviceCode)
    {
        var marked = DeviceCodeTenantMarker.Encode(tenantId, deviceCode);

        DeviceCodeTenantMarker.TryDecode(marked, out var decodedTenant, out var decodedCode).Should().BeTrue();
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
        DeviceCodeTenantMarker.TryDecode(value, out var tenantId, out var deviceCode).Should().BeFalse();
        tenantId.Should().BeEmpty();
        deviceCode.Should().BeEmpty();
    }

    [Fact]
    public void TryDecode_TenantIdLongerThanAllowed_ReturnsFalse()
    {
        var marked = DeviceCodeTenantMarker.Encode(new string('a', 65), "code");

        DeviceCodeTenantMarker.TryDecode(marked, out _, out _).Should().BeFalse();
    }
}
