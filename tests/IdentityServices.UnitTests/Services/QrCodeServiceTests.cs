using System.Security.Cryptography;
using FluentAssertions;
using Meshmakers.Octo.Backend.IdentityServices.Services;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using Xunit;

namespace IdentityServices.UnitTests.Services;

/// <summary>
///     Characterisation of the QR code of the two-factor setup. The rendered PNG must stay byte-identical
///     across QRCoder upgrades, so an authenticator app keeps reading the setup code.
/// </summary>
public class QrCodeServiceTests
{
    private const string OtpAuthUri =
        "otpauth://totp/Octo:gerald@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Octo&digits=6&period=30";

    private static QrCodeService CreateService()
    {
        var environment = Substitute.For<IWebHostEnvironment>();
        environment.WebRootPath.Returns(Path.Combine(Path.GetTempPath(), "qr-test-no-webroot"));
        return new QrCodeService(environment, NullLogger<QrCodeService>.Instance);
    }

    [Fact]
    public void GenerateQrCodeWithLogo_ReturnsPngThatIsStableForTheSameContent()
    {
        var service = CreateService();

        var first = Convert.FromBase64String(service.GenerateQrCodeWithLogo(OtpAuthUri));
        var second = Convert.FromBase64String(service.GenerateQrCodeWithLogo(OtpAuthUri));

        first.Take(8).Should().Equal(0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A);
        second.Should().Equal(first);
        Convert.ToHexString(SHA256.HashData(first)).Should().Be("794B8C3B2F8078ED8319AFDF28EFC7A721C1DD9E823569181614B1FAF81D77CB");
    }

    [Fact]
    public void GenerateQrCodeWithLogo_DifferentContent_GivesDifferentImage()
    {
        var service = CreateService();

        service.GenerateQrCodeWithLogo(OtpAuthUri).Should().NotBe(service.GenerateQrCodeWithLogo(OtpAuthUri + "x"));
    }
}
