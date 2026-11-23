using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using FluentAssertions;
using Meshmakers.Octo.Backend.IdentityServices.Services;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using QRCoder;
using Xunit;

namespace IdentityServices.UnitTests.Services;

/// <summary>
///     Characterisation of the QR code of the two-factor setup. The module matrix that QRCoder derives from the
///     setup URI must stay identical across QRCoder upgrades, so an authenticator app keeps reading the setup code.
///     The matrix is pinned instead of the PNG bytes: the bytes depend on the deflate implementation of the platform
///     and differ between operating systems, the matrix does not.
/// </summary>
public class QrCodeServiceTests
{
    private const string OtpAuthUri =
        "otpauth://totp/Octo:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Octo&digits=6&period=30";

    /// <summary>Pixels per module the service asks the renderer for.</summary>
    private const int PixelsPerModule = 10;

    private static QrCodeService CreateService()
    {
        var environment = Substitute.For<IWebHostEnvironment>();
        environment.WebRootPath.Returns(Path.Combine(Path.GetTempPath(), "qr-test-no-webroot"));
        return new QrCodeService(environment, NullLogger<QrCodeService>.Instance);
    }

    private static string ModuleMatrixHash(string content, out int size)
    {
        using var generator = new QRCodeGenerator();
        using var data = generator.CreateQrCode(content, QRCodeGenerator.ECCLevel.H);
        size = data.ModuleMatrix.Count;
        var text = new StringBuilder();
        foreach (var row in data.ModuleMatrix)
        {
            foreach (bool module in row)
            {
                text.Append(module ? '1' : '0');
            }

            text.Append('\n');
        }

        return Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes(text.ToString())));
    }

    [Fact]
    public void ModuleMatrix_OfTheSetupUri_IsStableAcrossQrCoderVersions()
    {
        var hash = ModuleMatrixHash(OtpAuthUri, out var size);

        size.Should().Be(61);
        hash.Should().Be("72709FC2C211126AE6D42648D4D253F629102116BE2A5037701B7BD719B0AD23");
    }

    [Fact]
    public void GenerateQrCodeWithLogo_ReturnsPngOfTheExpectedSize()
    {
        var png = Convert.FromBase64String(CreateService().GenerateQrCodeWithLogo(OtpAuthUri));
        ModuleMatrixHash(OtpAuthUri, out var modules);

        png.Take(8).Should().Equal(0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A);
        // The IHDR chunk follows the signature: 4 length bytes, "IHDR", then width and height (big endian).
        Encoding.ASCII.GetString(png, 12, 4).Should().Be("IHDR");
        BinaryPrimitives.ReadInt32BigEndian(png.AsSpan(16, 4)).Should().Be(modules * PixelsPerModule);
        BinaryPrimitives.ReadInt32BigEndian(png.AsSpan(20, 4)).Should().Be(modules * PixelsPerModule);
    }

    [Fact]
    public void GenerateQrCodeWithLogo_DifferentContent_GivesDifferentImage()
    {
        var service = CreateService();

        service.GenerateQrCodeWithLogo(OtpAuthUri).Should().NotBe(service.GenerateQrCodeWithLogo(OtpAuthUri + "x"));
    }
}
