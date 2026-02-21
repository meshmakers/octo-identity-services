using QRCoder;

namespace Meshmakers.Octo.Backend.IdentityServices.Services;

/// <summary>
/// Service for generating QR codes with optional Octo logo overlay.
/// Uses QRCoder's built-in image generation capabilities.
/// </summary>
public class QrCodeService : IQrCodeService
{
    private readonly IWebHostEnvironment _environment;
    private readonly ILogger<QrCodeService> _logger;
    private byte[]? _logoImage;

    // Deep Sea color from Octo Brand Manual
    private static readonly byte[] DeepSeaColor = [0x07, 0x17, 0x2b];
    private static readonly byte[] WhiteColor = [0xFF, 0xFF, 0xFF];

    public QrCodeService(IWebHostEnvironment environment, ILogger<QrCodeService> logger)
    {
        _environment = environment;
        _logger = logger;
        LoadLogo();
    }

    private void LoadLogo()
    {
        try
        {
            var logoPath = Path.Combine(_environment.WebRootPath, "images", "octo-logo.png");
            if (File.Exists(logoPath))
            {
                _logoImage = File.ReadAllBytes(logoPath);
                _logger.LogInformation("Loaded Octo logo from {LogoPath}", logoPath);
            }
            else
            {
                _logger.LogWarning("Octo logo not found at {LogoPath}, QR codes will be generated without logo", logoPath);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to load Octo logo");
        }
    }

    /// <inheritdoc />
    public string GenerateQrCodeWithLogo(string content)
    {
        // TODO: Implement logo overlay using System.Drawing.Common (Phase 6 of 2FA plan)
        // The _logoImage field is loaded but not yet used. Need to overlay it on the QR code center.
        // See: https://dev.azure.com/meshmakers/OctoMesh/_workitems/edit/3332

        // Use higher error correction level (H = 30%) to allow for logo overlay
        using var qrGenerator = new QRCodeGenerator();
        using var qrCodeData = qrGenerator.CreateQrCode(content, QRCodeGenerator.ECCLevel.H);
        using var qrCode = new PngByteQRCode(qrCodeData);

        // Generate QR code with Deep Sea color (dark) and white background
        var qrCodeBytes = qrCode.GetGraphic(10, DeepSeaColor, WhiteColor);
        return Convert.ToBase64String(qrCodeBytes);
    }
}
