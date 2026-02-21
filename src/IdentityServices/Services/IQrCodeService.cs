namespace Meshmakers.Octo.Backend.IdentityServices.Services;

/// <summary>
/// Service for generating QR codes with optional logo overlay.
/// </summary>
public interface IQrCodeService
{
    /// <summary>
    /// Generates a QR code image with the Octo logo in the center.
    /// </summary>
    /// <param name="content">The content to encode in the QR code.</param>
    /// <returns>A base64-encoded PNG image of the QR code with logo.</returns>
    string GenerateQrCodeWithLogo(string content);
}
