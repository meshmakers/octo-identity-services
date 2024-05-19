namespace Meshmakers.Octo.Backend.IdentityServices.Services;

public interface IOemService
{
    string Favicon { get; }
    string Favicon32x32 { get; }
    string StyleBundle { get; }
    string JsBundle { get; }
}