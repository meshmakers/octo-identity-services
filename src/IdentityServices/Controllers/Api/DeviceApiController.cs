namespace Meshmakers.Octo.Backend.IdentityServices.Controllers.Api;

// AB#4993 (OpenIddict migration): the device flow interaction moved to
// Controllers/Protocol/DeviceVerificationController (OpenIddict end-user verification
// endpoint, /connect/deviceverification). These DTOs remain the wire contract of that
// endpoint for the Angular device page.

public record DeviceAuthorizationContextDto
{
    public string UserCode { get; init; } = string.Empty;
    public string? ClientName { get; init; }
    public string? ClientUrl { get; init; }
    public string? ClientLogoUrl { get; init; }
    public IEnumerable<ScopeItemDto> IdentityScopes { get; init; } = [];
    public IEnumerable<ScopeItemDto> ApiScopes { get; init; } = [];
    public bool ConfirmUserCode { get; init; }
    public string? Description { get; init; }
}

public record DeviceAuthorizationRequestDto
{
    public string UserCode { get; init; } = string.Empty;
    public IEnumerable<string>? ScopesConsented { get; init; }
    public bool RememberConsent { get; init; }
    public string? Description { get; init; }
}

public record DeviceDenyRequestDto
{
    public string UserCode { get; init; } = string.Empty;
}

public record DeviceAuthorizationResultDto
{
    public bool Success { get; init; }
    public string? ErrorMessage { get; init; }
}
