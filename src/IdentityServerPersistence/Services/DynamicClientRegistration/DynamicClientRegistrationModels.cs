using System.Text.Json.Serialization;

namespace IdentityServerPersistence.Services.DynamicClientRegistration;

/// <summary>
///     RFC 7591 client-registration request. Only the subset our gate accepts is modelled; any other
///     member is ignored. JSON is snake_case per the spec.
/// </summary>
public sealed class DynamicClientRegistrationRequest
{
    [JsonPropertyName("redirect_uris")] public List<string>? RedirectUris { get; set; }

    [JsonPropertyName("grant_types")] public List<string>? GrantTypes { get; set; }

    [JsonPropertyName("response_types")] public List<string>? ResponseTypes { get; set; }

    [JsonPropertyName("token_endpoint_auth_method")]
    public string? TokenEndpointAuthMethod { get; set; }

    [JsonPropertyName("scope")] public string? Scope { get; set; }

    [JsonPropertyName("client_name")] public string? ClientName { get; set; }

    [JsonPropertyName("application_type")] public string? ApplicationType { get; set; }
}

/// <summary>
///     RFC 7591 client-information response returned on a successful registration. Public client, so
///     there is no <c>client_secret</c>.
/// </summary>
public sealed class DynamicClientRegistrationResponse
{
    [JsonPropertyName("client_id")] public string ClientId { get; set; } = string.Empty;

    [JsonPropertyName("client_id_issued_at")]
    public long ClientIdIssuedAt { get; set; }

    [JsonPropertyName("redirect_uris")] public List<string> RedirectUris { get; set; } = [];

    [JsonPropertyName("grant_types")] public List<string> GrantTypes { get; set; } = [];

    [JsonPropertyName("response_types")] public List<string> ResponseTypes { get; set; } = [];

    [JsonPropertyName("token_endpoint_auth_method")]
    public string TokenEndpointAuthMethod { get; set; } = "none";

    [JsonPropertyName("scope")] public string Scope { get; set; } = string.Empty;

    [JsonPropertyName("client_name")] public string? ClientName { get; set; }
}

/// <summary>
///     RFC 7591 §3.2.2 registration error (e.g. <c>invalid_redirect_uri</c>,
///     <c>invalid_client_metadata</c>).
/// </summary>
public sealed class DynamicClientRegistrationError
{
    [JsonPropertyName("error")] public string Error { get; set; } = string.Empty;

    [JsonPropertyName("error_description")]
    public string? ErrorDescription { get; set; }
}

/// <summary>
///     Outcome of a registration attempt, mapped to an HTTP status by the endpoint.
/// </summary>
public enum DynamicClientRegistrationOutcome
{
    /// <summary>A new client was created (HTTP 201).</summary>
    Created,

    /// <summary>An equivalent non-expired client already existed and was re-issued (HTTP 200).</summary>
    ReturnedExisting,

    /// <summary>Request rejected by the gate (HTTP 400 with an RFC 7591 error).</summary>
    Invalid,

    /// <summary>DCR is disabled for this deployment (HTTP 404).</summary>
    Disabled,

    /// <summary>The per-tenant client cap is reached (HTTP 403).</summary>
    CapExceeded
}

/// <summary>
///     Result of <see cref="IDynamicClientRegistrationService.RegisterAsync"/>: exactly one of
///     <see cref="Response"/> / <see cref="Error"/> is set depending on <see cref="Outcome"/>.
/// </summary>
public sealed record DynamicClientRegistrationResult(
    DynamicClientRegistrationOutcome Outcome,
    DynamicClientRegistrationResponse? Response,
    DynamicClientRegistrationError? Error);
