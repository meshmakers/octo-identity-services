namespace Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;

/// <summary>
///     Request body for creating a client or API resource secret (AB#6258). The server generates the secret
///     itself, so the caller supplies only the metadata. Fields the shipped clients still send
///     (<c>valueEncrypted</c>, <c>valueClearText</c>) are not part of this contract and are ignored — they are
///     never stored and never echoed. The response stays an <c>ApiSecretDto</c> (wire format unchanged).
/// </summary>
public class CreateApiSecretRequestDto
{
    /// <summary>Expiration date of the secret; <c>null</c> for a secret that does not expire.</summary>
    public DateTime? ExpirationDate { get; set; }

    /// <summary>Description of the secret.</summary>
    public string? Description { get; set; }
}
