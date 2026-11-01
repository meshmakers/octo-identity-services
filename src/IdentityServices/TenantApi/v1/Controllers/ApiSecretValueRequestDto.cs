using System.ComponentModel.DataAnnotations;

namespace Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;

/// <summary>
///     Request body that names one stored client or API resource secret by its stored value (the hash) — for
///     <c>POST apiSecrets/{client|apiResource}/{id}/delete</c> and <c>.../lookup</c> (AB#8008). The value travels in the
///     body because a URL path ends up in request logs, traces (<c>url.path</c>) and proxy access logs.
/// </summary>
/// <remarks>
///     A class with its own <see cref="ToString" />: ASP.NET Core writes the action arguments with <c>ToString()</c> into
///     its TRACE log, so the text never carries the value.
/// </remarks>
public sealed class ApiSecretValueRequestDto
{
    /// <summary>The stored value of the secret (<c>valueEncrypted</c>, the hash as returned by the list endpoints).</summary>
    [Required]
    public string ValueEncrypted { get; set; } = string.Empty;

    /// <summary>Never carries the value.</summary>
    public override string ToString() => nameof(ApiSecretValueRequestDto);
}
