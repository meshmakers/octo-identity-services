namespace Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers.Dto;

/// <summary>
///     Response body for <c>DELETE {tenantId}/v1/clients/cleanOverlayEntries</c> — strips
///     entries where <c>Source</c> starts with <c>overlay:</c> (or matches a specific
///     <c>overlay:&lt;name&gt;</c> if a name was supplied) from every blueprint-managed
///     <c>RtClient</c> URI list. The <c>DumpTenant --clean</c> wrapper (AB#4209 Step 5)
///     calls this against a temp-DB clone before piping the dump out, so the resulting
///     archive contains no <c>overlay:*</c> entries and is safe to re-import as Blueprint
///     seed material.
/// </summary>
/// <remarks>
///     Defined locally in identity-services for Step 5 PR 1. When PR 4 (SDK client method)
///     lands the DTOs are lifted to <c>Meshmakers.Octo.Communication.Contracts.DataTransferObjects</c>
///     in octo-sdk so the CLI can share the same shape. Mirrors the PR 1/2 sequencing of Step 4.
/// </remarks>
public sealed class CleanOverlayEntriesResultDto
{
    /// <summary>
    ///     The overlay name filter that was applied, or <c>null</c> if all
    ///     <c>overlay:*</c> sources were targeted.
    /// </summary>
    public string? OverlayName { get; init; }

    /// <summary>
    ///     Number of clients that had at least one matching entry removed (and thus
    ///     received an <c>UpdateAsync</c> + cache invalidation).
    /// </summary>
    public int ClientsAffected { get; init; }

    /// <summary>
    ///     Total number of URI entries removed across every list across every client.
    /// </summary>
    public int TotalEntriesRemoved { get; init; }

    /// <summary>
    ///     Per-client breakdown — one entry per client that had at least one matching
    ///     URI removed (clients with zero removals are omitted to keep the response small).
    /// </summary>
    public required List<CleanOverlayEntriesClientResultDto> ClientResults { get; init; }
}

/// <summary>
///     Per-client breakdown of removed entries.
/// </summary>
public sealed class CleanOverlayEntriesClientResultDto
{
    /// <summary>The ClientId the counts apply to.</summary>
    public required string ClientId { get; init; }

    /// <summary>Number of entries removed from <c>RedirectUris</c>.</summary>
    public int RedirectUrisRemoved { get; init; }

    /// <summary>Number of entries removed from <c>PostLogoutRedirectUris</c>.</summary>
    public int PostLogoutRedirectUrisRemoved { get; init; }

    /// <summary>Number of entries removed from <c>AllowedCorsOrigins</c>.</summary>
    public int AllowedCorsOriginsRemoved { get; init; }
}
