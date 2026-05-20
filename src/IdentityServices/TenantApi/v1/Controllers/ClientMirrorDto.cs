namespace Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;

/// <summary>
/// Serialised view of an <c>RtClientMirror</c> tracking row. Lives in the parent
/// tenant's identity DB and records that a <c>ClientCredentials</c> client has been
/// auto-provisioned into a specific child tenant.
/// </summary>
public sealed record ClientMirrorDto(
    string ParentClientId,
    string ParentTenantId,
    string ChildTenantId,
    DateTime ProvisionedAt,
    int SecretHashVersion);

/// <summary>
/// Result body for backfill / provision operations.
/// </summary>
public sealed record ClientMirrorBackfillResponseDto(
    int ChildTenantsConsidered,
    int NewlyProvisioned,
    int AlreadyPresent);

/// <summary>
/// Result body for a single-tenant manual provision operation.
/// </summary>
public sealed record ClientMirrorProvisionResponseDto(
    int FlaggedClientsConsidered,
    int NewlyProvisioned,
    int AlreadyPresent);

/// <summary>
/// Body for <c>PATCH .../{clientId}/autoProvisionInChildTenants</c>.
/// </summary>
public sealed record SetAutoProvisionInChildTenantsDto(bool Enabled);
