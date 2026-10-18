using System.Collections.Concurrent;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Microsoft.Extensions.Logging;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.Services.ClientGrants;

/// <summary>
///     Marker persisted in the tenant configuration once <see cref="OctoCliTokenExchangeGrant"/> has handled the
///     <c>octo-cli</c> client of a tenant. Its presence is the run-once gate: an administrator who later removes the
///     grant on purpose must not see it come back on the next restart.
/// </summary>
public sealed class OctoCliTokenExchangeGrantMarker
{
    public DateTime CompletedAtUtc { get; set; }

    /// <summary>True when the grant had to be added, false when the client already carried it.</summary>
    public bool GrantAdded { get; set; }
}

/// <summary>Outcome of one <see cref="OctoCliTokenExchangeGrant.EnsureAsync"/> call.</summary>
internal enum OctoCliTokenExchangeGrantStatus
{
    /// <summary>The grant was added to the client and the run-once marker recorded.</summary>
    Added,

    /// <summary>The client already carried the grant (new tenant or earlier run); marker recorded, nothing written.</summary>
    AlreadyPresent,

    /// <summary>The tenant has no <c>octo-cli</c> client; nothing written, no marker (retried on the next setup).</summary>
    ClientMissing,

    /// <summary>The marker already existed; nothing was read or written.</summary>
    AlreadyDone
}

internal sealed record OctoCliTokenExchangeGrantResult(OctoCliTokenExchangeGrantStatus Status, int ClientsUpdated);

/// <summary>
///     AB#6839: one-time, additive grant of the RFC 8693 token-exchange grant type to the <c>octo-cli</c> client of
///     every tenant, so that already provisioned tenants get what the <c>System.Identity.Bootstrap</c> 1.8.0 seed
///     gives new tenants.
/// </summary>
/// <remarks>
///     <para>
///         <b>Why the seed alone does not reach existing tenants.</b> <c>Client.AllowedGrantTypes</c> is
///         <c>TenantOwned</c> in the System.Identity CK model (AB#6324/AB#6329): the blueprint import (Upsert) keeps
///         the value an existing client holds, so a seed change only reaches clients that are created afterwards.
///         That protection is deliberate (an administrator's grant decisions must survive blueprint updates), hence
///         the fix is an explicit, narrow step here instead of a change of the ownership.
///     </para>
///     <para>
///         Only <c>AllowedGrantTypes</c> of clients with <c>ClientId == "octo-cli"</c> is touched, and only by
///         appending the missing URN — no other grant, attribute or client changes. Guarded by a tenant-configuration
///         marker (same pattern as <c>FileRoleGrant</c>), so a grant an administrator removes later stays removed.
///         Runs from <c>DefaultConfigurationCreatorService.SetupTenantAsync</c> after the blueprint apply and after
///         the child-tenant client mirror provisioning (which copies the parent's grants over a mirrored client).
///     </para>
/// </remarks>
internal static class OctoCliTokenExchangeGrant
{
    public const string ClientId = "octo-cli";
    public const string TokenExchangeGrantType = "urn:ietf:params:oauth:grant-type:token-exchange";

    private static readonly ConcurrentDictionary<string, SemaphoreSlim> Locks = new(StringComparer.Ordinal);

    /// <summary>Pure rule: true when <paramref name="grantTypes"/> does not yet contain the token-exchange grant.</summary>
    public static bool NeedsGrant(IEnumerable<string>? grantTypes)
    {
        return grantTypes == null || !grantTypes.Contains(TokenExchangeGrantType, StringComparer.Ordinal);
    }

    public static async Task<OctoCliTokenExchangeGrantResult> EnsureAsync(
        ITenantContext tenantContext, ILogger logger)
    {
        var gate = Locks.GetOrAdd(tenantContext.TenantId, _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync().ConfigureAwait(false);
        try
        {
            var result = await EnsureCoreAsync(tenantContext).ConfigureAwait(false);
            logger.LogInformation(
                "AB#6839 octo-cli token-exchange grant: tenant='{TenantId}' result={Result} clientsUpdated={ClientsUpdated}",
                tenantContext.TenantId, result.Status, result.ClientsUpdated);
            return result;
        }
        finally
        {
            gate.Release();
        }
    }

    private static async Task<OctoCliTokenExchangeGrantResult> EnsureCoreAsync(ITenantContext tenantContext)
    {
        using (var readSession = await tenantContext.GetAdminSessionAsync())
        {
            var marker = await tenantContext.GetConfigurationAsync<OctoCliTokenExchangeGrantMarker>(
                readSession, IdentityServiceConstants.OctoCliTokenExchangeGrantKey, defaultValue: null);
            if (marker != null)
            {
                return new OctoCliTokenExchangeGrantResult(OctoCliTokenExchangeGrantStatus.AlreadyDone, 0);
            }
        }

        var tenantRepository = tenantContext.GetTenantRepositoryAsAdmin();
        var updated = 0;
        using (var session = await tenantRepository.GetSessionAsync())
        {
            session.StartTransaction();
            var clients = await tenantRepository.GetRtEntitiesByTypeAsync<RtClient>(session,
                RtEntityQueryOptions.Create()
                    .FieldFilter(nameof(RtClient.ClientId), FieldFilterOperator.Equals, ClientId));
            var octoCliClients = clients.Items.ToList();
            if (octoCliClients.Count == 0)
            {
                await session.CommitTransactionAsync();
                return new OctoCliTokenExchangeGrantResult(OctoCliTokenExchangeGrantStatus.ClientMissing, 0);
            }

            foreach (var client in octoCliClients.Where(c => NeedsGrant(c.AllowedGrantTypes)))
            {
                var grants = client.AllowedGrantTypes ?? new AttributeStringValueList();
                grants.Add(TokenExchangeGrantType);
                client.AllowedGrantTypes = grants;
                await tenantRepository.ReplaceOneRtEntityByIdAsync(session, client.RtId, client);
                updated++;
            }

            await session.CommitTransactionAsync();
        }

        // The marker follows the committed write: a crash in between re-runs the step, which then finds the grant.
        using (var markerSession = await tenantContext.GetAdminSessionAsync())
        {
            await tenantContext.SetConfigurationAsync(
                markerSession,
                IdentityServiceConstants.OctoCliTokenExchangeGrantKey,
                new OctoCliTokenExchangeGrantMarker { CompletedAtUtc = DateTime.UtcNow, GrantAdded = updated > 0 });
        }

        return new OctoCliTokenExchangeGrantResult(
            updated > 0 ? OctoCliTokenExchangeGrantStatus.Added : OctoCliTokenExchangeGrantStatus.AlreadyPresent,
            updated);
    }
}
