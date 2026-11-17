using System.Text.RegularExpressions;
using IdentityServerPersistence;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Common.DistributionEventHub.Services;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Messages;
using Meshmakers.Octo.Services.Methods;
using Meshmakers.Octo.Services.Methods.Authorization;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;

namespace Meshmakers.Octo.Backend.IdentityServices.Methods;

/// <summary>Error codes of the overlay methods (declared in <c>ck-client.yaml</c>, System.Identity 3.3.0).</summary>
internal static class ClientOverlayErrors
{
    public const string InvalidOverlayName = "INVALID_OVERLAY_NAME";
    public const string NoOverlayUris = "NO_OVERLAY_URIS";
    public const string ConcurrentChange = "CONCURRENT_CHANGE";
}

/// <summary>
///     The overlay URI rules (concept of the declarative identity overlays): an overlay URI is written with
///     <c>Source = "overlay:&lt;name&gt;"</c>, a URI already in a list (any source) is skipped, and a clean removes the entries
///     of one overlay or of every overlay. Used only by the overlay method handlers; the REST endpoints are their facades.
/// </summary>
internal static partial class ClientOverlayUris
{
    /// <summary>The allowed overlay name: letters, digits, <c>.</c>, <c>-</c> and <c>_</c>.</summary>
    [GeneratedRegex("^[A-Za-z0-9._-]+$")]
    public static partial Regex OverlayName();

    /// <summary>Number of non-blank entries; a list of blanks is no overlay at all.</summary>
    public static int CountNonWhitespace(IEnumerable<string>? list) =>
        list?.Count(item => !string.IsNullOrWhiteSpace(item)) ?? 0;

    /// <summary>
    ///     Appends each non-blank URI of <paramref name="incoming" /> to <paramref name="targetList" /> unless an entry with
    ///     the same URI exists (any source, ordinal). Returns how many were added and how many skipped as duplicates.
    /// </summary>
    public static (int Added, int Skipped) Append(IAttributeValueList<RtClientUriEntryRecord> targetList,
        IEnumerable<string>? incoming, string sourceTag)
    {
        if (incoming == null)
        {
            return (0, 0);
        }

        var existing = new HashSet<string>(targetList.Select(entry => entry.Uri), StringComparer.Ordinal);
        int added = 0, skipped = 0;
        foreach (var uri in incoming)
        {
            if (string.IsNullOrWhiteSpace(uri))
            {
                continue;
            }

            if (!existing.Add(uri))
            {
                skipped++;
                continue;
            }

            targetList.Add(new RtClientUriEntryRecord { Uri = uri, Source = sourceTag });
            added++;
        }

        return (added, skipped);
    }

    /// <summary>
    ///     Removes the entries whose source matches: <paramref name="targetSource" /> <c>null</c> matches every
    ///     <c>overlay:*</c> source, otherwise the exact source. Returns the number removed.
    /// </summary>
    public static int Remove(IAttributeValueList<RtClientUriEntryRecord> targetList, string? targetSource)
    {
        var removed = 0;
        for (var i = targetList.Count - 1; i >= 0; i--)
        {
            if (Matches(targetList[i], targetSource))
            {
                targetList.RemoveAt(i);
                removed++;
            }
        }

        return removed;
    }

    /// <summary><c>true</c> when the list holds at least one entry <see cref="Remove" /> would remove.</summary>
    public static bool HasEntries(IAttributeValueList<RtClientUriEntryRecord>? list, string? targetSource) =>
        list != null && list.Any(entry => Matches(entry, targetSource));

    private static bool Matches(RtClientUriEntryRecord entry, string? targetSource) =>
        targetSource != null
            ? string.Equals(entry.Source, targetSource, StringComparison.Ordinal)
            : entry.Source.StartsWith(ClientUriSources.OverlayPrefix, StringComparison.Ordinal);
}

/// <summary>
///     Shared parts of the overlay handlers: caller rule (<see cref="IdentityMethodCallerRules.IsTenantAdministrator" />, the
///     REST policy of <c>ClientsController</c>), tenant binding, the CORS cache event, and exactly one <c>Identity.Method</c>
///     event per call (also when the call throws).
/// </summary>
internal abstract class ClientOverlayHandlerBase(IServiceProvider services)
{
    protected IServiceProvider Services { get; } = services;

    /// <summary>Checks the caller and binds the tenant; the failure to answer, or <c>null</c>.</summary>
    protected async Task<CkMethodFailure?> AdmitAsync(CkMethodPrincipal? principal, string tenantId)
    {
        if (!IdentityMethodCallerRules.IsTenantAdministrator(principal))
        {
            return CkMethodOutcome.Forbidden("role-required").Failure;
        }

        return await Services.GetRequiredService<IMethodTenantAccessor>().BindAsync(tenantId).ConfigureAwait(false)
            ? null
            : CkMethodOutcome.TargetNotFound().Failure;
    }

    /// <summary>Publishes the CORS client refresh of the tenant (a cache invalidation, cheap), as the REST endpoints did.</summary>
    protected Task PublishCorsRefreshAsync(IOctoClientStore clientStore) =>
        Services.GetRequiredService<IDistributionEventHubService>().PublishAsync(
            new CorsClientsUpdate(clientStore.TenantId, Guid.NewGuid(), DateTime.Now));

    /// <summary>Runs the call and writes its audit record with <paramref name="outcomeOf" />.</summary>
    protected async Task<CkMethodOutcome<TResult>> AuditedAsync<TParameters, TResult>(
        CkMethodContext<TParameters> context, Dictionary<string, string> details,
        Func<Task<CkMethodOutcome<TResult>>> run) where TParameters : class where TResult : class
    {
        var outcomeCode = "METHOD_HANDLER_FAILED";
        try
        {
            var outcome = await run().ConfigureAwait(false);
            outcomeCode = outcome.Failure?.Code ?? IdentityMethodAuditWriter.SuccessOutcome;
            return outcome;
        }
        finally
        {
            await Services.GetRequiredService<IIdentityMethodAuditWriter>().RecordAsync(context.TenantId,
                context.MethodId, context.InvocationId, context.TargetRtId, context.CallerPrincipal?.Subject,
                outcomeCode, details).ConfigureAwait(false);
        }
    }
}

/// <summary>
///     Handler of <c>System.Identity/Client.ApplyOverlayUris-1</c> (System.Identity 3.3.0): appends overlay URIs to the three
///     URI lists of a client. REST facade: <c>POST system/v1/clients/{client}/overlayUris</c>.
/// </summary>
/// <remarks>
///     One version-checked read-modify-write through <see cref="IOctoClientStore.MutateAsync" /> (the merge runs again on a
///     fresh read after a conflict, so the counts belong to the write that was stored); a re-run that adds nothing writes
///     nothing. A conflict the store cannot resolve is <c>CONCURRENT_CHANGE</c>. The CORS refresh is published after every
///     successful call, also when nothing was added: a re-apply is the repair for a policy cached before the origins existed.
///     Audit details: <c>clientId</c>, <c>overlayName</c>, <c>added</c>, <c>skipped</c>; never a URI.
/// </remarks>
internal sealed class ClientApplyOverlayUrisHandler(IServiceProvider services)
    : ClientOverlayHandlerBase(services), ICkMethodHandler<ClientApplyOverlayUrisParameters, ClientApplyOverlayUrisResult>
{
    public Task<CkMethodOutcome<ClientApplyOverlayUrisResult>> HandleAsync(
        CkMethodContext<ClientApplyOverlayUrisParameters> context, CancellationToken cancellationToken)
    {
        var details = new Dictionary<string, string>(StringComparer.Ordinal);
        return AuditedAsync(context, details, () => ApplyAsync(context, details, cancellationToken));
    }

    private async Task<CkMethodOutcome<ClientApplyOverlayUrisResult>> ApplyAsync(
        CkMethodContext<ClientApplyOverlayUrisParameters> context, Dictionary<string, string> details,
        CancellationToken cancellationToken)
    {
        if (await AdmitAsync(context.CallerPrincipal, context.TenantId).ConfigureAwait(false) is { } refused)
        {
            return refused;
        }

        if (string.IsNullOrWhiteSpace(context.TargetRtId) || !OctoObjectId.TryParse(context.TargetRtId, out var rtId))
        {
            return CkMethodOutcome<ClientApplyOverlayUrisResult>.TargetNotFound();
        }

        var parameters = context.Parameters;
        var overlayName = parameters.OverlayName ?? string.Empty;
        details["overlayName"] = overlayName;
        if (!ClientOverlayUris.OverlayName().IsMatch(overlayName))
        {
            return CkMethodOutcome<ClientApplyOverlayUrisResult>.Fail(ClientOverlayErrors.InvalidOverlayName);
        }

        if (ClientOverlayUris.CountNonWhitespace(parameters.RedirectUris) +
            ClientOverlayUris.CountNonWhitespace(parameters.PostLogoutRedirectUris) +
            ClientOverlayUris.CountNonWhitespace(parameters.AllowedCorsOrigins) == 0)
        {
            return CkMethodOutcome<ClientApplyOverlayUrisResult>.Fail(ClientOverlayErrors.NoOverlayUris);
        }

        var client = await ClientRoleMethodHandlerBase<ClientSetRolesParameters>.LoadClientAsync(Services, rtId)
            .ConfigureAwait(false);
        if (client == null || string.IsNullOrWhiteSpace(client.ClientId))
        {
            return CkMethodOutcome<ClientApplyOverlayUrisResult>.TargetNotFound();
        }

        // CWE-863: the target client's data permission, as the GraphQL gateway checks it before dispatch; the REST facade
        // calls in-process.
        var call = new IdentityMethodCall(Services, context.CallerPrincipal!);
        if (await call.CheckTargetWritableAsync(client.ToRtEntityId(), cancellationToken).ConfigureAwait(false) is
            { } denied)
        {
            foreach (var (key, value) in call.Details)
            {
                details[key] = value;
            }

            return CkMethodOutcome<ClientApplyOverlayUrisResult>.Fail(denied.Failure!);
        }

        details[ClientSecretMethodHandlerBase.ClientIdDetail] = client.ClientId;
        var sourceTag = ClientUriSources.OverlayPrefix + overlayName;
        (int Added, int Skipped) redirect = default, postLogout = default, cors = default;
        var clientStore = Services.GetRequiredService<IOctoClientStore>();
        RtClient? stored;
        var replaced = false;
        try
        {
            stored = await clientStore.MutateAsync(client.ClientId, current =>
            {
                // MutateAsync resolves the client id: never change another client that took over the id meanwhile. Set on
                // every run: the callback runs again after a version conflict.
                replaced = current.RtId != rtId;
                if (replaced)
                {
                    return false;
                }

                redirect = ClientOverlayUris.Append(current.RedirectUris, parameters.RedirectUris, sourceTag);
                postLogout = ClientOverlayUris.Append(current.PostLogoutRedirectUris,
                    parameters.PostLogoutRedirectUris, sourceTag);
                cors = ClientOverlayUris.Append(current.AllowedCorsOrigins, parameters.AllowedCorsOrigins, sourceTag);
                return redirect.Added + postLogout.Added + cors.Added > 0;
            }).ConfigureAwait(false);
        }
        catch (RtVersionConflictException)
        {
            return CkMethodOutcome<ClientApplyOverlayUrisResult>.Fail(ClientOverlayErrors.ConcurrentChange);
        }

        if (stored == null || replaced)
        {
            return CkMethodOutcome<ClientApplyOverlayUrisResult>.TargetNotFound();
        }

        await PublishCorsRefreshAsync(clientStore).ConfigureAwait(false);
        details["added"] = (redirect.Added + postLogout.Added + cors.Added).ToString(System.Globalization.CultureInfo.InvariantCulture);
        details["skipped"] = (redirect.Skipped + postLogout.Skipped + cors.Skipped).ToString(System.Globalization.CultureInfo.InvariantCulture);
        return new ClientApplyOverlayUrisResult
        {
            Value = new RtClientOverlayUrisResultRecord
            {
                OverlayName = overlayName,
                ClientId = stored.ClientId,
                RedirectUrisAdded = redirect.Added,
                RedirectUrisSkipped = redirect.Skipped,
                PostLogoutRedirectUrisAdded = postLogout.Added,
                PostLogoutRedirectUrisSkipped = postLogout.Skipped,
                AllowedCorsOriginsAdded = cors.Added,
                AllowedCorsOriginsSkipped = cors.Skipped
            }
        };
    }
}

/// <summary>
///     Handler of the static <c>System.Identity/Client.CleanOverlayEntries-1</c> (System.Identity 3.3.0): removes the overlay
///     entries of one overlay (or of every overlay) from every client of the tenant. REST facade:
///     <c>DELETE system/v1/clients/cleanOverlayEntries</c>.
/// </summary>
/// <remarks>
///     A client without a matching entry is never written. Each client is one version-checked read-modify-write; a conflict
///     the store cannot resolve stops the call with <c>CONCURRENT_CHANGE</c> (the clients cleaned before it stay cleaned, as
///     in REST). The CORS refresh is published once when anything was removed. Audit details: <c>overlayName</c>,
///     <c>clientsAffected</c>, <c>removed</c>.
/// </remarks>
internal sealed class ClientCleanOverlayEntriesHandler(IServiceProvider services)
    : ClientOverlayHandlerBase(services),
        ICkMethodHandler<ClientCleanOverlayEntriesParameters, ClientCleanOverlayEntriesResult>
{
    public Task<CkMethodOutcome<ClientCleanOverlayEntriesResult>> HandleAsync(
        CkMethodContext<ClientCleanOverlayEntriesParameters> context, CancellationToken cancellationToken)
    {
        var details = new Dictionary<string, string>(StringComparer.Ordinal);
        return AuditedAsync(context, details, () => CleanAsync(context, details, cancellationToken));
    }

    private async Task<CkMethodOutcome<ClientCleanOverlayEntriesResult>> CleanAsync(
        CkMethodContext<ClientCleanOverlayEntriesParameters> context, Dictionary<string, string> details,
        CancellationToken cancellationToken)
    {
        if (await AdmitAsync(context.CallerPrincipal, context.TenantId).ConfigureAwait(false) is { } refused)
        {
            return refused;
        }

        // A static method has no target entity: the GraphQL gateway checks the caller's Write permission on the declaring
        // type before dispatch; the REST facade calls in-process, where only the handler can check it.
        var call = new IdentityMethodCall(Services, context.CallerPrincipal!);
        if (await call.CheckTypeWritableAsync(RtEntityExtensions.GetRtCkTypeId<RtClient>(), cancellationToken)
                .ConfigureAwait(false) is { } denied)
        {
            foreach (var (key, value) in call.Details)
            {
                details[key] = value;
            }

            return CkMethodOutcome<ClientCleanOverlayEntriesResult>.Fail(denied);
        }

        var overlayName = context.Parameters.OverlayName;
        details["overlayName"] = overlayName ?? string.Empty;
        if (overlayName != null && !ClientOverlayUris.OverlayName().IsMatch(overlayName))
        {
            return CkMethodOutcome<ClientCleanOverlayEntriesResult>.Fail(ClientOverlayErrors.InvalidOverlayName);
        }

        var targetSource = overlayName != null ? ClientUriSources.OverlayPrefix + overlayName : null;
        var clientStore = Services.GetRequiredService<IOctoClientStore>();
        var entries = new List<RtClientOverlayCleanEntryRecord>();
        var totalRemoved = 0;
        foreach (var listed in await clientStore.GetClients().ConfigureAwait(false))
        {
            if (!ClientOverlayUris.HasEntries(listed.RedirectUris, targetSource) &&
                !ClientOverlayUris.HasEntries(listed.PostLogoutRedirectUris, targetSource) &&
                !ClientOverlayUris.HasEntries(listed.AllowedCorsOrigins, targetSource))
            {
                continue;
            }

            int redirect = 0, postLogout = 0, cors = 0;
            try
            {
                var stored = await clientStore.MutateAsync(listed.ClientId, current =>
                {
                    redirect = ClientOverlayUris.Remove(current.RedirectUris, targetSource);
                    postLogout = ClientOverlayUris.Remove(current.PostLogoutRedirectUris, targetSource);
                    cors = ClientOverlayUris.Remove(current.AllowedCorsOrigins, targetSource);
                    return redirect + postLogout + cors > 0;
                }).ConfigureAwait(false);
                if (stored == null)
                {
                    continue;
                }
            }
            catch (RtVersionConflictException)
            {
                // the clients cleaned before the conflict stay cleaned: the audit names what was changed
                RecordCounts(details, entries.Count, totalRemoved);
                await PublishIfChangedAsync(clientStore, totalRemoved).ConfigureAwait(false);
                return CkMethodOutcome<ClientCleanOverlayEntriesResult>.Fail(ClientOverlayErrors.ConcurrentChange);
            }
            catch
            {
                // any other failure: the removals before it are stored, so the cache is refreshed for them before the
                // failure propagates (a retry finds nothing left to remove and would not refresh it)
                RecordCounts(details, entries.Count, totalRemoved);
                try
                {
                    await PublishIfChangedAsync(clientStore, totalRemoved).ConfigureAwait(false);
                }
                catch (Exception publishFailure)
                {
                    // best effort: the original failure is the answer, the refresh failure is only logged
                    Services.GetRequiredService<ILogger<ClientCleanOverlayEntriesHandler>>().LogWarning(publishFailure,
                        "CORS refresh after a failed overlay clean could not be published in tenant {TenantId}",
                        context.TenantId);
                }

                throw;
            }

            var clientTotal = redirect + postLogout + cors;
            if (clientTotal == 0)
            {
                continue;
            }

            entries.Add(new RtClientOverlayCleanEntryRecord
            {
                ClientId = listed.ClientId,
                RedirectUrisRemoved = redirect,
                PostLogoutRedirectUrisRemoved = postLogout,
                AllowedCorsOriginsRemoved = cors
            });
            totalRemoved += clientTotal;
        }

        await PublishIfChangedAsync(clientStore, totalRemoved).ConfigureAwait(false);
        RecordCounts(details, entries.Count, totalRemoved);
        var result = new RtClientOverlayCleanResultRecord
        {
            OverlayName = overlayName,
            ClientsAffected = entries.Count,
            TotalEntriesRemoved = totalRemoved
        };
        foreach (var entry in entries)
        {
            result.ClientResults.Add(entry);
        }

        return new ClientCleanOverlayEntriesResult { Value = result };
    }

    private static void RecordCounts(Dictionary<string, string> details, int clientsAffected, int removed)
    {
        details["clientsAffected"] = clientsAffected.ToString(System.Globalization.CultureInfo.InvariantCulture);
        details["removed"] = removed.ToString(System.Globalization.CultureInfo.InvariantCulture);
    }

    private Task PublishIfChangedAsync(IOctoClientStore clientStore, int totalRemoved) =>
        totalRemoved > 0 ? PublishCorsRefreshAsync(clientStore) : Task.CompletedTask;
}
