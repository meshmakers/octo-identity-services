using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Backend.IdentityServices.Authorization.RoleChange;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.DataPermissions;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Meshmakers.Octo.Services.Methods;
using Meshmakers.Octo.Services.Methods.Authorization;
using Microsoft.AspNetCore.Identity;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;

namespace Meshmakers.Octo.Backend.IdentityServices.Methods;

/// <summary>
///     Shared flow of <c>Client.SetRoles</c>, <c>Client.AddRole</c> and <c>Client.RemoveRole</c> (System.Identity 3.3.0): the
///     rules of the REST endpoints <c>PUT system/v1/clients/{client}/roles[/{role}]</c> and
///     <c>DELETE .../roles/{role}</c> of <c>ClientsController</c>, which are their facades.
/// </summary>
/// <remarks>
///     <para>
///         <b>Caller.</b> The REST policy <c>IdentityTenantAdministrationWritePolicy</c>: scope <c>octo_api</c> and the tenant
///         role <c>TenantManagement</c> or <c>UserManagement</c> (<see cref="IdentityMethodCallerRules.IsTenantAdministrator" />),
///         checked on the principal the host validated.
///     </para>
///     <para>
///         <b>Roles.</b> Only the directly assigned roles (<c>AssignedRole</c>) are read and written; a role that is unknown or
///         that the caller cannot read is <c>ROLE_NOT_FOUND</c> and nothing changes. Only the difference is written,
///         so a kept role is never written again. Every role the call adds runs the client grant rule of the role change
///         guard: a built-in role the caller does not hold is refused (<c>role-not-held</c>) and a client-credentials
///         caller cannot give its own client a role (<c>self-grant</c>); removals are never judged, as in REST. A refusal is
///         <c>METHOD_FORBIDDEN</c> with <c>reason</c> (and <c>roleNames</c>), the same answer as the user role methods.
///     </para>
///     <para>
///         <b>Audit.</b> One <c>Identity.Method</c> event per call with <c>clientId</c>, <c>rolesBefore</c> and
///         <c>rolesAfter</c> (role names). Nothing is revoked: a role change shows in the next token of the client.
///     </para>
/// </remarks>
internal abstract class ClientRoleMethodHandlerBase<TParameters>(IServiceProvider services)
    : IdentityAdminMethodHandlerBase<TParameters>(services) where TParameters : class
{
    protected override bool IsAdmitted(CkMethodPrincipal principal) =>
        IdentityMethodCallerRules.IsTenantAdministrator(principal);

    /// <summary>Applies the change; the client exists, <paramref name="current" /> holds its direct role ids.</summary>
    protected abstract Task<CkMethodOutcome> ApplyRolesAsync(IdentityMethodCall call, RtClient client,
        IReadOnlySet<string> current, TParameters parameters, CancellationToken cancellationToken);

    protected sealed override async Task<CkMethodOutcome> ApplyAsync(IdentityMethodCall call, OctoObjectId targetRtId,
        TParameters parameters, CancellationToken cancellationToken)
    {
        var client = await LoadClientAsync(call.Services, targetRtId).ConfigureAwait(false);
        if (client == null || string.IsNullOrWhiteSpace(client.ClientId))
        {
            return CkMethodOutcome.TargetNotFound();
        }

        call.Details[ClientSecretMethodHandlerBase.ClientIdDetail] = client.ClientId;
        var current = (await call.Services.GetRequiredService<IClientRoleStore>().GetDirectRoleIdsAsync(client.RtId)
            .ConfigureAwait(false)).ToHashSet(StringComparer.Ordinal);
        call.Details["rolesBefore"] = await NamesAsync(call, current).ConfigureAwait(false);
        call.Details["rolesAfter"] = call.Details["rolesBefore"];
        return await ApplyRolesAsync(call, client, current, parameters, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    ///     The role named <paramref name="roleName" />, or <c>null</c> when it does not exist or the caller cannot read it
    ///     (not visible answers like missing).
    /// </summary>
    protected static async Task<RtRole?> FindReadableRoleAsync(IdentityMethodCall call, string? roleName,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(roleName))
        {
            return null;
        }

        var role = await call.Services.GetRequiredService<RoleManager<RtRole>>().FindByNameAsync(roleName.Trim())
            .ConfigureAwait(false);
        if (role == null)
        {
            return null;
        }

        var verdict = await call.EvaluateAsync(new RtEntityId(RtEntityExtensions.GetRtCkTypeId<RtRole>(), role.RtId),
            RtDataAction.Read, cancellationToken).ConfigureAwait(false);
        return verdict.IsAllowed ? role : null;
    }

    /// <summary>The client grant rule of the role change guard for the added roles; <c>null</c> when allowed or nothing is added.</summary>
    protected static async Task<CkMethodOutcome?> GuardGrantAsync(IdentityMethodCall call, RtClient client,
        IReadOnlyCollection<string> addedRoleNames, CancellationToken cancellationToken)
    {
        if (addedRoleNames.Count == 0)
        {
            return null;
        }

        var decision = await call.Services.GetRequiredService<IRoleChangeGuard>()
            .EvaluateClientGrantAsync(call.Caller, client, addedRoleNames, cancellationToken).ConfigureAwait(false);
        return decision.IsAllowed ? null : call.Refuse(decision);
    }

    /// <summary>Records the direct roles after the call in the audit details.</summary>
    protected static async Task RecordAfterAsync(IdentityMethodCall call, IEnumerable<string> roleIds) =>
        call.Details["rolesAfter"] = await NamesAsync(call, roleIds).ConfigureAwait(false);

    /// <summary>A <c>ROLE_NOT_FOUND</c> answer naming the role.</summary>
    protected static CkMethodOutcome RoleNotFound(string? roleName) =>
        CkMethodOutcome.Fail(new CkMethodFailure(UserRoleMethodErrors.RoleNotFound,
            new Dictionary<string, string> { [UserRoleMethodErrors.RoleNameParameter] = roleName ?? string.Empty }));

    /// <summary>Reads the client by rtId in the bound tenant.</summary>
    internal static async Task<RtClient?> LoadClientAsync(IServiceProvider services, OctoObjectId rtId)
    {
        var repository = services.GetRequiredService<IMultiTenancyResolverService>().GetTenantRepository();
        using var session = await repository.GetSessionAsync().ConfigureAwait(false);
        session.StartTransaction();
        var client = await repository.GetRtEntityByRtIdAsync<RtClient>(session, rtId).ConfigureAwait(false);
        await session.CommitTransactionAsync().ConfigureAwait(false);
        return client;
    }

    private static async Task<string> NamesAsync(IdentityMethodCall call, IEnumerable<string> roleIds)
    {
        var roleManager = call.Services.GetRequiredService<RoleManager<RtRole>>();
        var names = new List<string>();
        foreach (var id in roleIds)
        {
            var role = await roleManager.FindByIdAsync(id).ConfigureAwait(false);
            names.Add(role?.Name ?? id);
        }

        return string.Join(",", names.Order(StringComparer.OrdinalIgnoreCase));
    }
}

/// <summary>
///     Handler of <c>System.Identity/Client.SetRoles-1</c> (System.Identity 3.3.0): replaces the direct roles of a client by
///     the given role names. All names are resolved first; one unknown name changes nothing (<c>ROLE_NOT_FOUND</c>). Only the
///     added roles are judged by the guard, and only the difference is written.
/// </summary>
internal sealed class ClientSetRolesHandler(IServiceProvider services)
    : ClientRoleMethodHandlerBase<ClientSetRolesParameters>(services)
{
    protected override async Task<CkMethodOutcome> ApplyRolesAsync(IdentityMethodCall call, RtClient client,
        IReadOnlySet<string> current, ClientSetRolesParameters parameters, CancellationToken cancellationToken)
    {
        var wanted = new HashSet<string>(StringComparer.Ordinal);
        var addedIds = new List<string>();
        var addedNames = new List<string>();
        foreach (var name in parameters.RoleNames ?? [])
        {
            var role = await FindReadableRoleAsync(call, name, cancellationToken).ConfigureAwait(false);
            if (role == null)
            {
                return RoleNotFound(name);
            }

            var id = role.RtId.ToString();
            if (wanted.Add(id) && !current.Contains(id))
            {
                addedIds.Add(id);
                addedNames.Add(role.Name ?? id);
            }
        }

        var refusal = await GuardGrantAsync(call, client, addedNames, cancellationToken).ConfigureAwait(false);
        if (refusal != null)
        {
            return refusal;
        }

        var removedIds = current.Where(id => !wanted.Contains(id)).ToList();
        if (addedIds.Count > 0 || removedIds.Count > 0)
        {
            await call.Services.GetRequiredService<IClientRoleStore>()
                .ApplyRoleChangesAsync(client.RtId, addedIds, removedIds).ConfigureAwait(false);
        }

        await RecordAfterAsync(call, wanted).ConfigureAwait(false);
        return CkMethodOutcome.Ok();
    }
}

/// <summary>
///     Handler of <c>System.Identity/Client.AddRole-1</c> (System.Identity 3.3.0): assigns a role to a client. A role the
///     client already holds directly is a success without a write (REST answered <c>200</c> and wrote nothing).
/// </summary>
internal sealed class ClientAddRoleHandler(IServiceProvider services)
    : ClientRoleMethodHandlerBase<ClientAddRoleParameters>(services)
{
    protected override async Task<CkMethodOutcome> ApplyRolesAsync(IdentityMethodCall call, RtClient client,
        IReadOnlySet<string> current, ClientAddRoleParameters parameters, CancellationToken cancellationToken)
    {
        var role = await FindReadableRoleAsync(call, parameters.RoleName, cancellationToken).ConfigureAwait(false);
        if (role == null)
        {
            return RoleNotFound(parameters.RoleName);
        }

        var id = role.RtId.ToString();
        if (current.Contains(id))
        {
            return CkMethodOutcome.Ok();
        }

        var refusal = await GuardGrantAsync(call, client, [role.Name ?? id], cancellationToken).ConfigureAwait(false);
        if (refusal != null)
        {
            return refusal;
        }

        await call.Services.GetRequiredService<IClientRoleStore>().ApplyRoleChangesAsync(client.RtId, [id], [])
            .ConfigureAwait(false);
        await RecordAfterAsync(call, current.Append(id)).ConfigureAwait(false);
        return CkMethodOutcome.Ok();
    }
}

/// <summary>
///     Handler of <c>System.Identity/Client.RemoveRole-1</c> (System.Identity 3.3.0): removes a direct role from a client. A
///     role the client does not hold is a success without a write; an unknown role is <c>ROLE_NOT_FOUND</c> (the REST facade
///     keeps its <c>200</c>). No guard: a removal gives nothing to anybody and clients do not count as administrators.
/// </summary>
internal sealed class ClientRemoveRoleHandler(IServiceProvider services)
    : ClientRoleMethodHandlerBase<ClientRemoveRoleParameters>(services)
{
    protected override async Task<CkMethodOutcome> ApplyRolesAsync(IdentityMethodCall call, RtClient client,
        IReadOnlySet<string> current, ClientRemoveRoleParameters parameters, CancellationToken cancellationToken)
    {
        var role = await FindReadableRoleAsync(call, parameters.RoleName, cancellationToken).ConfigureAwait(false);
        if (role == null)
        {
            return RoleNotFound(parameters.RoleName);
        }

        var id = role.RtId.ToString();
        if (!current.Contains(id))
        {
            return CkMethodOutcome.Ok();
        }

        await call.Services.GetRequiredService<IClientRoleStore>().ApplyRoleChangesAsync(client.RtId, [], [id])
            .ConfigureAwait(false);
        await RecordAfterAsync(call, current.Where(r => r != id)).ConfigureAwait(false);
        return CkMethodOutcome.Ok();
    }
}
