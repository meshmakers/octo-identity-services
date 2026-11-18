using Meshmakers.Octo.Backend.IdentityServices.Authorization.RoleChange;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Services.Methods;
using Microsoft.AspNetCore.Identity;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;

namespace Meshmakers.Octo.Backend.IdentityServices.Methods;

/// <summary>Declared errors and audit details of the role, group, API scope and API resource CRUD methods (System.Identity 3.7.0).</summary>
internal static class IdentityCrudErrors
{
    /// <summary>A role with this name exists.</summary>
    public const string RoleAlreadyExists = "ROLE_ALREADY_EXISTS";

    /// <summary>A group with this name exists.</summary>
    public const string GroupAlreadyExists = "GROUP_ALREADY_EXISTS";

    /// <summary>An API scope with this name exists.</summary>
    public const string ApiScopeAlreadyExists = "API_SCOPE_ALREADY_EXISTS";

    /// <summary>An API resource with this name exists.</summary>
    public const string ApiResourceAlreadyExists = "API_RESOURCE_ALREADY_EXISTS";

    /// <summary>The API resource was changed concurrently; retry.</summary>
    public const string ConcurrentChange = "CONCURRENT_CHANGE";

    /// <summary>Audit detail: the name of the entity before the call (update, delete).</summary>
    public const string NameBeforeDetail = "nameBefore";

    /// <summary>Audit detail: the name of the entity after the call (create, update).</summary>
    public const string NameDetail = "name";
}

/// <summary>Maps an <see cref="IdentityResult" /> of the role manager onto the declared answers of the role methods.</summary>
internal static class RoleManagerResults
{
    /// <summary>
    ///     The failure of a role create or rename: <c>ROLE_ALREADY_EXISTS</c> for a duplicate name, a validation failure of
    ///     <c>name</c> for an invalid one. Anything else is unexpected and throws (<c>METHOD_HANDLER_FAILED</c>, no store text).
    /// </summary>
    public static CkMethodFailure FailureOf(IdentityResult result, string operation)
    {
        var codes = result.Errors.Select(e => e.Code).ToList();
        if (codes.Contains(nameof(IdentityErrorDescriber.DuplicateRoleName)))
        {
            return new CkMethodFailure(IdentityCrudErrors.RoleAlreadyExists);
        }

        if (codes.Contains(nameof(IdentityErrorDescriber.InvalidRoleName)))
        {
            return CkMethodOutcome.ValidationFailed("name", "invalid").Failure!;
        }

        throw new InvalidOperationException($"{operation} failed ({string.Join(",", codes)}).");
    }
}

/// <summary>
///     Handler of the static <c>System.Identity/Role.CreateRole-1</c> (System.Identity 3.7.0): creates a role through the role
///     manager, as <c>POST system/v1/roles</c> did (the name is stored as sent, the normalized name is derived by the role
///     manager). REST is its facade.
/// </summary>
internal sealed class RoleCreateRoleHandler(IServiceProvider services)
    : IdentityCreateMethodHandlerBase<RoleCreateRoleParameters, RoleCreateRoleResult>(services)
{
    protected override RtCkId<CkTypeId> DeclaringType => RtEntityExtensions.GetRtCkTypeId<RtRole>();

    protected override async Task<CkMethodOutcome<RoleCreateRoleResult>> CreateAsync(IdentityMethodCall call,
        RoleCreateRoleParameters parameters, CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(parameters.Name))
        {
            return CkMethodOutcome<RoleCreateRoleResult>.ValidationFailed("name", "required");
        }

        call.Details[IdentityCrudErrors.NameDetail] = parameters.Name;
        var role = new RtRole { Name = parameters.Name };
        var result = await call.Services.GetRequiredService<RoleManager<RtRole>>().CreateAsync(role).ConfigureAwait(false);
        if (!result.Succeeded)
        {
            return CkMethodOutcome<RoleCreateRoleResult>.Fail(RoleManagerResults.FailureOf(result, "Creating the role"));
        }

        return new RoleCreateRoleResult { Value = role.RtId.ToString() };
    }

    protected override string? CreatedRtIdOf(RoleCreateRoleResult result) => result.Value;
}

/// <summary>
///     Handler of <c>System.Identity/Role.UpdateRole-1</c> (System.Identity 3.7.0): renames a role, as
///     <c>PUT system/v1/roles/{roleName}</c> did. A built-in role is refused by the role change guard
///     (<c>METHOD_FORBIDDEN</c>, <c>reason</c> <c>built-in-role</c>); its REST facade turns that back into the audited 409.
///     Holders keep the role (they hold it by id); the next token and authorization check use the new name.
/// </summary>
internal sealed class RoleUpdateRoleHandler(IServiceProvider services)
    : IdentityAdminMethodHandlerBase<RoleUpdateRoleParameters>(services)
{
    protected override async Task<CkMethodOutcome> ApplyAsync(IdentityMethodCall call, OctoObjectId targetRtId,
        RoleUpdateRoleParameters parameters, CancellationToken cancellationToken)
    {
        var roleManager = call.Services.GetRequiredService<RoleManager<RtRole>>();
        var role = await roleManager.FindByIdAsync(targetRtId.ToString()).ConfigureAwait(false);
        if (role == null)
        {
            return CkMethodOutcome.TargetNotFound();
        }

        call.Details[IdentityCrudErrors.NameBeforeDetail] = role.Name ?? string.Empty;
        // The guard first, as REST: a built-in role is refused whatever the new name is (also an empty one).
        var newName = string.IsNullOrEmpty(parameters.Name) ? null : parameters.Name;
        var decision = call.Services.GetRequiredService<IRoleChangeGuard>().EvaluateRoleDefinition(role, newName);
        if (!decision.IsAllowed)
        {
            return call.Refuse(decision);
        }

        if (newName == null)
        {
            return CkMethodOutcome.ValidationFailed("name", "required");
        }

        call.Details[IdentityCrudErrors.NameDetail] = newName;

        role.Name = newName;
        var result = await roleManager.UpdateAsync(role).ConfigureAwait(false);
        return result.Succeeded
            ? CkMethodOutcome.Ok()
            : CkMethodOutcome.Fail(RoleManagerResults.FailureOf(result, "Renaming the role"));
    }
}

/// <summary>
///     Handler of <c>System.Identity/Role.DeleteRole-1</c> (System.Identity 3.7.0): deletes a role, as
///     <c>DELETE system/v1/roles/{roleName}</c> did. A built-in role is refused by the role change guard.
/// </summary>
internal sealed class RoleDeleteRoleHandler(IServiceProvider services)
    : IdentityAdminMethodHandlerBase<RoleDeleteRoleParameters>(services)
{
    protected override async Task<CkMethodOutcome> ApplyAsync(IdentityMethodCall call, OctoObjectId targetRtId,
        RoleDeleteRoleParameters parameters, CancellationToken cancellationToken)
    {
        var roleManager = call.Services.GetRequiredService<RoleManager<RtRole>>();
        var role = await roleManager.FindByIdAsync(targetRtId.ToString()).ConfigureAwait(false);
        if (role == null)
        {
            return CkMethodOutcome.TargetNotFound();
        }

        call.Details[IdentityCrudErrors.NameBeforeDetail] = role.Name ?? string.Empty;
        var decision = call.Services.GetRequiredService<IRoleChangeGuard>().EvaluateRoleDefinition(role, null);
        if (!decision.IsAllowed)
        {
            return call.Refuse(decision);
        }

        var result = await roleManager.DeleteAsync(role).ConfigureAwait(false);
        if (!result.Succeeded)
        {
            throw new InvalidOperationException(
                $"Deleting the role failed ({string.Join(",", result.Errors.Select(e => e.Code))}).");
        }

        return CkMethodOutcome.Ok();
    }
}
