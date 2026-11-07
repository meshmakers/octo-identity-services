using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Text.Json;
using Asp.Versioning;
using IdentityServerPersistence;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Backend.IdentityServices.Authorization.RoleChange;
using Meshmakers.Octo.Backend.IdentityServices.Methods;
using Meshmakers.Octo.Backend.IdentityServices.OpenIddict;
using Meshmakers.Octo.Backend.IdentityServices.Services;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects.ApiErrors;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Methods;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Meshmakers.Octo.Services.Methods;
using Meshmakers.Octo.Services.Methods.Facades;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using MongoDB.Bson;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Meshmakers.Octo.Backend.Authentication;
using Meshmakers.Octo.Backend.IdentityServices.Mapping;

namespace Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;

/// <summary>
///     REST Controller for user management
/// </summary>
[Authorize(AuthenticationSchemes = AuthenticationConstants.BearerAuthenticationScheme)]
[Route(IdentityServiceConstants.ApiPathPrefix + "/[controller]")]
[ApiController]
[ApiVersion(IdentityServiceConstants.ApiVersion1)]
public class UsersController : ControllerBase
{
    /// <summary>500 message of <c>POST users</c> when the user was created but <c>ResetPasswordOnLogin</c> could not be set.</summary>
    internal const string ResetPasswordOnLoginNotSetMessage =
        "The user was created, but ResetPasswordOnLogin could not be set.";

    // AB#5708: the xt_ prefix marks cross-tenant shadow users, whose name is trusted to unwind to the
    // person's home identity (roles, allowed_tenants, token exchange). A local user carrying it could
    // impersonate another tenant's user.
    internal const string ReservedUserNameMessage =
        "User names starting with 'xt_' are reserved for cross-tenant users.";

    private readonly ILogger<UsersController> _logger;
    private readonly RoleManager<RtRole> _roleManager;
    private readonly IMultiTenancyResolverService _multiTenancyResolverService;
    private readonly IUserEmailInteractionService _userEmailInteractionService;
    private readonly UserManager<RtUser> _userManager;
    private readonly OctoUserStore _octoUserStore;
    private readonly IUserSessionRevocationService _userSessionRevocationService;
    private readonly IRoleChangeGuard _roleChangeGuard;
    private readonly IIdentityAuditService _identityAuditService;
    private readonly IIdentityMethodFacade _methodFacade;

    /// <summary>
    ///     Constructor
    /// </summary>
    /// <param name="userManager">The storage service of users</param>
    /// <param name="roleManager">The storage service of roles</param>
    /// <param name="multiTenancyResolverService">Multi-tenancy resolver service</param>
    /// <param name="userEmailInteractionService"></param>
    /// <param name="userStore">The user store for direct role queries</param>
    /// <param name="userSessionRevocationService">Revokes all sessions and tokens of a user (AB#7899)</param>
    /// <param name="roleChangeGuard">Self-grant, role-not-held and last-administrator rules (AB#7914)</param>
    /// <param name="identityAuditService">Audit of refused role changes</param>
    /// <param name="methodFacade">Calls the <c>User</c> methods the role, merge, create and password reset endpoints serve (AB#8412, AB#8413)</param>
    /// <param name="logger">Logger</param>
    public UsersController(
        UserManager<RtUser> userManager,
        RoleManager<RtRole> roleManager,
        IMultiTenancyResolverService multiTenancyResolverService,
        IUserEmailInteractionService userEmailInteractionService,
        IUserStore<RtUser> userStore,
        IUserSessionRevocationService userSessionRevocationService,
        IRoleChangeGuard roleChangeGuard,
        IIdentityAuditService identityAuditService,
        IIdentityMethodFacade methodFacade,
        ILogger<UsersController> logger)
    {
        _userManager = userManager;
        _roleManager = roleManager;
        _multiTenancyResolverService = multiTenancyResolverService;
        _userEmailInteractionService = userEmailInteractionService;
        _octoUserStore = (OctoUserStore)userStore;
        _userSessionRevocationService = userSessionRevocationService;
        _roleChangeGuard = roleChangeGuard;
        _identityAuditService = identityAuditService;
        _methodFacade = methodFacade;
        _logger = logger;
    }

    // GET system/v1/users
    /// <summary>
    ///     Returns all existing users
    /// </summary>
    /// <returns></returns>
    [HttpGet]
    [Authorize(IdentityServiceConstants.IdentityUserAdministrationReadPolicy)]
    [EndpointSummary("Returns all existing users.")]
    [ProducesResponseType(typeof(IEnumerable<UserDto>), StatusCodes.Status200OK)]
    public IEnumerable<UserDto> Get()
    {
        var list = _userManager.Users.AsEnumerable().Select(user => user.ToDto()).ToList();

        return list;
    }

    // GET system/v1/users/getPaged
    /// <summary>
    ///     Returns all existing users
    /// </summary>
    /// <returns></returns>
    [HttpGet("GetPaged")]
    [Authorize(IdentityServiceConstants.IdentityUserAdministrationReadPolicy)]
    [EndpointSummary("Returns all existing users.")]
    [ProducesResponseType(typeof(IEnumerable<UserDto>), StatusCodes.Status200OK)]
    public PagedResult<UserDto> Get([Required][FromQuery] PagingParams pagingParams)
    {
        var list = new List<UserDto>();
        foreach (var rtUser in _userManager.Users.Skip(pagingParams.Skip).Take(pagingParams.Take))
        {
            var userDto = rtUser.ToDto();
            list.Add(userDto);
        }

        var pagedResult =
            new PagedResult<UserDto>(list, pagingParams.Skip, pagingParams.Take, _userManager.Users.Count());

        var header = pagedResult.GetHeader();
        if (header != null)
        {
            Response.Headers.Append("X-Pagination", header.ToJson());
        }

        return pagedResult;
    }

    // GET system/v1/users/directory
    /// <summary>
    ///     The slim user directory of the tenant: id and display name of every user, for pickers that every
    ///     signed-in user of the tenant may use (AB#5859).
    /// </summary>
    /// <remarks>
    ///     No role is required — unlike <c>getPaged</c>, which needs <c>UserManagement</c> and returns e-mail
    ///     and logins. Instead the token must have been issued for this tenant
    ///     (<see cref="Authorization.IdentityApiOwnTenantRequirement" />). The search matches the display
    ///     name only (case-insensitive substring), so it cannot be used to probe e-mail addresses or user
    ///     names hidden behind a first/last name. Sorted by display name, then id, for stable paging.
    /// </remarks>
    [HttpGet("directory")]
    [Authorize(IdentityServiceConstants.IdentityUserDirectoryReadPolicy)]
    [EndpointSummary("Returns id and display name of the tenant's users (no e-mail, roles or groups).")]
    [ProducesResponseType(typeof(PagedResult<UserDirectoryEntryDto>), StatusCodes.Status200OK)]
    public PagedResult<UserDirectoryEntryDto> GetDirectory(
        [FromQuery] [Description("Number of entries to skip (default 0)")] int skip = 0,
        [FromQuery] [Description("Number of entries to return, 1..500 (default 100)")] int take = 100,
        [FromQuery] [Description("Optional case-insensitive substring of the display name")] string? search = null)
    {
        skip = Math.Max(0, skip);
        take = Math.Clamp(take, 1, MaxDirectoryPageSize);
        var term = search?.Trim();

        var entries = _userManager.Users.ToList()
            .Select(ToDirectoryEntry)
            .Where(e => string.IsNullOrEmpty(term) ||
                        e.DisplayName.Contains(term, StringComparison.OrdinalIgnoreCase))
            .OrderBy(e => e.DisplayName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(e => e.UserId, StringComparer.Ordinal)
            .ToList();

        var pagedResult = new PagedResult<UserDirectoryEntryDto>(entries.Skip(skip).Take(take), skip, take,
            entries.Count);

        var header = pagedResult.GetHeader();
        if (header != null)
        {
            Response.Headers.Append("X-Pagination", header.ToJson());
        }

        return pagedResult;
    }

    internal const int MaxDirectoryPageSize = 500;

    internal static UserDirectoryEntryDto ToDirectoryEntry(RtUser user)
    {
        var fullName = string.Join(' ',
            new[] { user.FirstName, user.LastName }.Where(n => !string.IsNullOrWhiteSpace(n))
                .Select(n => n!.Trim()));
        return new UserDirectoryEntryDto
        {
            UserId = user.RtId.ToString(),
            DisplayName = fullName.Length > 0 ? fullName : user.UserName ?? string.Empty
        };
    }

    // GET system/v1/users/{userName}
    [HttpGet("{userName}")]
    [Authorize(IdentityServiceConstants.IdentityUserAdministrationReadPolicy)]
    [EndpointSummary("Returns user information based on it's userName, email or id")]
    [ProducesResponseType(typeof(UserDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> Get([Required][Description("Name of the user")] string userName)
    {
        var rtUser = await _userManager.FindByNameAsync(userName) ??
                     await _userManager.FindByEmailAsync(userName) ??
                     await _userManager.FindByIdAsync(userName);
        if (rtUser == null)
        {
            return NotFound();
        }

        var userDto = rtUser.ToDto();
        return Ok(userDto);
    }

    // GET system/v1/users/{userName}
    [HttpGet("{userName}/roles")]
    [Authorize(IdentityServiceConstants.IdentityUserAdministrationReadPolicy)]
    [EndpointSummary("Returns user roles based on it's userName, email or id")]
    [ProducesResponseType(typeof(IEnumerable<RoleDto>), StatusCodes.Status200OK)]
    public async Task<IActionResult> GetUserRoles([Required][Description("Name of the user")] string userName)
    {
        var octoUser = await _userManager.FindByNameAsync(userName) ??
                       await _userManager.FindByEmailAsync(userName) ??
                       await _userManager.FindByIdAsync(userName);
        if (octoUser == null)
        {
            return NotFound();
        }


        // Get role names via UserManager (which queries AssignedRole associations + group roles)
        var roleNames = await _userManager.GetRolesAsync(octoUser);
        List<RoleDto> roles = new();
        foreach (var roleName in roleNames)
        {
            var role = await _roleManager.FindByNameAsync(roleName);
            if (role != null)
            {
                roles.Add(role.ToDto());
            }
        }

        return Ok(roles);
    }

    // GET system/v1/users/{userName}/directRoles
    [HttpGet("{userName}/directRoles")]
    [Authorize(IdentityServiceConstants.IdentityUserAdministrationReadPolicy)]
    [EndpointSummary("Returns only directly assigned user roles (excluding group-inherited roles)")]
    [ProducesResponseType(typeof(IEnumerable<RoleDto>), StatusCodes.Status200OK)]
    public async Task<IActionResult> GetUserDirectRoles([Required][Description("Name of the user")] string userName)
    {
        var octoUser = await _userManager.FindByNameAsync(userName) ??
                       await _userManager.FindByEmailAsync(userName) ??
                       await _userManager.FindByIdAsync(userName);
        if (octoUser == null)
        {
            return NotFound();
        }

        var roleNames = await _octoUserStore.GetDirectRolesAsync(octoUser);
        List<RoleDto> roles = new();
        foreach (var roleName in roleNames)
        {
            var role = await _roleManager.FindByNameAsync(roleName);
            if (role != null)
            {
                roles.Add(role.ToDto());
            }
        }

        return Ok(roles);
    }

    // POST system/v1/users
    /// <summary>
    ///     Creates a new user with an initial password. Facade of the static CK method <c>User.CreateUser-1</c> (AB#8413).
    /// </summary>
    /// <remarks>
    ///     The endpoint calls <c>User.CreateUser</c> in-process (the password never reaches the broker, also while
    ///     <c>Methods:Identity:EnablePasswordMethods</c> keeps the method off the bus): normalised user name and e-mail, user
    ///     validators, password policy, welcome notification, one <c>Identity.Method</c> audit event. Routes, bodies and status
    ///     codes are unchanged; see the parity table in the identity <c>CLAUDE.md</c>.
    /// </remarks>
    [HttpPost]
    [Authorize(IdentityServiceConstants.IdentityUserAdministrationWritePolicy)]
    [EndpointSummary("Creates a new user.")]
    [EndpointDescription("Refuses a user name or an e-mail address another user of the tenant already has (case-insensitive) " +
                         "with 409 application/problem+json, code USER_ALREADY_EXISTS, field userName or email - the same " +
                         "rule as the CK method User.CreateUser-1, which this endpoint calls. A taken user name wins over a " +
                         "taken e-mail address.")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status409Conflict)]
    public async Task<IActionResult> Post(
        [Required] [FromBody] [Description("The user data transfer object instance")]
        RegisterUserDto userDto)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        if (CrossTenantShadowUserName.IsShadowUserName(userDto.Name))
        {
            return BadRequest(ReservedUserNameMessage);
        }

        const string operation = "Creation of user failed";
        var response = await _methodFacade.InvokeAsync(IdentityMethodFacade.UserCkTypeId,
            SystemIdentityCkIds.UserCreateUserMethodId, null,
            new UserCreateUserParameters
            {
                UserName = userDto.Name ?? string.Empty,
                Email = userDto.Email,
                FirstName = userDto.FirstName,
                LastName = userDto.LastName,
                Password = userDto.Password
            }, User, HttpContext.RequestAborted);

        if (response.Success)
        {
            // The method has no parameter for the REST-only flag; keep the REST payload meaning (AB#8413 parity table).
            // A lost flag must not look like success: the user would keep the administrator-chosen password.
            if (userDto.ResetPasswordOnLogin && !await SetResetPasswordOnLoginAsync(response))
            {
                return StatusCode(StatusCodes.Status500InternalServerError,
                    new InternalServerErrorDto(ResetPasswordOnLoginNotSetMessage));
            }

            return Ok();
        }

        return response.ToActionResult(new CkMethodFacadeOptions()
            .MapError(UserCreateUserHandler.UserNameReserved, _ => BadRequest(ReservedUserNameMessage))
            .MapError(UserCreateUserHandler.UserAlreadyExists, error =>
                error.Parameters.GetValueOrDefault(CkMethodErrorParameters.Field) == UserCreationProblems.EmailField
                    ? UserCreationProblems.DuplicateEmail()
                    : UserCreationProblems.DuplicateUserName())
            .MapError(UserCreateUserHandler.PasswordPolicyViolation, error =>
                BadRequest(new OperationFailedErrorDto(operation, DescribeIdentityErrors(error))))
            .MapError(CkMethodErrorCodes.MethodValidationFailed, error =>
                BadRequest(new OperationFailedErrorDto(operation, [DescribeValidationFailure(error, userDto)])))
            .MapError(CkMethodErrorCodes.MethodHandlerFailed, _ =>
                StatusCode(StatusCodes.Status500InternalServerError, new InternalServerErrorDto(operation + "."))));
    }

    /// <summary>
    ///     Sets the REST-only flag <c>ResetPasswordOnLogin</c> on the user <c>User.CreateUser</c> just created.
    /// </summary>
    /// <returns><c>false</c> when the created user is not found or the update fails; the caller answers 500.</returns>
    private async Task<bool> SetResetPasswordOnLoginAsync(CkMethodResponse response)
    {
        // The result of User.CreateUser is the bare rtId string on the wire (UserCreateUserWireFormTests).
        var rtId = response.ResultJson == null ? null : JsonSerializer.Deserialize<string>(response.ResultJson);
        var user = rtId == null ? null : await _userManager.FindByIdAsync(rtId);
        if (user == null)
        {
            _logger.LogError("Create user (ResetPasswordOnLogin): the created user {RtId} was not found", rtId);
            return false;
        }

        user.ResetPasswordOnLogin = true;
        var result = await _userManager.UpdateAsync(user);
        if (!result.Succeeded)
        {
            LogIdentityError("Create user (ResetPasswordOnLogin)", result.Errors);
            return false;
        }

        return true;
    }

    // PUT system/v1/users/5
    [HttpPut("{userName}")]
    [Authorize(IdentityServiceConstants.IdentityUserAdministrationWritePolicy)]
    [EndpointSummary("Updates a user.")]
    [EndpointDescription("Refuses renaming the user to a user name, or changing the e-mail address to one, another user of " +
                         "the tenant already has (case-insensitive) with 409 application/problem+json, code " +
                         "USER_ALREADY_EXISTS, field userName or email - the same answer as the create. Keeping the current address is never checked, so users that already share an address stay " +
                         "editable.")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status409Conflict)]
    public async Task<IActionResult> Put(
        [Required] [Description("The username")]
        string userName,
        [Required] [FromBody] [Description("The client data transfer object instance")]
        UserDto userDto)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var rtUser = await _userManager.FindByNameAsync(userName);
        if (rtUser == null)
        {
            return NotFound(new NotFoundErrorDto($"User name '{userName}' not found."));
        }

        // Renaming INTO the reserved shadow namespace is refused; editing an existing shadow user
        // (whose name already carries the prefix) stays possible.
        var previousUserName = rtUser.UserName;
        var previousEmail = rtUser.Email;
        userDto.ApplyTo(rtUser);
        if (CrossTenantShadowUserName.IsShadowUserName(rtUser.UserName) &&
            !string.Equals(rtUser.UserName, previousUserName, StringComparison.OrdinalIgnoreCase))
        {
            return BadRequest(ReservedUserNameMessage);
        }

        // AB#8084: changing the address to one another user already has is refused like a create (AB#8064). Only a change is
        // checked, so users of tenants that already hold duplicates stay editable while they keep their address.
        if (UserEmailUniqueness.ChangesAddress(_userManager, previousEmail, rtUser.Email) &&
            await UserEmailUniqueness.IsTakenByAnotherUserAsync(_userManager, rtUser, rtUser.Email))
        {
            _logger.LogInformation("Update user refused: another user of the tenant has the requested e-mail address");
            return UserCreationProblems.DuplicateEmail();
        }

        try
        {
            var result = await _userManager.UpdateAsync(rtUser);
            if (result.Succeeded)
            {
                return Ok();
            }

            // AB#8083: renaming onto the name of another user (the user validator answers DuplicateUserName) is a conflict.
            if (result.Errors.Any(e => e.Code == nameof(IdentityErrorDescriber.DuplicateUserName)))
            {
                _logger.LogInformation("Update user refused: another user of the tenant has the requested user name");
                return UserCreationProblems.DuplicateUserName();
            }

            return GetBadRequestResultWithErrorDescription("Update of user failed", result.Errors);
        }
        catch (Exception e)
        {
            return StatusCode(StatusCodes.Status500InternalServerError, new InternalServerErrorDto(e.Message));
        }
    }

    // POST: {tenant}/v1/users/ResetPassword
    /// <summary>
    ///     Sets a new password for a user (administrator reset). Facade of the CK method <c>User.ResetPassword-1</c> (AB#8413).
    ///     AB#8008: the user name and the new password travel only in the JSON body; the former query-parameter form
    ///     (<c>?userName=…&amp;password=…</c>) is refused with 400, so a password never lands in a request URL (request logs,
    ///     traces, proxy access logs).
    /// </summary>
    /// <remarks>
    ///     The endpoint resolves the user name and calls <c>User.ResetPassword</c> in-process (never over the broker, also while
    ///     <c>Methods:Identity:EnablePasswordMethods</c> keeps the method off the bus): password policy, the lockout is lifted,
    ///     security stamp rotated, refresh tokens and authorizations revoked, one <c>Identity.Method</c> audit event. After a
    ///     success the endpoint sends the password-reset notification as before - until the method sends it itself (AB#7775,
    ///     then this call goes; a test counts exactly one notification per reset).
    /// </remarks>
    [HttpPost]
    [Route("ResetPassword")]
    [Authorize(IdentityServiceConstants.IdentityUserAdministrationWritePolicy)]
    [RefuseCredentialInQuery("password")]
    [EndpointSummary("Resets the password of an user.")]
    [EndpointDescription("Runs the CK method User.ResetPassword-1: also lifts a lockout of the user and ends the user's " +
                         "sessions (refresh tokens).")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> ResetPassword(
        [Required] [FromBody] [Description("The user name and the new password")]
        ResetUserPasswordRequestDto request)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var userName = request.UserName;
        var user = await _userManager.FindByNameAsync(userName);
        if (user == null)
        {
            return NotFound(new NotFoundErrorDto($"User '{userName}' not found."));
        }

        // AB#5708: shadow users authenticate in their home tenant; a local password would bypass it. Answered before the
        // call, as before; the method refuses it as well (SHADOW_USER_PASSWORD_NOT_ALLOWED, mapped to the same answer).
        if (CrossTenantShadowUserName.IsShadowUserName(user.UserName))
        {
            return BadRequest(ShadowUserPasswordValidator.ErrorMessage);
        }

        const string operation = "Reset of password failed.";
        var response = await _methodFacade.InvokeAsync(IdentityMethodFacade.UserCkTypeId,
            SystemIdentityCkIds.UserResetPasswordMethodId, user.RtId.ToString(),
            new UserResetPasswordParameters { NewPassword = request.Password }, User, HttpContext.RequestAborted);

        if (response.Success)
        {
            // Until AB#7775 the method sends no e-mail; the REST contract keeps exactly one notification per reset.
            await _userEmailInteractionService.SendPasswordResetNotificationAsync(
                _multiTenancyResolverService.GetTenantId(), user);
            return Ok();
        }

        return response.ToActionResult(new CkMethodFacadeOptions()
            .MapError(CkMethodErrorCodes.MethodTargetNotFound,
                _ => NotFound(new NotFoundErrorDto($"User '{userName}' not found.")))
            .MapError(UserResetPasswordHandler.ShadowUserPasswordNotAllowed,
                _ => BadRequest(ShadowUserPasswordValidator.ErrorMessage))
            .MapError(UserResetPasswordHandler.PasswordPolicyViolation,
                error => BadRequest(new OperationFailedErrorDto(operation, DescribeIdentityErrors(error))))
            .MapError(CkMethodErrorCodes.MethodHandlerFailed,
                _ => StatusCode(StatusCodes.Status500InternalServerError, new InternalServerErrorDto(operation))));
    }

    // POST {tenant}/v1/users/{userName}/revokeSessions
    /// <summary>
    ///     AB#7899: ends every session and token of the user in this tenant — rotates the security stamp, revokes all OAuth
    ///     tokens (refresh tokens, codes) and authorizations, removes the server-side browser sessions. Issued JWT access
    ///     tokens stay valid until they expire.
    /// </summary>
    [HttpPost("{userName}/revokeSessions")]
    [Authorize(IdentityServiceConstants.IdentityUserAdministrationWritePolicy)]
    [EndpointSummary("Revokes all sessions and tokens of a user.")]
    [ProducesResponseType<UserSessionRevocationResultDto>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> RevokeSessions([Description("The username")] string userName)
    {
        var user = await _userManager.FindByNameAsync(userName);
        if (user == null)
        {
            return NotFound(new NotFoundErrorDto($"User '{userName}' not found."));
        }

        return Ok(await _userSessionRevocationService.RevokeAsync(user, AuditActor.FromPrincipal(User),
            HttpContext.RequestAborted));
    }

    // POST {tenant}/v1/users/{userName}/disableTwoFactor
    /// <summary>
    ///     AB#7879: a user administrator switches off the second factor of a user (recovery when the authenticator is lost):
    ///     removes the authenticator key and the recovery codes, sets <c>TwoFactorEnabled = false</c>, rotates the security
    ///     stamp and revokes the user's refresh tokens and authorizations in this tenant. The user then signs in with the
    ///     password and can enrol a new authenticator. Same effect as the CK method <c>User.DisableTwoFactor-1</c>; idempotent.
    /// </summary>
    [HttpPost("{userName}/disableTwoFactor")]
    [Authorize(IdentityServiceConstants.IdentityUserAdministrationWritePolicy)]
    [EndpointSummary("Switches off the second factor of a user.")]
    [ProducesResponseType<UserTwoFactorDisableResultDto>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> DisableTwoFactor([Description("The username")] string userName,
        [FromServices] IUserTwoFactorAdministrationService twoFactorAdministration)
    {
        var user = await _userManager.FindByNameAsync(userName);
        if (user == null)
        {
            return NotFound(new NotFoundErrorDto($"User '{userName}' not found."));
        }

        return Ok(await twoFactorAdministration.DisableAsync(user, TwoFactorDisablePath.AdminRest,
            AuditActor.FromPrincipal(User).Actor, HttpContext.RequestAborted));
    }

    // POST {tenant}/v1/users/revokeSessions?scope=shadowUsers&dryRun=true
    /// <summary>
    ///     AB#7899: the same for every cross-tenant shadow user (xt_*) of this tenant. Dry run by default: only the counts
    ///     and the first user names; <c>dryRun=false</c> applies.
    /// </summary>
    [HttpPost("revokeSessions")]
    [Authorize(IdentityServiceConstants.IdentityUserAdministrationWritePolicy)]
    [EndpointSummary("Revokes all sessions and tokens of the cross-tenant shadow users (dry run by default).")]
    [ProducesResponseType<ShadowUserSessionRevocationResultDto>(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> RevokeSessionsInBulk(
        [Required] [Description("Which users: only 'shadowUsers' (xt_*) is supported")] string scope,
        [Description("true (default): count only; false: revoke")] bool dryRun = true)
    {
        if (!string.Equals(scope, "shadowUsers", StringComparison.OrdinalIgnoreCase))
        {
            return BadRequest("Only scope=shadowUsers is supported.");
        }

        return Ok(await _userSessionRevocationService.RevokeShadowUsersAsync(dryRun, AuditActor.FromPrincipal(User),
            HttpContext.RequestAborted));
    }

    // DELETE system/v1/users/5
    [HttpDelete("{userName}")]
    [Authorize(IdentityServiceConstants.IdentityUserAdministrationWritePolicy)]
    [EndpointSummary("Deletes an user.")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> Delete([Required][Description("The username")] string userName)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var applicationUser = await _userManager.FindByNameAsync(userName);
        if (applicationUser == null)
        {
            return NotFound(new NotFoundErrorDto($"User name '{userName}' not found."));
        }

        var refusal = await CheckRoleChangeAsync(applicationUser, null);
        if (refusal != null)
        {
            return refusal;
        }

        try
        {
            var result = await _userManager.DeleteAsync(applicationUser);
            if (result.Succeeded)
            {
                return Ok();
            }

            return GetBadRequestResultWithErrorDescription("Delete of user failed", result.Errors);
        }
        catch (Exception e)
        {
            return StatusCode(StatusCodes.Status500InternalServerError, new InternalServerErrorDto(e.Message));
        }
    }

    // PUT system/v1/users/demo/roles
    /// <summary>
    ///     Replaces the direct roles of a user. Facade of the CK method <c>User.SetRoles-1</c> (AB#8412).
    /// </summary>
    /// <remarks>
    ///     The endpoint resolves the user name and the role ids (an unknown id is <c>404</c> and changes nothing) and calls
    ///     <c>User.SetRoles</c> in-process: role change guard (AB#7914), difference of the direct roles, one
    ///     <c>Identity.Method</c> audit event. Status codes and bodies are unchanged.
    /// </remarks>
    [HttpPut("{userName}/roles")]
    [Authorize(IdentityServiceConstants.IdentityUserAdministrationWritePolicy)]
    [EndpointSummary("Adds roles to an user.")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> UpdateUserRoles([Required][Description("The username")] string userName,
        [Required] [FromBody] [Description("The role ids")]
        IEnumerable<OctoObjectId> roleIds)
    {
        var user = await _userManager.FindByNameAsync(userName);
        if (user == null)
        {
            return NotFound(new NotFoundErrorDto($"User with name '{userName}' not found."));
        }

        // REST names the roles by id, the method by name: resolve every id first, so an unknown id changes nothing.
        var roleIdsByName = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var roleId in roleIds)
        {
            var role = await _roleManager.FindByIdAsync(roleId.ToString());
            if (role == null)
            {
                return NotFound(new NotFoundErrorDto($"Role with id '{roleId}' not found."));
            }

            if (role.NormalizedName != null)
            {
                roleIdsByName[role.Name ?? role.NormalizedName] = roleId.ToString();
            }
        }

        var response = await _methodFacade.InvokeAsync(IdentityMethodFacade.UserCkTypeId,
            SystemIdentityCkIds.UserSetRolesMethodId, user.RtId.ToString(),
            new UserSetRolesParameters { RoleNames = roleIdsByName.Keys.ToList() }, User, HttpContext.RequestAborted);
        return await ToRoleFacadeResultAsync(response, user, new CkMethodFacadeOptions()
            .MapError(UserRoleMethodErrors.RoleNotFound, error =>
                NotFound(new NotFoundErrorDto(
                    $"Role with id '{RoleParameter(error, roleIdsByName)}' not found."))));
    }

    // PUT system/v1/users/demo/roles/users
    /// <summary>
    ///     Adds a direct role to a user. Facade of the CK method <c>User.AddRole-1</c> (AB#8412).
    /// </summary>
    /// <remarks>
    ///     A role the user already holds, also through a group, is <c>400</c> as before; the rest (role change guard, write,
    ///     <c>Identity.Method</c> audit event) is the method.
    /// </remarks>
    [HttpPut("{userName}/roles/{roleName}")]
    [Authorize(IdentityServiceConstants.IdentityUserAdministrationWritePolicy)]
    [EndpointSummary("Adds a role to a user.")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> AddUserToRole([Required][Description("The username")] string userName,
        [Required] [Description("The role name")]
        string roleName)
    {
        var user = await _userManager.FindByNameAsync(userName);
        if (user == null)
        {
            return NotFound(new NotFoundErrorDto($"User with name '{userName}' not found."));
        }

        var role = await _roleManager.FindByNameAsync(roleName);
        if (role == null)
        {
            return NotFound(new NotFoundErrorDto($"Role with name '{roleName}' not found."));
        }

        // REST contract: a role held through a group counts as held (the method looks at the direct roles only).
        var alreadyHeld = new OperationFailedErrorDto($"User '{user.UserName}' already has role '{role.Name}'");
        if (role.NormalizedName != null && await _userManager.IsInRoleAsync(user, role.NormalizedName))
        {
            return BadRequest(alreadyHeld);
        }

        var response = await _methodFacade.InvokeAsync(IdentityMethodFacade.UserCkTypeId,
            SystemIdentityCkIds.UserAddRoleMethodId, user.RtId.ToString(),
            new UserAddRoleParameters { RoleName = role.Name ?? roleName }, User, HttpContext.RequestAborted);
        return await ToRoleFacadeResultAsync(response, user, new CkMethodFacadeOptions()
            .MapError(UserRoleMethodErrors.RoleNotFound,
                _ => NotFound(new NotFoundErrorDto($"Role with name '{roleName}' not found.")))
            .MapError(UserRoleMethodErrors.RoleAlreadyAssigned, _ => BadRequest(alreadyHeld)));
    }

    // POST system/v1/users/{userName}/merge
    /// <summary>
    ///     Merges external logins from a source user into the target user, then deletes the source user.
    ///     This is useful for consolidating duplicate accounts created by external identity providers.
    /// </summary>
    /// <remarks>
    ///     Facade of the CK method <c>User.Merge-1</c> (AB#8412): role change guard on the deletion of the source user,
    ///     write permission on the source user, logins moved, sessions and refresh tokens of the source user revoked,
    ///     source user deleted, one <c>Identity.Method</c> audit event. Roles, groups and claims of the source user are not
    ///     transferred.
    /// </remarks>
    [HttpPost("{userName}/merge")]
    [Authorize(IdentityServiceConstants.IdentityUserAdministrationWritePolicy)]
    [EndpointSummary("Merges external logins from source user into target user and deletes source user.")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<IActionResult> MergeUsers(
        [Required] [Description("The target username (this user will be kept)")]
        string userName,
        [Required] [FromBody] [Description("The merge request containing the source username")]
        MergeUsersRequestDto mergeRequest)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var targetUser = await _userManager.FindByNameAsync(userName);
        if (targetUser == null)
        {
            return NotFound(new NotFoundErrorDto($"Target user '{userName}' not found."));
        }

        var response = await _methodFacade.InvokeAsync(IdentityMethodFacade.UserCkTypeId,
            SystemIdentityCkIds.UserMergeMethodId, targetUser.RtId.ToString(),
            new UserMergeParameters { SourceUserName = mergeRequest.SourceUserName }, User, HttpContext.RequestAborted);

        // AB#7914: the source user is deleted at the end; that must not remove the last user administrator.
        if (RoleChangeRefusal(response) is { } decision)
        {
            var sourceUser = await _userManager.FindByNameAsync(mergeRequest.SourceUserName.Trim());
            if (sourceUser != null)
            {
                return await RefuseRoleChangeAsync(sourceUser, RoleChangeCaller.FromPrincipal(User), decision);
            }

            return RoleChangeProblems.ToResult(decision);
        }

        return response.ToActionResult(new CkMethodFacadeOptions()
            .MapSuccess(_ => Ok())
            .MapError(CkMethodErrorCodes.MethodTargetNotFound,
                _ => NotFound(new NotFoundErrorDto($"Target user '{userName}' not found.")))
            .MapError(UserMergeHandler.SourceUserNotFound,
                _ => NotFound(new NotFoundErrorDto($"Source user '{mergeRequest.SourceUserName}' not found.")))
            .MapError(UserMergeHandler.CannotMergeIntoItself,
                _ => BadRequest(new OperationFailedErrorDto("Cannot merge a user into itself.")))
            .MapError(UserMergeHandler.MergeFailed, MergeFailedResult)
            .MapError(CkMethodErrorCodes.MethodHandlerFailed,
                _ => StatusCode(StatusCodes.Status500InternalServerError,
                    new InternalServerErrorDto("Merging the users failed."))));
    }

    // DELETE system/v1/users/demo/roles/Users
    /// <summary>
    ///     Removes a direct role from a user. Facade of the CK method <c>User.RemoveRole-1</c> (AB#8412).
    /// </summary>
    /// <remarks>
    ///     A role the user does not hold at all is <c>400</c> as before; a role held only through a group is <c>200</c> and
    ///     changes nothing, as before. The rest (role change guard, write, <c>Identity.Method</c> audit event) is the method.
    /// </remarks>
    [HttpDelete("{userName}/roles/{roleName}")]
    [Authorize(IdentityServiceConstants.IdentityUserAdministrationWritePolicy)]
    [EndpointSummary("Removes a role from a user.")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> RemoveRoleFromUser([Required][Description("The username")] string userName,
        [Required] [Description("The role name")]
        string roleName)
    {
        var user = await _userManager.FindByNameAsync(userName);
        if (user == null)
        {
            return NotFound(new NotFoundErrorDto($"User with name '{userName}' not found."));
        }

        var role = await _roleManager.FindByNameAsync(roleName);
        if (role == null)
        {
            return NotFound(new NotFoundErrorDto($"Role with name '{roleName}' not found."));
        }

        // REST contract: a role held through a group counts as held (the method looks at the direct roles only).
        if (role.NormalizedName != null && !await _userManager.IsInRoleAsync(user, role.NormalizedName))
        {
            return BadRequest(new OperationFailedErrorDto($"User '{user.UserName}' doesn't have role '{role.Name}'"));
        }

        var response = await _methodFacade.InvokeAsync(IdentityMethodFacade.UserCkTypeId,
            SystemIdentityCkIds.UserRemoveRoleMethodId, user.RtId.ToString(),
            new UserRemoveRoleParameters { RoleName = role.Name ?? roleName }, User, HttpContext.RequestAborted);
        return await ToRoleFacadeResultAsync(response, user, new CkMethodFacadeOptions()
            .MapError(UserRoleMethodErrors.RoleNotFound,
                _ => NotFound(new NotFoundErrorDto($"Role with name '{roleName}' not found.")))
            // held only through a group: REST has always answered 200 without a change
            .MapError(UserRoleMethodErrors.RoleNotAssigned, _ => Ok()));
    }

    /// <summary>
    ///     The REST answer of a role method (AB#8412): <c>200</c> on success, the problem answer of the role change guard
    ///     (403 / 409, with the WARN log and the <c>Identity.RoleChangeRefused</c> audit record of AB#7914), a missing user
    ///     as <c>404</c>, the endpoint's own mappings, else the facade defaults.
    /// </summary>
    private async Task<IActionResult> ToRoleFacadeResultAsync(CkMethodResponse response, RtUser user,
        CkMethodFacadeOptions options)
    {
        if (RoleChangeRefusal(response) is { } decision)
        {
            return await RefuseRoleChangeAsync(user, RoleChangeCaller.FromPrincipal(User), decision);
        }

        return response.ToActionResult(options
            .MapSuccess(_ => Ok())
            .MapError(CkMethodErrorCodes.MethodTargetNotFound,
                _ => NotFound(new NotFoundErrorDto($"User with name '{user.UserName}' not found."))));
    }

    /// <summary>
    ///     The decision of the role change guard when the method refused the call because of it (<c>METHOD_FORBIDDEN</c>
    ///     with a guard <c>reason</c>), else <c>null</c>. Other refusals (<c>role-required</c>, <c>data-permission</c>) are
    ///     not guard decisions.
    /// </summary>
    private static RoleChangeDecision? RoleChangeRefusal(CkMethodResponse response)
    {
        if (response.Success || response.Error is not { Code: CkMethodErrorCodes.MethodForbidden } error ||
            !error.Parameters.TryGetValue("reason", out var reason) ||
            reason is not (RoleChangeReasons.SelfGrant or RoleChangeReasons.RoleNotHeld or
                RoleChangeReasons.LastAdministrator))
        {
            return null;
        }

        var roleNames = error.Parameters.TryGetValue("roleNames", out var names)
            ? names.Split(',', StringSplitOptions.RemoveEmptyEntries)
            : [];
        return new RoleChangeDecision(reason, roleNames);
    }

    /// <summary>The role id of a <c>ROLE_NOT_FOUND</c> answer of <c>User.SetRoles</c> (the method names the role).</summary>
    private static string RoleParameter(CkMethodError error, IReadOnlyDictionary<string, string> roleIdsByName) =>
        error.Parameters.TryGetValue(UserRoleMethodErrors.RoleNameParameter, out var name) &&
        roleIdsByName.TryGetValue(name, out var id)
            ? id
            : name ?? string.Empty;

    /// <summary>The <c>400</c> answer of a failed merge step, with the error codes of the user manager.</summary>
    private BadRequestObjectResult MergeFailedResult(CkMethodError error)
    {
        error.Parameters.TryGetValue("loginProvider", out var loginProvider);
        var message = error.Parameters.GetValueOrDefault("step") switch
        {
            "removeLogin" => $"Failed to remove login '{loginProvider}' from source user",
            "addLogin" => $"Failed to transfer login '{loginProvider}' to target user",
            _ => "Failed to delete source user after merge"
        };
        return BadRequest(new OperationFailedErrorDto(message,
            (error.Details ?? []).Select(d => new FailedDetailsDto { Code = d.Code })));
    }

    /// <summary>
    ///     Runs <see cref="IRoleChangeGuard" /> for a change of the direct roles of <paramref name="user" /> (or its
    ///     deletion when <paramref name="rolesAfter" /> is <c>null</c>). Returns the problem answer (403 / 409) and audits
    ///     the refusal, or <c>null</c> when the change is allowed (AB#7914).
    /// </summary>
    private async Task<IActionResult?> CheckRoleChangeAsync(RtUser user, IEnumerable<string>? rolesAfter,
        IEnumerable<string>? rolesBefore = null)
    {
        rolesBefore ??= await _octoUserStore.GetDirectRolesAsync(user);
        var caller = RoleChangeCaller.FromPrincipal(User);
        var decision = await _roleChangeGuard.EvaluateAsync(
            new RoleChangeRequest(caller, user, rolesBefore.ToList(), rolesAfter?.ToList()), HttpContext.RequestAborted);
        if (decision.IsAllowed)
        {
            return null;
        }

        return await RefuseRoleChangeAsync(user, caller, decision);
    }

    /// <summary>Writes the WARN log and the audit event of a refused role change and returns the problem answer (AB#7914).</summary>
    private async Task<IActionResult> RefuseRoleChangeAsync(RtUser user, RoleChangeCaller caller,
        RoleChangeDecision decision)
    {
        var callerText = caller.Subject != null ? $"subject {caller.Subject}" : $"client {caller.ClientId}";
        var message =
            $"Role change refused ({decision.Reason}): caller {callerText}, target user {user.RtId}, roles [{string.Join(",", decision.RoleNames)}], {Request.Method} {Request.Path.Value}";
        _logger.LogWarning("{Message}", message);
        await _identityAuditService.StoreFailureAsync(RoleChangeProblems.AuditEventName, message);
        return RoleChangeProblems.ToResult(decision);
    }

    /// <summary>
    ///     The REST <c>failedDetails</c> of a password policy refusal (AB#8413): the envelope carries only the codes of the failed
    ///     rules (never a value), the description is rebuilt from the error describer and the password options of this
    ///     service, so the body keeps code and description as before.
    /// </summary>
    private IEnumerable<FailedDetailsDto> DescribeIdentityErrors(CkMethodError error)
    {
        var describer = _userManager.ErrorDescriber;
        var password = _userManager.Options.Password;
        return (error.Details ?? []).Select(d => d.Code).Where(c => !string.IsNullOrWhiteSpace(c)).Select(code =>
            new FailedDetailsDto
            {
                Code = code,
                Description = code switch
                {
                    nameof(IdentityErrorDescriber.PasswordTooShort) => describer.PasswordTooShort(password.RequiredLength)
                        .Description,
                    nameof(IdentityErrorDescriber.PasswordRequiresUniqueChars) => describer
                        .PasswordRequiresUniqueChars(password.RequiredUniqueChars).Description,
                    nameof(IdentityErrorDescriber.PasswordRequiresNonAlphanumeric) => describer
                        .PasswordRequiresNonAlphanumeric().Description,
                    nameof(IdentityErrorDescriber.PasswordRequiresDigit) => describer.PasswordRequiresDigit().Description,
                    nameof(IdentityErrorDescriber.PasswordRequiresLower) => describer.PasswordRequiresLower().Description,
                    nameof(IdentityErrorDescriber.PasswordRequiresUpper) => describer.PasswordRequiresUpper().Description,
                    _ => code
                }
            }).ToList();
    }

    /// <summary>The REST <c>failedDetails</c> entry of a <c>METHOD_VALIDATION_FAILED</c> answer of <c>User.CreateUser</c>.</summary>
    private FailedDetailsDto DescribeValidationFailure(CkMethodError error, UserDto userDto)
    {
        var describer = _userManager.ErrorDescriber;
        var identityError = error.Parameters.GetValueOrDefault(CkMethodErrorParameters.Field) switch
        {
            "email" => describer.InvalidEmail(userDto.Email),
            _ => describer.InvalidUserName(userDto.Name)
        };
        return new FailedDetailsDto { Code = identityError.Code, Description = identityError.Description };
    }

    private void LogIdentityError(string operation, IEnumerable<IdentityError> errors)
    {
        var identityErrors = errors as IdentityError[] ?? errors.ToArray();
        _logger.LogError("{Operation} failed with errors: '{Errors}' and codes '{Codes}'",
            operation,
            string.Join(", ", identityErrors.Select(x => x.Description)),
            string.Join(", ", identityErrors.Select(x => x.Code)));
    }

    private IActionResult GetBadRequestResultWithErrorDescription(string operation, IEnumerable<IdentityError> errors)
    {
        return BadRequest(new OperationFailedErrorDto(operation,
            errors.Select(x => new FailedDetailsDto { Code = x.Code, Description = x.Description })));
    }
}