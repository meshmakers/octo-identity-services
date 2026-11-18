using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using Asp.Versioning;
using IdentityServerPersistence;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Common.DistributionEventHub.Services;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.Secrets;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Messages;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Meshmakers.Octo.Backend.Authentication;
using Meshmakers.Octo.Backend.IdentityServices.Mapping;
using System.Text.Json;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Methods;
using Meshmakers.Octo.Services.Methods;
using Meshmakers.Octo.Services.Methods.Facades;
using Meshmakers.Octo.Backend.IdentityServices.Methods;

namespace Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;

/// <summary>
///     REST Controller for identity provider management
/// </summary>
[Authorize(AuthenticationSchemes = AuthenticationConstants.BearerAuthenticationScheme)]
[Route(IdentityServiceConstants.ApiPathPrefix + "/[controller]")]
[ApiController]
[ApiVersion(IdentityServiceConstants.ApiVersion1)]
public class IdentityProvidersController : ControllerBase
{
    private readonly IOctoIdentityProviderStore _identityProviderStore;
    private readonly IdentityProviderDtoMapper _identityProviderDtoMapper;
    private readonly IIdentityMethodFacade _methodFacade;

    /// <summary>
    ///     Constructor
    /// </summary>
    /// <param name="identityProviderStore">Reads the providers (GET) and the stored provider after a write.</param>
    /// <param name="identityProviderDtoMapper">Maps a stored provider to its DTO (the secret only as "is set").</param>
    /// <param name="methodFacade">
    ///     Runs the System.Identity 3.8.0 provider methods in-process: create, replace and delete are their facades.
    /// </param>
    public IdentityProvidersController(IOctoIdentityProviderStore identityProviderStore,
        IdentityProviderDtoMapper identityProviderDtoMapper, IIdentityMethodFacade methodFacade)
    {
        _identityProviderStore = identityProviderStore;
        _identityProviderDtoMapper = identityProviderDtoMapper;
        _methodFacade = methodFacade;
    }

    [HttpGet]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationReadPolicy)]
    [EndpointSummary("Returns all available identity providers.")]
    [ProducesResponseType(typeof(IdentityProvidersResult), StatusCodes.Status200OK)]
    public async Task<ActionResult<IdentityProvidersResult>> GetIdentityProvidersAsync()
    {
        var identityProviders = await _identityProviderStore.GetAllAsync();
        return new IdentityProvidersResult
        {
            IdentityProviders = identityProviders.Select(_identityProviderDtoMapper.ToDto)
        };
    }

    [HttpGet("{rtId}")]
    [ProducesResponseType(typeof(IdentityProvidersResult), StatusCodes.Status200OK)]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationReadPolicy)]
    [EndpointSummary("Returns an identity provider by its ID.")]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult<IdentityProvidersResult>> Get([Required] OctoObjectId rtId)
    {
        var identityProvider = await _identityProviderStore.GetByIdAsync(rtId);
        if (identityProvider == null)
        {
            return NotFound();
        }

        return new IdentityProvidersResult
        {
            IdentityProviders = [_identityProviderDtoMapper.ToDto(identityProvider)]
        };
    }

    [HttpPost]
    [ProducesResponseType(typeof(IdentityProviderDto), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(UniquenessViolationErrorResponse), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status503ServiceUnavailable)]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationWritePolicy)]
    [EndpointSummary("Add a new identity provider.")]
    public async Task<ActionResult<IdentityProviderDto>> AddNewIdentityProviderAsync(
        [FromBody][Description("The configuration for the new identity provider.")] IdentityProviderDto identityProviderDto)
    {
        // ClientSecret is no longer [Required] on the DTO because PUT must accept it being omitted
        // (the existing secret is preserved). Creation still needs a secret, so enforce it here.
        // AB#5540: ClientSecret is write-only (Secret value type) — create/replace accept it as a
        // string (null or "" on replace = keep the stored secret); no response ever contains it.
        // There is no "clear" operation: the secret is required on the provider types.
        if (RequiresClientSecretOnCreate(identityProviderDto, out var missingFieldName))
        {
            ModelState.AddModelError(missingFieldName, $"The {missingFieldName} field is required.");
            return ValidationProblem(ModelState);
        }

        if (!IsProviderNameValid(identityProviderDto.Name))
        {
            ModelState.AddModelError(nameof(IdentityProviderDto.Name), ProviderNameValidationMessage);
            return ValidationProblem(ModelState);
        }

        // The facade of IdentityProvider.CreateIdentityProvider-1 (System.Identity 3.8.0), called on the concrete
        // provider type of the DTO. The method stores the provider, checks the OctoTenant parent and announces the
        // change; the response is mapped from the stored entity, never from the request.
        if (ProviderCkTypeIdOf(identityProviderDto) is not { } ckTypeId)
        {
            ModelState.AddModelError(nameof(IdentityProviderDto), "Unknown identity provider type.");
            return ValidationProblem(ModelState);
        }

        var p = MethodParametersOf(identityProviderDto);
        var response = await _methodFacade.InvokeAsync(ckTypeId,
            SystemIdentityCkIds.IdentityProviderCreateIdentityProviderMethodId, null,
            new IdentityProviderCreateIdentityProviderParameters
            {
                Name = p.Name ?? string.Empty, Enabled = p.Enabled, Description = p.Description,
                AllowSelfRegistration = p.AllowSelfRegistration, DefaultGroupRtId = p.DefaultGroupRtId,
                ClientId = p.ClientId, ClientSecret = p.ClientSecret, TenantId = p.TenantId, Authority = p.Authority,
                Host = p.Host, Port = p.Port, UseTls = p.UseTls, UserBaseDn = p.UserBaseDn,
                UserNameAttribute = p.UserNameAttribute, ParentTenantId = p.ParentTenantId
            }, User, HttpContext.RequestAborted);
        if (!response.Success)
        {
            return ToFailure(response, identityProviderDto);
        }

        var rtId = OctoObjectId.Parse(JsonSerializer.Deserialize<string>(response.ResultJson!, CkMethodJson.Options)!);
        var created = await _identityProviderStore.GetByIdAsync(rtId);
        return created == null ? NotFound() : _identityProviderDtoMapper.ToDto(created);
    }

    // The provider Name is embedded verbatim into the just-in-time provisioned external
    // user name ("{providerName}_{email}"). ASP.NET Identity's UserValidator only accepts a
    // limited character set, so a name with spaces/parentheses/non-ASCII letters (e.g.
    // "Microsoft Entra ID") makes UserManager.CreateAsync fail with InvalidUserName, which the
    // user only sees as "Failed to create user account" AFTER a successful external login.
    // Reject such names here — the single write path shared by the Studio UI, octo-cli and the
    // MCP server — so the problem surfaces at configuration time instead of at login time.
    internal const string ProviderNameValidationMessage =
        "The Name may only contain ASCII letters, digits and the separators '.', '_' and '-' (no spaces or other special characters), and must not be 'xt' or start with 'xt_' (reserved for cross-tenant users), because it is used to build user names for externally provisioned accounts.";

    private static readonly System.Text.RegularExpressions.Regex ProviderNameRegex =
        new("^[A-Za-z0-9._-]+$", System.Text.RegularExpressions.RegexOptions.Compiled);

    internal static bool IsProviderNameValid(string? name)
        => !string.IsNullOrWhiteSpace(name) && ProviderNameRegex.IsMatch(name)
           && !IsProviderNameReserved(name);

    // "{providerName}_{email}" must not start with the xt_ prefix reserved for cross-tenant shadow
    // users (AB#5708): such a name would unwind to another tenant's identity.
    internal static bool IsProviderNameReserved(string name)
        => IdentityServerPersistence.Services.CrossTenantShadowUserName.IsShadowUserName($"{name}_");

    private static bool RequiresClientSecretOnCreate(IdentityProviderDto dto, out string missingFieldName)
    {
        missingFieldName = nameof(GoogleIdentityProviderDto.ClientSecret);
        return dto switch
        {
            GoogleIdentityProviderDto g => string.IsNullOrEmpty(g.ClientSecret),
            MicrosoftIdentityProviderDto m => string.IsNullOrEmpty(m.ClientSecret),
            FacebookIdentityProviderDto f => string.IsNullOrEmpty(f.ClientSecret),
            AzureEntraIdProviderDto a => string.IsNullOrEmpty(a.ClientSecret),
            _ => false
        };
    }

    [HttpDelete("{rtId}")]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationWritePolicy)]
    [EndpointSummary("Delete an existing identity provider.")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> DeleteIdentityProviderAsync([Required][Description("The ID of the identity provider to be deleted")] OctoObjectId rtId)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        // The facade of IdentityProvider.DeleteIdentityProvider-1, called on the provider's own concrete type.
        // An unknown id is 404 (was 200 before the facade, nothing was deleted then either).
        var stored = await _identityProviderStore.GetByIdAsync(rtId);
        if (stored == null || ProviderCkTypeIdOf(stored) is not { } ckTypeId)
        {
            return NotFound();
        }

        var response = await _methodFacade.InvokeAsync(ckTypeId,
            SystemIdentityCkIds.IdentityProviderDeleteIdentityProviderMethodId, rtId.ToString(),
            new IdentityProviderDeleteIdentityProviderParameters(), User, HttpContext.RequestAborted);
        return response.ToActionResult(new CkMethodFacadeOptions().MapSuccess(_ => new OkResult()));
    }

    [HttpPut("{rtId}")]
    [ProducesResponseType(typeof(IdentityProviderDto), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(UniquenessViolationErrorResponse), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status503ServiceUnavailable)]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationWritePolicy)]
    [EndpointSummary("Replace an existing identity provider.")]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public async Task<ActionResult<IdentityProviderDto>> ReplaceProviderAsync(
        [FromRoute][Required][Description("ID of an existing provider")] OctoObjectId rtId,
        [FromBody][Required][Description("The configuration for the new identity provider.")] IdentityProviderDto identityProviderDto)
    {
        if (identityProviderDto == null)
        {
            throw new ArgumentNullException(nameof(identityProviderDto));
        }

        if (!IsProviderNameValid(identityProviderDto.Name))
        {
            ModelState.AddModelError(nameof(IdentityProviderDto.Name), ProviderNameValidationMessage);
            return ValidationProblem(ModelState);
        }

        // The facade of IdentityProvider.UpdateIdentityProvider-1, called on the concrete type of the DTO. A
        // provider of another type, or an unknown id, is 404 (the type of a provider never changes; an unknown id was
        // inserted before the facade).
        if (ProviderCkTypeIdOf(identityProviderDto) is not { } ckTypeId)
        {
            ModelState.AddModelError(nameof(IdentityProviderDto), "Unknown identity provider type.");
            return ValidationProblem(ModelState);
        }

        var p = MethodParametersOf(identityProviderDto);
        var response = await _methodFacade.InvokeAsync(ckTypeId,
            SystemIdentityCkIds.IdentityProviderUpdateIdentityProviderMethodId, rtId.ToString(),
            new IdentityProviderUpdateIdentityProviderParameters
            {
                Name = p.Name ?? string.Empty, Enabled = p.Enabled, Description = p.Description,
                AllowSelfRegistration = p.AllowSelfRegistration, DefaultGroupRtId = p.DefaultGroupRtId,
                ClientId = p.ClientId, ClientSecret = p.ClientSecret, TenantId = p.TenantId, Authority = p.Authority,
                Host = p.Host, Port = p.Port, UseTls = p.UseTls, UserBaseDn = p.UserBaseDn,
                UserNameAttribute = p.UserNameAttribute, ParentTenantId = p.ParentTenantId
            }, User, HttpContext.RequestAborted);
        if (!response.Success)
        {
            return ToFailure(response, identityProviderDto);
        }

        // never echo the request - it carries the write-only ClientSecret in clear text. The response is mapped
        // from the stored entity, whose Secret attribute is never projected.
        return await StoredDtoAsync(rtId);
    }

    /// <summary>Problem-detail code when a client secret is saved on a host without key ring (AB#5540).</summary>
    internal const string SecretEncryptionNotConfiguredCode = "SecretEncryptionNotConfigured";

    internal const string SecretEncryptionNotConfiguredTitle = "Secret encryption is not configured on this server";

    private static ObjectResult SecretEncryptionNotConfiguredProblem()
    {
        var problem = new ProblemDetails
        {
            Status = StatusCodes.Status503ServiceUnavailable,
            Title = SecretEncryptionNotConfiguredTitle,
            Detail = "The client secret cannot be saved because no secret encryption key ring is configured " +
                     "(configuration section SecretEncryption). Configure the key ring and retry.",
            Extensions = { ["code"] = SecretEncryptionNotConfiguredCode }
        };
        return new ObjectResult(problem)
        {
            StatusCode = StatusCodes.Status503ServiceUnavailable,
            ContentTypes = { "application/problem+json" }
        };
    }

    /// <summary>The concrete CK type of the provider a DTO describes, or <c>null</c> for the abstract base.</summary>
    private static string? ProviderCkTypeIdOf(IdentityProviderDto dto) => dto switch
    {
        GoogleIdentityProviderDto => CkTypeIdOf<RtGoogleIdentityProvider>(),
        MicrosoftIdentityProviderDto => CkTypeIdOf<RtMicrosoftIdentityProvider>(),
        FacebookIdentityProviderDto => CkTypeIdOf<RtFacebookIdentityProvider>(),
        AzureEntraIdProviderDto => CkTypeIdOf<RtAzureEntraIdIdentityProvider>(),
        MicrosoftAdProviderDto => CkTypeIdOf<RtMicrosoftAdIdentityProvider>(),
        OpenLdapProviderDto => CkTypeIdOf<RtOpenLdapIdentityProvider>(),
        OctoTenantIdentityProviderDto => CkTypeIdOf<RtOctoTenantIdentityProvider>(),
        _ => null
    };

    /// <summary>The concrete CK type of a stored provider.</summary>
    private static string? ProviderCkTypeIdOf(RtIdentityProvider stored) => stored switch
    {
        RtGoogleIdentityProvider => CkTypeIdOf<RtGoogleIdentityProvider>(),
        RtMicrosoftIdentityProvider => CkTypeIdOf<RtMicrosoftIdentityProvider>(),
        RtFacebookIdentityProvider => CkTypeIdOf<RtFacebookIdentityProvider>(),
        RtAzureEntraIdIdentityProvider => CkTypeIdOf<RtAzureEntraIdIdentityProvider>(),
        RtMicrosoftAdIdentityProvider => CkTypeIdOf<RtMicrosoftAdIdentityProvider>(),
        RtOpenLdapIdentityProvider => CkTypeIdOf<RtOpenLdapIdentityProvider>(),
        RtOctoTenantIdentityProvider => CkTypeIdOf<RtOctoTenantIdentityProvider>(),
        _ => null
    };

    private static string CkTypeIdOf<T>() where T : RtIdentityProvider =>
        IdentityProviderMethodSupport.CkTypeIdOf<T>();

    /// <summary>The method parameters of a REST DTO (the defaults of the DTO classes travel with it).</summary>
    internal static IdentityProviderConfiguration MethodParametersOf(IdentityProviderDto dto) => dto switch
    {
        GoogleIdentityProviderDto g => Common(dto) with { ClientId = g.ClientId, ClientSecret = g.ClientSecret },
        MicrosoftIdentityProviderDto m => Common(dto) with { ClientId = m.ClientId, ClientSecret = m.ClientSecret },
        FacebookIdentityProviderDto f => Common(dto) with { ClientId = f.ClientId, ClientSecret = f.ClientSecret },
        AzureEntraIdProviderDto a => Common(dto) with
        {
            ClientId = a.ClientId, ClientSecret = a.ClientSecret, TenantId = a.TenantId, Authority = a.Authority
        },
        MicrosoftAdProviderDto ad => Common(dto) with { Host = ad.Host, Port = ad.Port, UseTls = ad.UseTls },
        OpenLdapProviderDto ldap => Common(dto) with
        {
            Host = ldap.Host, Port = ldap.Port, UseTls = ldap.UseTls, UserBaseDn = ldap.UserBaseDn,
            UserNameAttribute = ldap.UserNameAttribute
        },
        OctoTenantIdentityProviderDto octo => Common(dto) with { ParentTenantId = octo.ParentTenantId },
        _ => Common(dto)
    };

    private static IdentityProviderConfiguration Common(IdentityProviderDto dto) => new(dto.Name, dto.IsEnabled,
        dto.Description, dto.AllowSelfRegistration, dto.DefaultGroupRtId, null, null, null, null, null, null, null, null,
        null, null);

    /// <summary>The stored provider as the response (the secret only as "is set").</summary>
    private async Task<ActionResult<IdentityProviderDto>> StoredDtoAsync(OctoObjectId rtId)
    {
        var stored = await _identityProviderStore.GetByIdAsync(rtId);
        return stored == null ? NotFound() : Ok(_identityProviderDtoMapper.ToDto(stored));
    }

    /// <summary>The REST answer of a refused create or replace, in the shapes the endpoints answered before the facade.</summary>
    private ActionResult ToFailure(CkMethodResponse response, IdentityProviderDto dto)
    {
        var result = response.ToActionResult(new CkMethodFacadeOptions()
            .MapError(IdentityProviderMethodErrors.ParentTenantNotAncestor,
                _ => CrossTenantAncestryProblems.ParentTenantNotAncestor(_identityProviderStore.TenantId,
                    (dto as OctoTenantIdentityProviderDto)?.ParentTenantId ?? string.Empty))
            .MapError(IdentityProviderMethodErrors.SecretEncryptionNotConfigured,
                _ => SecretEncryptionNotConfiguredProblem())
            .MapError(IdentityProviderMethodErrors.IdentityProviderAlreadyExists,
                _ => Problem(detail: "Name must be unique", statusCode: StatusCodes.Status409Conflict))
            .MapError(CkMethodErrorCodes.MethodValidationFailed, error =>
            {
                ModelState.AddModelError(error.Parameters.GetValueOrDefault(CkMethodErrorParameters.Field) ?? nameof(IdentityProviderDto),
                    "The value is missing or invalid.");
                return ValidationProblem(ModelState);
            }));
        return (ActionResult)result;
    }
}
