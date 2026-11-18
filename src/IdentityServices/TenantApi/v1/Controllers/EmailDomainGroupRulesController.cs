using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Text.Json;
using Asp.Versioning;
using IdentityServerPersistence;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Methods;
using Meshmakers.Octo.Services.Methods;
using Meshmakers.Octo.Services.Methods.Facades;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Meshmakers.Octo.Backend.Authentication;
using Meshmakers.Octo.Backend.IdentityServices.Mapping;
using Meshmakers.Octo.Backend.IdentityServices.Methods;

namespace Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;

/// <summary>
///     REST Controller for email domain group rule management
/// </summary>
[Authorize(AuthenticationSchemes = AuthenticationConstants.BearerAuthenticationScheme)]
[Route(IdentityServiceConstants.ApiPathPrefix + "/[controller]")]
[ApiController]
[ApiVersion(IdentityServiceConstants.ApiVersion1)]
public class EmailDomainGroupRulesController(
    IEmailDomainGroupRuleStore emailDomainGroupRuleStore,
    IIdentityMethodFacade methodFacade) : ControllerBase
{
    private const string GetEmailDomainGroupRuleRouteName = "GetEmailDomainGroupRule";

    [HttpGet]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationReadPolicy)]
    [EndpointSummary("Returns all email domain group rules.")]
    [ProducesResponseType(typeof(EmailDomainGroupRulesResult), StatusCodes.Status200OK)]
    public async Task<ActionResult<EmailDomainGroupRulesResult>> GetAllAsync()
    {
        var rules = await emailDomainGroupRuleStore.GetAllAsync();
        return new EmailDomainGroupRulesResult
        {
            EmailDomainGroupRules = rules.Select(rule => rule.ToDto())
        };
    }

    [HttpGet("{rtId}", Name = GetEmailDomainGroupRuleRouteName)]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationReadPolicy)]
    [EndpointSummary("Returns an email domain group rule by its ID.")]
    [ProducesResponseType(typeof(EmailDomainGroupRuleDto), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult<EmailDomainGroupRuleDto>> GetByIdAsync([Required] OctoObjectId rtId)
    {
        var rule = await emailDomainGroupRuleStore.GetByIdAsync(rtId);
        if (rule == null)
        {
            return NotFound();
        }

        return rule.ToDto();
    }

    /// <summary>
    ///     Facade of the static <c>EmailDomainGroupRule.CreateEmailDomainGroupRule-1</c> (System.Identity 3.8.0, AB#9042).
    /// </summary>
    [HttpPost]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationWritePolicy)]
    [EndpointSummary("Create a new email domain group rule.")]
    [ProducesResponseType(typeof(EmailDomainGroupRuleDto), StatusCodes.Status201Created)]
    [ProducesResponseType(typeof(ValidationProblemDetails), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status409Conflict)]
    public async Task<ActionResult<EmailDomainGroupRuleDto>> CreateAsync(
        [FromBody][Description("The email domain group rule to create.")] EmailDomainGroupRuleDto dto)
    {
        var response = await methodFacade.InvokeAsync(IdentityMethodFacade.EmailDomainGroupRuleCkTypeId,
            SystemIdentityCkIds.EmailDomainGroupRuleCreateEmailDomainGroupRuleMethodId, null,
            new EmailDomainGroupRuleCreateEmailDomainGroupRuleParameters
            {
                EmailDomainPattern = dto.EmailDomainPattern ?? string.Empty,
                TargetGroupRtId = dto.TargetGroupRtId ?? string.Empty, Description = dto.Description
            }, User, HttpContext.RequestAborted);
        if (!response.Success)
        {
            return (ActionResult)response.ToActionResult(RuleFailures());
        }

        var rtId = OctoObjectId.Parse(JsonSerializer.Deserialize<string>(response.ResultJson!, CkMethodJson.Options)!);
        var rule = await emailDomainGroupRuleStore.GetByIdAsync(rtId);
        if (rule == null)
        {
            return NotFound();
        }

        var routeValuesOfCreatedRule = new
        {
            tenantId = RouteData.Values["tenantId"],
            version = RouteData.Values["version"],
            rtId = rule.RtId
        };
        return CreatedAtRoute(GetEmailDomainGroupRuleRouteName, routeValuesOfCreatedRule, rule.ToDto());
    }

    /// <summary>
    ///     Facade of <c>EmailDomainGroupRule.UpdateEmailDomainGroupRule-1</c> (System.Identity 3.8.0, AB#9042). An unknown id
    ///     is 404 (it was inserted before the facade).
    /// </summary>
    [HttpPut("{rtId}")]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationWritePolicy)]
    [EndpointSummary("Replace an existing email domain group rule.")]
    [ProducesResponseType(typeof(EmailDomainGroupRuleDto), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ValidationProblemDetails), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(typeof(ProblemDetails), StatusCodes.Status409Conflict)]
    public async Task<ActionResult<EmailDomainGroupRuleDto>> UpdateAsync(
        [FromRoute][Required] OctoObjectId rtId,
        [FromBody][Required][Description("The updated email domain group rule.")] EmailDomainGroupRuleDto dto)
    {
        var response = await methodFacade.InvokeAsync(IdentityMethodFacade.EmailDomainGroupRuleCkTypeId,
            SystemIdentityCkIds.EmailDomainGroupRuleUpdateEmailDomainGroupRuleMethodId, rtId.ToString(),
            new EmailDomainGroupRuleUpdateEmailDomainGroupRuleParameters
            {
                EmailDomainPattern = dto.EmailDomainPattern ?? string.Empty,
                TargetGroupRtId = dto.TargetGroupRtId ?? string.Empty, Description = dto.Description
            }, User, HttpContext.RequestAborted);
        if (!response.Success)
        {
            return (ActionResult)response.ToActionResult(RuleFailures());
        }

        var rule = await emailDomainGroupRuleStore.GetByIdAsync(rtId);
        return rule == null ? NotFound() : Ok(rule.ToDto());
    }

    /// <summary>
    ///     Facade of <c>EmailDomainGroupRule.DeleteEmailDomainGroupRule-1</c> (System.Identity 3.8.0, AB#9042). An unknown id
    ///     is 404 (it was 200 before the facade; nothing was deleted then either).
    /// </summary>
    [HttpDelete("{rtId}")]
    [Authorize(IdentityServiceConstants.IdentityTenantAdministrationWritePolicy)]
    [EndpointSummary("Delete an email domain group rule.")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<IActionResult> DeleteAsync([Required] OctoObjectId rtId)
    {
        var response = await methodFacade.InvokeAsync(IdentityMethodFacade.EmailDomainGroupRuleCkTypeId,
            SystemIdentityCkIds.EmailDomainGroupRuleDeleteEmailDomainGroupRuleMethodId, rtId.ToString(),
            new EmailDomainGroupRuleDeleteEmailDomainGroupRuleParameters(), User, HttpContext.RequestAborted);
        return response.ToActionResult(new CkMethodFacadeOptions().MapSuccess(_ => new OkResult()));
    }

    private CkMethodFacadeOptions RuleFailures() => new CkMethodFacadeOptions()
        .MapError(EmailDomainGroupRuleMethodErrors.RuleAlreadyExists,
            _ => Problem(detail: "EmailDomainPattern must be unique", statusCode: StatusCodes.Status409Conflict))
        .MapError(CkMethodErrorCodes.MethodValidationFailed, error =>
        {
            ModelState.AddModelError(error.Parameters.GetValueOrDefault(CkMethodErrorParameters.Field) ?? "body",
                "The value is required.");
            return ValidationProblem(ModelState);
        });
}
