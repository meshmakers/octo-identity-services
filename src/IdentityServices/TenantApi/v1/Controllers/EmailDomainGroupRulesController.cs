using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using Asp.Versioning;
using AutoMapper;
using IdentityModel;
using IdentityServerPersistence;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.IdentityServices.TenantApi.v1.Controllers;

/// <summary>
///     REST Controller for email domain group rule management
/// </summary>
[Authorize(AuthenticationSchemes = OidcConstants.AuthenticationSchemes.AuthorizationHeaderBearer)]
[Route(IdentityServiceConstants.ApiPathPrefix + "/[controller]")]
[ApiController]
[ApiVersion(IdentityServiceConstants.ApiVersion1)]
public class EmailDomainGroupRulesController(
    IEmailDomainGroupRuleStore emailDomainGroupRuleStore,
    IMapper mapper) : ControllerBase
{
    [HttpGet]
    [Authorize(IdentityServiceConstants.IdentityApiReadOnlyPolicy)]
    [EndpointSummary("Returns all email domain group rules.")]
    [ProducesResponseType(typeof(EmailDomainGroupRulesResult), StatusCodes.Status200OK)]
    public async Task<ActionResult<EmailDomainGroupRulesResult>> GetAllAsync()
    {
        var rules = await emailDomainGroupRuleStore.GetAllAsync();
        return new EmailDomainGroupRulesResult
        {
            EmailDomainGroupRules = rules.Select(mapper.Map<EmailDomainGroupRuleDto>)
        };
    }

    [HttpGet("{rtId}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadOnlyPolicy)]
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

        return mapper.Map<EmailDomainGroupRuleDto>(rule);
    }

    [HttpPost]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Create a new email domain group rule.")]
    [ProducesResponseType(typeof(EmailDomainGroupRuleDto), StatusCodes.Status201Created)]
    [ProducesResponseType(typeof(UniquenessViolationErrorResponse), StatusCodes.Status400BadRequest)]
    public async Task<ActionResult<EmailDomainGroupRuleDto>> CreateAsync(
        [FromBody][Description("The email domain group rule to create.")] EmailDomainGroupRuleDto dto)
    {
        var rule = mapper.Map<RtEmailDomainGroupRule>(dto);
        rule.RtId = new OctoObjectId(Guid.NewGuid().ToString("N"));

        await HandleWriteExceptionAsync(async () => await emailDomainGroupRuleStore.StoreAsync(rule));

        var resultDto = mapper.Map<EmailDomainGroupRuleDto>(rule);
        return CreatedAtAction(nameof(GetByIdAsync), new { rtId = rule.RtId }, resultDto);
    }

    [HttpPut("{rtId}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Replace an existing email domain group rule.")]
    [ProducesResponseType(typeof(EmailDomainGroupRuleDto), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(UniquenessViolationErrorResponse), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    public async Task<ActionResult<EmailDomainGroupRuleDto>> UpdateAsync(
        [FromRoute][Required] OctoObjectId rtId,
        [FromBody][Required][Description("The updated email domain group rule.")] EmailDomainGroupRuleDto dto)
    {
        var rule = mapper.Map<RtEmailDomainGroupRule>(dto);
        rule.RtId = rtId;

        await HandleWriteExceptionAsync(async () => await emailDomainGroupRuleStore.StoreAsync(rule));
        return Ok(mapper.Map<EmailDomainGroupRuleDto>(rule));
    }

    [HttpDelete("{rtId}")]
    [Authorize(IdentityServiceConstants.IdentityApiReadWritePolicy)]
    [EndpointSummary("Delete an email domain group rule.")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> DeleteAsync([Required] OctoObjectId rtId)
    {
        await emailDomainGroupRuleStore.RemoveAsync(rtId);
        return Ok();
    }

    private static async Task HandleWriteExceptionAsync(Func<Task> action)
    {
        try
        {
            await action();
        }
        catch (DuplicateKeyException ex)
        {
            throw new DuplicateKeyException("EmailDomainPattern must be unique", typeof(EmailDomainGroupRuleDto),
                new[] { nameof(EmailDomainGroupRuleDto.EmailDomainPattern) }, ex);
        }
    }
}
