using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Methods;
using Meshmakers.Octo.Services.Methods;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Meshmakers.Octo.Services.Methods.Authorization;

namespace Meshmakers.Octo.Backend.IdentityServices.Methods;

/// <summary>Declared errors of the e-mail domain group rule methods (System.Identity 3.8.0).</summary>
internal static class EmailDomainGroupRuleMethodErrors
{
    /// <summary>A rule with this domain pattern exists.</summary>
    public const string RuleAlreadyExists = "EMAIL_DOMAIN_GROUP_RULE_ALREADY_EXISTS";

    /// <summary>Audit detail: the domain pattern of the rule.</summary>
    public const string PatternDetail = "emailDomainPattern";

    /// <summary>
    ///     Validates the parameters (both required, as the REST DTO) and stores the rule (insert or replace). <c>null</c> on
    ///     success, else the failure; nothing is stored on a failure.
    /// </summary>
    public static async Task<CkMethodFailure?> StoreAsync(IdentityMethodCall call, OctoObjectId rtId,
        string? emailDomainPattern, string? targetGroupRtId, string? description)
    {
        if (string.IsNullOrWhiteSpace(emailDomainPattern))
        {
            return CkMethodOutcome.ValidationFailed("emailDomainPattern", "required").Failure;
        }

        if (string.IsNullOrWhiteSpace(targetGroupRtId))
        {
            return CkMethodOutcome.ValidationFailed("targetGroupRtId", "required").Failure;
        }

        call.Details[PatternDetail] = emailDomainPattern;
        call.Details["targetGroupRtId"] = targetGroupRtId;
        var rule = new RtEmailDomainGroupRule
        {
            RtId = rtId, EmailDomainPattern = emailDomainPattern, TargetGroupRtId = targetGroupRtId,
            Description = description
        };
        try
        {
            await call.Services.GetRequiredService<IEmailDomainGroupRuleStore>().StoreAsync(rule).ConfigureAwait(false);
        }
        catch (DuplicateKeyException)
        {
            return new CkMethodFailure(RuleAlreadyExists);
        }

        return null;
    }
}

/// <summary>
///     Handler of the static <c>System.Identity/EmailDomainGroupRule.CreateEmailDomainGroupRule-1</c> (System.Identity 3.8.0):
///     creates a rule, as <c>POST system/v1/emailDomainGroupRules</c> did. REST is its facade.
/// </summary>
internal sealed class EmailDomainGroupRuleCreateHandler(IServiceProvider services)
    : IdentityCreateMethodHandlerBase<EmailDomainGroupRuleCreateEmailDomainGroupRuleParameters,
        EmailDomainGroupRuleCreateEmailDomainGroupRuleResult>(services)
{
    protected override RtCkId<CkTypeId> DeclaringType => RtEntityExtensions.GetRtCkTypeId<RtEmailDomainGroupRule>();

    protected override bool IsAdmitted(CkMethodPrincipal principal) =>
        IdentityMethodCallerRules.IsTenantAdministrator(principal);

    protected override async Task<CkMethodOutcome<EmailDomainGroupRuleCreateEmailDomainGroupRuleResult>> CreateAsync(
        IdentityMethodCall call, EmailDomainGroupRuleCreateEmailDomainGroupRuleParameters p,
        CancellationToken cancellationToken)
    {
        var rtId = OctoObjectId.GenerateNewId();
        var failure = await EmailDomainGroupRuleMethodErrors.StoreAsync(call, rtId, p.EmailDomainPattern,
            p.TargetGroupRtId, p.Description).ConfigureAwait(false);
        return failure != null
            ? CkMethodOutcome<EmailDomainGroupRuleCreateEmailDomainGroupRuleResult>.Fail(failure)
            : new EmailDomainGroupRuleCreateEmailDomainGroupRuleResult { Value = rtId.ToString() };
    }

    protected override string? CreatedRtIdOf(EmailDomainGroupRuleCreateEmailDomainGroupRuleResult result) => result.Value;
}

/// <summary>
///     Handler of <c>System.Identity/EmailDomainGroupRule.UpdateEmailDomainGroupRule-1</c> (System.Identity 3.8.0): replaces a
///     rule, as <c>PUT system/v1/emailDomainGroupRules/{rtId}</c> did for an existing rule.
/// </summary>
internal sealed class EmailDomainGroupRuleUpdateHandler(IServiceProvider services)
    : IdentityAdminMethodHandlerBase<EmailDomainGroupRuleUpdateEmailDomainGroupRuleParameters>(services)
{
    protected override bool IsAdmitted(CkMethodPrincipal principal) =>
        IdentityMethodCallerRules.IsTenantAdministrator(principal);

    protected override async Task<CkMethodOutcome> ApplyAsync(IdentityMethodCall call, OctoObjectId targetRtId,
        EmailDomainGroupRuleUpdateEmailDomainGroupRuleParameters p, CancellationToken cancellationToken)
    {
        if (await call.Services.GetRequiredService<IEmailDomainGroupRuleStore>().GetByIdAsync(targetRtId)
                .ConfigureAwait(false) == null)
        {
            return CkMethodOutcome.TargetNotFound();
        }

        var failure = await EmailDomainGroupRuleMethodErrors.StoreAsync(call, targetRtId, p.EmailDomainPattern,
            p.TargetGroupRtId, p.Description).ConfigureAwait(false);
        return failure != null ? CkMethodOutcome.Fail(failure) : CkMethodOutcome.Ok();
    }
}

/// <summary>
///     Handler of <c>System.Identity/EmailDomainGroupRule.DeleteEmailDomainGroupRule-1</c> (System.Identity 3.8.0): deletes a
///     rule, as <c>DELETE system/v1/emailDomainGroupRules/{rtId}</c> did.
/// </summary>
internal sealed class EmailDomainGroupRuleDeleteHandler(IServiceProvider services)
    : IdentityAdminMethodHandlerBase<EmailDomainGroupRuleDeleteEmailDomainGroupRuleParameters>(services)
{
    protected override bool IsAdmitted(CkMethodPrincipal principal) =>
        IdentityMethodCallerRules.IsTenantAdministrator(principal);

    protected override async Task<CkMethodOutcome> ApplyAsync(IdentityMethodCall call, OctoObjectId targetRtId,
        EmailDomainGroupRuleDeleteEmailDomainGroupRuleParameters parameters, CancellationToken cancellationToken)
    {
        var store = call.Services.GetRequiredService<IEmailDomainGroupRuleStore>();
        var rule = await store.GetByIdAsync(targetRtId).ConfigureAwait(false);
        if (rule == null)
        {
            return CkMethodOutcome.TargetNotFound();
        }

        call.Details[EmailDomainGroupRuleMethodErrors.PatternDetail] = rule.EmailDomainPattern;
        await store.RemoveAsync(targetRtId).ConfigureAwait(false);
        return CkMethodOutcome.Ok();
    }
}
