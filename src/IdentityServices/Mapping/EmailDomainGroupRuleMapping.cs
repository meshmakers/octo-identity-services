using Meshmakers.Octo.Communication.Contracts.DataTransferObjects;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace Meshmakers.Octo.Backend.IdentityServices.Mapping;

public static class EmailDomainGroupRuleMapping
{
    public static EmailDomainGroupRuleDto ToDto(this RtEmailDomainGroupRule rule) => new()
    {
        RtId = rule.RtId,
        EmailDomainPattern = rule.EmailDomainPattern,
        TargetGroupRtId = rule.TargetGroupRtId,
        Description = rule.Description
    };

    public static RtEmailDomainGroupRule ToEntity(this EmailDomainGroupRuleDto dto) => new()
    {
        EmailDomainPattern = dto.EmailDomainPattern!,
        TargetGroupRtId = dto.TargetGroupRtId!,
        Description = dto.Description
    };
}
