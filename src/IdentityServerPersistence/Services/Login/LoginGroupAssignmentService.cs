using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Microsoft.Extensions.Logging;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.Services.Login;

public class LoginGroupAssignmentService(
    IGroupStore groupStore,
    IEmailDomainGroupRuleStore emailDomainGroupRuleStore,
    ILogger<LoginGroupAssignmentService> logger) : ILoginGroupAssignmentService
{
    public async Task AssignGroupsAsync(RtUser user, RtIdentityProvider? provider)
    {
        var assignedGroupIds = new HashSet<string>();

        // 1. Provider's default group
        if (!string.IsNullOrEmpty(provider?.DefaultGroupRtId))
        {
            await AddUserToGroupAsync(user, provider.DefaultGroupRtId, assignedGroupIds, "provider default");
        }

        // 2. Email domain rules (may not be available if the CK type is not imported in this tenant)
        if (!string.IsNullOrEmpty(user.Email) && user.Email.Contains('@'))
        {
            try
            {
                var domain = user.Email.Split('@', 2)[1].ToLowerInvariant();

                var rules = await emailDomainGroupRuleStore.GetAllAsync();
                foreach (var rule in rules)
                {
                    if (!string.IsNullOrEmpty(rule.EmailDomainPattern) &&
                        !string.IsNullOrEmpty(rule.TargetGroupRtId) &&
                        string.Equals(rule.EmailDomainPattern, domain, StringComparison.OrdinalIgnoreCase))
                    {
                        await AddUserToGroupAsync(user, rule.TargetGroupRtId, assignedGroupIds, $"email domain rule '{rule.EmailDomainPattern}'");
                    }
                }
            }
            catch (CkCacheException ex)
            {
                logger.LogDebug(ex,
                    "EmailDomainGroupRule CK type not available in tenant, skipping email domain group assignment for user '{UserName}'",
                    user.UserName);
            }
        }
    }

    private async Task AddUserToGroupAsync(RtUser user, string groupRtId, HashSet<string> assignedGroupIds, string source)
    {
        if (!assignedGroupIds.Add(groupRtId))
        {
            return; // Already assigned in this session
        }

        try
        {
            var group = await groupStore.FindByIdAsync(new OctoObjectId(groupRtId));
            if (group == null)
            {
                logger.LogWarning(
                    "Group '{GroupRtId}' referenced by {Source} does not exist, skipping assignment for user '{UserName}'",
                    groupRtId, source, user.UserName);
                return;
            }

            await groupStore.AddMemberUserAsync(new OctoObjectId(groupRtId), user.RtId.ToString());

            logger.LogInformation(
                "Added user '{UserName}' to group '{GroupName}' via {Source}",
                user.UserName, group.GroupName, source);
        }
        catch (Exception ex)
        {
            logger.LogError(ex,
                "Failed to add user '{UserName}' to group '{GroupRtId}' via {Source}",
                user.UserName, groupRtId, source);
        }
    }
}
