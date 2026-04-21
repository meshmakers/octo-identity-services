using System.Security.Claims;
using IdentityModel;
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

    public async Task SyncExternalGroupClaimsAsync(RtUser user, IReadOnlyList<Claim> externalClaims)
    {
        try
        {
            var roleClaims = externalClaims
                .Where(c => c.Type == JwtClaimTypes.Role || c.Type == ClaimTypes.Role)
                .Select(c => c.Value)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            logger.LogInformation(
                "Syncing external group claims for user '{UserName}': found {RoleClaimCount} role claim(s) [{RoleClaims}]",
                user.UserName, roleClaims.Count, string.Join(", ", roleClaims));

            if (roleClaims.Count == 0)
            {
                return;
            }

            var userIdString = user.RtId.ToString();

            // Resolve external group names to OctoMesh groups
            var desiredGroupIds = new HashSet<string>();
            foreach (var groupName in roleClaims)
            {
                var normalizedName = groupName.ToUpperInvariant();
                var group = await groupStore.FindByNameAsync(normalizedName);
                if (group != null)
                {
                    logger.LogInformation(
                        "Matched external group claim '{GroupName}' to OctoMesh group '{OctoGroupName}' (RtId: {GroupRtId})",
                        groupName, group.GroupName, group.RtId);
                    desiredGroupIds.Add(group.RtId.ToString());
                }
                else
                {
                    logger.LogWarning(
                        "No OctoMesh group found for external group claim '{GroupName}' (normalized: '{NormalizedName}'), skipping for user '{UserName}'",
                        groupName, normalizedName, user.UserName);
                }
            }

            if (desiredGroupIds.Count == 0)
            {
                logger.LogWarning(
                    "None of the {Count} external group claim(s) matched any OctoMesh group for user '{UserName}'",
                    roleClaims.Count, user.UserName);
                return;
            }

            // Get current group memberships to diff
            var allGroups = (await groupStore.GetAllAsync()).ToList();
            var currentGroupIds = new HashSet<string>();
            foreach (var group in allGroups)
            {
                var memberUserIds = await groupStore.GetMemberUserIdsAsync(group.RtId);
                if (memberUserIds.Contains(userIdString))
                {
                    currentGroupIds.Add(group.RtId.ToString());
                }
            }

            // Add user to new groups
            var groupsToAdd = desiredGroupIds.Except(currentGroupIds).ToList();
            if (groupsToAdd.Count == 0)
            {
                logger.LogInformation(
                    "User '{UserName}' is already a member of all {Count} matched group(s), no changes needed",
                    user.UserName, desiredGroupIds.Count);
                return;
            }

            foreach (var groupId in groupsToAdd)
            {
                try
                {
                    await groupStore.AddMemberUserAsync(new OctoObjectId(groupId), userIdString);
                    var group = await groupStore.FindByIdAsync(new OctoObjectId(groupId));
                    logger.LogInformation(
                        "Added user '{UserName}' to group '{GroupName}' via external identity group sync",
                        user.UserName, group?.GroupName ?? groupId);
                }
                catch (Exception ex)
                {
                    logger.LogError(ex,
                        "Failed to add user '{UserName}' to group '{GroupId}' via external identity group sync",
                        user.UserName, groupId);
                }
            }
        }
        catch (Exception ex)
        {
            logger.LogError(ex,
                "External group claim sync failed for user '{UserName}'. Login will proceed without group synchronization.",
                user.UserName);
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
