using Meshmakers.Octo.ConstructionKit.Contracts;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;

namespace IdentityServerPersistence.SystemStores;

public interface IEmailDomainGroupRuleStore
{
    Task<RtEmailDomainGroupRule?> GetByIdAsync(OctoObjectId rtId);
    Task<IEnumerable<RtEmailDomainGroupRule>> GetAllAsync();
    Task<RtEmailDomainGroupRule?> GetByDomainPatternAsync(string domainPattern);
    Task StoreAsync(RtEmailDomainGroupRule rule);
    Task RemoveAsync(OctoObjectId rtId);
}
