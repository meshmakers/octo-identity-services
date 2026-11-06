using IdentityServerPersistence.Services;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;

namespace IdentityServices.IntegrationTests.Persistence;

/// <summary>
///     Builds the real <see cref="CrossTenantAncestryGuard" /> (AB#8339) over the test's system context. The default mode is
///     the shipped default, <see cref="CrossTenantAncestryMode.Warn" />, so tests that arrange their hierarchy through
///     OctoTenant identity providers alone keep the behaviour they pin.
/// </summary>
internal static class TestAncestryGuards
{
    public static CrossTenantAncestryGuard Create(ISystemContext systemContext,
        CrossTenantAncestryMode mode = CrossTenantAncestryMode.Warn, ILogger<CrossTenantAncestryGuard>? logger = null)
    {
        var options = Substitute.For<IOptionsMonitor<CrossTenantAncestryOptions>>();
        options.CurrentValue.Returns(new CrossTenantAncestryOptions { CrossTenantAncestry = mode });
        var registry = new TenantRegistry(systemContext,
            new Microsoft.Extensions.Caching.Memory.MemoryCache(new Microsoft.Extensions.Caching.Memory.MemoryCacheOptions()));
        return new CrossTenantAncestryGuard(registry, systemContext, options,
            logger ?? NullLogger<CrossTenantAncestryGuard>.Instance);
    }
}
