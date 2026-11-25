using System.Text.RegularExpressions;
using FluentAssertions;
using IdentityServices.IntegrationTests.Fixtures;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace IdentityServices.IntegrationTests.Persistence;

/// <summary>
///     The startup path of the service sets the child tenants up in parallel (<see cref="DefaultConfigurationInitializationService" />
///     runs <c>SetupAsync</c> of ONE creator service for several tenants at once), and every setup applies the
///     <c>System.Identity.Bootstrap</c> seed through the same blueprint service. When that blueprint service imported on one
///     shared import command, a tenant import that started reset the queues, the duplicate check and the guard entries of
///     the import still running for another tenant: seed entities or associations went missing in one tenant, or were
///     flushed into the session of another, and every overlapping pass logged "Duplicate RtId ... within one import
///     payload" for a seed without duplicates. This test runs the real initialization service over several fresh child
///     tenants and checks that every tenant holds exactly its seed, every seed association exactly once, and that no
///     duplicate warning was logged.
/// </summary>
[Collection("Sequential")]
public class ConcurrentTenantSeedImportIntegrationTests : IClassFixture<IdentityServicesWithBootstrapFixture>
{
    private const int ChildTenants = 6;

    private static readonly string SeedDirectory = Path.Combine(FindRepositoryRoot(), "src", "Persistence.IdentityCkModel",
        "Blueprints", "System.Identity.Bootstrap", "seed-data");

    private readonly IdentityServicesWithBootstrapFixture _fixture;

    public ConcurrentTenantSeedImportIntegrationTests(IdentityServicesWithBootstrapFixture fixture,
        ITestOutputHelper outputHelper)
    {
        _fixture = fixture;
        _fixture.OutputHelper = outputHelper;
    }

    [Fact]
    public async Task ParallelTenantSetup_GivesEveryTenantExactlyItsOwnSeed_AndLogsNoDuplicate()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();

        var prefix = $"cs{Guid.NewGuid():N}"[..10];
        var tenantIds = Enumerable.Range(0, ChildTenants).Select(i => $"{prefix}{i}").ToList();
        using (var session = await systemContext.GetAdminSessionAsync())
        {
            session.StartTransaction();
            foreach (var tenantId in tenantIds)
            {
                await systemContext.CreateChildTenantAsync(session, tenantId, tenantId);
            }

            await session.CommitTransactionAsync();
        }

        _fixture.Warnings.Entries.Clear();

        // The real startup path: system tenant first, then every child tenant in parallel through one creator service.
        var initialization = new DefaultConfigurationInitializationService(
            NullLogger<DefaultConfigurationInitializationService>.Instance, systemContext,
            _fixture.GetService<IDefaultConfigurationCreatorService>());
        await initialization.InitializeAsync();

        var (entities, associations) = ReadSeed();
        entities.Should().HaveCount(41, "System.Identity.Bootstrap 1.10.0 seeds 41 entities");

        foreach (var tenantId in tenantIds)
        {
            var tenantContext = await systemContext.GetChildTenantContextAsync(tenantId);
            var repo = tenantContext.GetTenantRepositoryAsAdmin();
            using var check = await repo.GetSessionAsync();
            check.StartTransaction();

            foreach (var (rtId, ckTypeId) in entities)
            {
                var entity = await repo.GetRtEntityByRtIdAsync(check,
                    new RtEntityId(new RtCkId<CkTypeId>(ckTypeId), OctoObjectId.Parse(rtId)));
                entity.Should().NotBeNull("tenant {0} holds seed entity {1} ({2})", tenantId, rtId, ckTypeId);
            }

            // Exactly the seed: no seed-range entity of a type more often than the seed has it.
            foreach (var group in entities.GroupBy(e => e.CkTypeId))
            {
                var stored = (await repo.GetRtEntitiesByTypeAsync(check, new RtCkId<CkTypeId>(group.Key),
                        RtEntityQueryOptions.Create()))
                    .Items.Select(e => e.RtId.ToString().ToLowerInvariant())
                    .Where(id => id.StartsWith("6600000000000000000000", StringComparison.Ordinal))
                    .ToList();
                stored.Should().BeEquivalentTo(group.Select(e => e.RtId),
                    "tenant {0} holds exactly the seed entities of type {1}", tenantId, group.Key);
            }

            foreach (var (origin, originCkTypeId, roleId, target, targetCkTypeId) in associations)
            {
                var edge = await repo.GetRtAssociationOrDefaultAsync(check,
                    new RtEntityId(new RtCkId<CkTypeId>(originCkTypeId), OctoObjectId.Parse(origin)),
                    new RtEntityId(new RtCkId<CkTypeId>(targetCkTypeId), OctoObjectId.Parse(target)),
                    new RtCkId<CkAssociationRoleId>(roleId));
                edge.Should().NotBeNull("tenant {0} holds seed association {1} -{2}-> {3}", tenantId, origin, roleId,
                    target);
            }

            await check.CommitTransactionAsync();
        }

        _fixture.Warnings.Entries.Where(e => e.Message.Contains("Duplicate RtId", StringComparison.Ordinal))
            .Should().BeEmpty("the seed has no duplicate rtId, so no import of it may report one");
    }

    /// <summary>The seed entities (rtId, CK type) and associations of the blueprint, read from its seed files.</summary>
    private static (List<(string RtId, string CkTypeId)> Entities,
        List<(string Origin, string OriginCkTypeId, string RoleId, string Target, string TargetCkTypeId)> Associations)
        ReadSeed()
    {
        var entities = new List<(string, string)>();
        var associations = new List<(string, string, string, string, string)>();
        var entityStart = new Regex(@"^  - rtId:\s*'?([0-9A-Fa-f]{24})'?");
        var ckType = new Regex(@"^    ckTypeId:\s*(\S+)");
        var role = new Regex(@"^      - roleId:\s*(\S+)");
        var targetId = new Regex(@"^        targetRtId:\s*'?([0-9A-Fa-f]{24})'?");
        var targetType = new Regex(@"^        targetCkTypeId:\s*(\S+)");

        foreach (var file in Directory.GetFiles(SeedDirectory, "*.yaml", SearchOption.AllDirectories).Order())
        {
            string? rtId = null, type = null, roleId = null, target = null;
            foreach (var line in File.ReadLines(file))
            {
                Match m;
                if ((m = entityStart.Match(line)).Success)
                {
                    rtId = m.Groups[1].Value.ToLowerInvariant();
                    type = null;
                }
                else if (rtId != null && (m = ckType.Match(line)).Success)
                {
                    type = m.Groups[1].Value;
                    entities.Add((rtId, type));
                }
                else if (rtId != null && (m = role.Match(line)).Success)
                {
                    roleId = m.Groups[1].Value;
                }
                else if (roleId != null && (m = targetId.Match(line)).Success)
                {
                    target = m.Groups[1].Value.ToLowerInvariant();
                }
                else if (target != null && type != null && (m = targetType.Match(line)).Success)
                {
                    associations.Add((rtId!, type, roleId!, target, m.Groups[1].Value));
                    roleId = null;
                    target = null;
                }
            }
        }

        return (entities, associations);
    }

    private static string FindRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory != null && !File.Exists(Path.Combine(directory.FullName, "Octo.Identity.sln")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ??
               throw new DirectoryNotFoundException("Octo.Identity.sln not found above " + AppContext.BaseDirectory);
    }
}
