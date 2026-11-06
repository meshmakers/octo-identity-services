using FluentAssertions;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.Services.SourceTenantGrants;
using IdentityServices.IntegrationTests.Fixtures;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Xunit;

namespace IdentityServices.IntegrationTests.Persistence;

/// <summary>
///     AB#8341 at the service level against a real MongoDB: the shipped default policy, the audit hook (AB#8342) and the
///     rule that the looked-up identifier never reaches a log line in clear.
/// </summary>
/// <remarks>Registry: system → T, system → S (sibling of T). Users live in S and the system tenant.</remarks>
public class SourceUserLookupServiceIntegrationTests : IClassFixture<IdentityServicesFixture>
{
    private readonly IdentityServicesFixture _fixture;

    private static CancellationToken Ct => TestContext.Current.CancellationToken;

    public SourceUserLookupServiceIntegrationTests(IdentityServicesFixture fixture, ITestOutputHelper outputHelper)
    {
        _fixture = fixture;
        _fixture.OutputHelper = outputHelper;
    }

    [Fact]
    public async Task ShippedDefaultPolicy_DeniesTheSibling_AdmitsTheRegistryAncestor()
    {
        var h = await ArrangeAsync();
        var service = CreateService(new DenyNonAncestorsSourceTenantGrantPolicy());

        (await service.LookupAsync(h.Target, h.Sibling, h.SiblingUserName, "admin", Ct))
            .Should().BeNull("no tenant permits another until AB#8345");
        var ancestor = await service.LookupAsync(h.Target, h.Root, h.RootUserName, "admin", Ct);
        ancestor.Should().NotBeNull("a registry ancestor needs no permission");
        ancestor!.SourceTenantId.Should().Be(h.Root);
        ancestor.UserName.Should().Be(h.RootUserName);
    }

    [Fact]
    public async Task PermittingPolicy_FindsTheSiblingUser_AndAuditsHitAndMissWithoutTheIdentifier()
    {
        var h = await ArrangeAsync();
        var audit = new CapturingAuditSink();
        var service = CreateService(new PermitAll(), audit);
        var missedEmail = $"missed-{Guid.NewGuid():N}@secret.example";

        var hit = await service.LookupAsync(h.Target, h.Sibling, h.SiblingEmail.ToUpperInvariant(), "admin-a", Ct);
        var miss = await service.LookupAsync(h.Target, h.Sibling, missedEmail, "admin-a", Ct);
        var absentTenant = await service.LookupAsync(h.Target, "absent-tenant-8341", missedEmail, "admin-a", Ct);

        hit.Should().NotBeNull();
        hit!.UserName.Should().Be(h.SiblingUserName);
        miss.Should().BeNull();
        absentTenant.Should().BeNull();

        audit.Events.Should().HaveCount(3);
        audit.Events[0].Should().Be(new SourceUserLookupAuditEvent(h.Target, h.Sibling, "admin-a", true, true,
            hit.UserId, h.SiblingUserName));
        audit.Events[1].Should().Be(new SourceUserLookupAuditEvent(h.Target, h.Sibling, "admin-a", false, true, null,
            null));
        audit.Events[2].SourceTenantExists.Should().BeFalse("AB#8342 writes a miss for an absent tenant only into T");
        audit.Events.Select(e => e.ToString()).Should().NotContain(e =>
            e.Contains(missedEmail, StringComparison.OrdinalIgnoreCase) ||
            e.Contains(h.SiblingEmail, StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Identifier_NeverReachesTheLogInClear()
    {
        var h = await ArrangeAsync();
        var log = new CapturingLogger<SourceUserLookupService>();
        var service = CreateService(new PermitAll(), logger: log);
        var missedEmail = $"missed-{Guid.NewGuid():N}@secret.example";

        await service.LookupAsync(h.Target, h.Sibling, h.SiblingEmail, "admin", Ct);
        await service.LookupAsync(h.Target, h.Sibling, missedEmail, "admin", Ct);
        await service.LookupAsync(h.Target, "absent-tenant-8341", missedEmail, "admin", Ct);

        log.Messages.Should().HaveCountGreaterThanOrEqualTo(3);
        log.Messages.Should().NotContain(m => m.Contains(missedEmail, StringComparison.OrdinalIgnoreCase) ||
                                              m.Contains(h.SiblingEmail, StringComparison.OrdinalIgnoreCase));
        log.Messages.Should().Contain(m => m.Contains("identifier hash"));
    }

    [Fact]
    public async Task ThrowingPolicyOrAuditSink_IsAMissOrIgnored_NeverAnError()
    {
        var h = await ArrangeAsync();

        (await CreateService(new ThrowingPolicy()).LookupAsync(h.Target, h.Sibling, h.SiblingUserName, "admin", Ct))
            .Should().BeNull("a failing policy permits nothing");
        (await CreateService(new PermitAll(), new ThrowingAuditSink())
                .LookupAsync(h.Target, h.Sibling, h.SiblingUserName, "admin", Ct))
            .Should().NotBeNull("a failing audit write never breaks the lookup");
    }

    // ---------- arrangement ----------

    private sealed record Hierarchy(string Root, string Target, string Sibling, string SiblingUserName,
        string SiblingEmail, string RootUserName);

    private async Task<Hierarchy> ArrangeAsync()
    {
        await _fixture.InitializeAsync();
        var systemContext = _fixture.GetSystemContext();
        var root = systemContext.TenantId;
        await _fixture.GetService<IDefaultConfigurationCreatorService>().SetupAsync(root);
        var target = await CreateChildAsync(systemContext, NewId("tgt"));
        var sibling = await CreateChildAsync(systemContext, NewId("sib"));

        var siblingUserName = NewId("alice");
        var siblingEmail = $"{siblingUserName}@secret.example";
        await InsertUserAsync((await systemContext.TryFindTenantRepositoryAsync(sibling))!, siblingUserName,
            siblingEmail);
        var rootUserName = NewId("root");
        await InsertUserAsync(systemContext.GetSystemTenantRepositoryAsAdmin(), rootUserName,
            $"{rootUserName}@example.com");
        return new Hierarchy(root, target, sibling, siblingUserName, siblingEmail, rootUserName);
    }

    private static string NewId(string prefix) => $"{prefix}-{Guid.NewGuid():N}"[..20];

    private async Task<string> CreateChildAsync(ITenantContext parent, string tenantId)
    {
        using (var session = await parent.GetAdminSessionAsync())
        {
            session.StartTransaction();
            await parent.CreateChildTenantAsync(session, tenantId, tenantId);
            await session.CommitTransactionAsync();
        }

        await _fixture.GetService<IDefaultConfigurationCreatorService>().SetupAsync(tenantId);
        return tenantId;
    }

    private static async Task InsertUserAsync(
        Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories.ITenantRepository repository, string userName,
        string email)
    {
        using var session = await repository.GetSessionAsync();
        session.StartTransaction();
        await repository.InsertOneRtEntityAsync(session, new RtUser
        {
            RtId = OctoObjectId.GenerateNewId(),
            UserName = userName,
            NormalizedUserName = userName.ToUpperInvariant(),
            Email = email,
            NormalizedEmail = email.ToUpperInvariant(),
            EmailConfirmed = true,
            SecurityStamp = Guid.NewGuid().ToString()
        });
        await session.CommitTransactionAsync();
    }

    private SourceUserLookupService CreateService(ISourceTenantGrantPolicy policy,
        ISourceUserLookupAuditSink? audit = null, ILogger<SourceUserLookupService>? logger = null)
    {
        var systemContext = _fixture.GetSystemContext();
        return new SourceUserLookupService(
            new TenantRegistry(systemContext, new Microsoft.Extensions.Caching.Memory.MemoryCache(
                new Microsoft.Extensions.Caching.Memory.MemoryCacheOptions())),
            TestAncestryGuards.Create(systemContext, CrossTenantAncestryMode.Enforce),
            policy,
            audit ?? new NoOpSourceUserLookupAuditSink(),
            Options.Create(new IdentityOptions()),
            TimeProvider.System,
            logger ?? new CapturingLogger<SourceUserLookupService>());
    }

    private sealed class PermitAll : ISourceTenantGrantPolicy
    {
        public Task<bool> IsPermittedAsync(string sourceTenantId, string targetTenantId,
            CancellationToken cancellationToken = default) => Task.FromResult(true);
    }

    private sealed class ThrowingPolicy : ISourceTenantGrantPolicy
    {
        public Task<bool> IsPermittedAsync(string sourceTenantId, string targetTenantId,
            CancellationToken cancellationToken = default) => throw new InvalidOperationException("policy down");
    }

    private sealed class CapturingAuditSink : ISourceUserLookupAuditSink
    {
        public List<SourceUserLookupAuditEvent> Events { get; } = [];

        public Task RecordAsync(SourceUserLookupAuditEvent auditEvent, CancellationToken cancellationToken = default)
        {
            Events.Add(auditEvent);
            return Task.CompletedTask;
        }
    }

    private sealed class ThrowingAuditSink : ISourceUserLookupAuditSink
    {
        public Task RecordAsync(SourceUserLookupAuditEvent auditEvent, CancellationToken cancellationToken = default)
            => throw new InvalidOperationException("audit down");
    }

    private sealed class CapturingLogger<T> : ILogger<T>
    {
        private readonly List<string> _messages = [];

        public IReadOnlyList<string> Messages
        {
            get
            {
                lock (_messages)
                {
                    return _messages.ToList();
                }
            }
        }

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            lock (_messages)
            {
                _messages.Add(formatter(state, exception) + (exception == null ? "" : " " + exception.Message));
            }
        }
    }
}
