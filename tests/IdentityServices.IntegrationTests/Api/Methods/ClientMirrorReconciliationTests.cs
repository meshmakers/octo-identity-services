using System.Collections.Concurrent;
using System.Diagnostics.Metrics;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using FluentAssertions;
using IdentityServerPersistence.Services;
using IdentityServerPersistence.SystemStores;
using IdentityServices.IntegrationTests.Infrastructure;
using Meshmakers.Octo.Backend.IdentityServices.Methods;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Methods;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Meshmakers.Octo.Services.Methods;
using Meshmakers.Octo.Services.Methods.Authorization;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServices.IntegrationTests.Api.Methods;

/// <summary>
///     AB#8019: a secret removed (or added, or expired) in the parent tenant reaches every child-tenant mirror through the
///     periodic reconciliation even when the immediate mirror sync after the write failed. Real MongoDB, real child tenant,
///     the real <c>Client.AddSecret</c> / <c>Client.RemoveSecret</c> handlers and the real token endpoint. The failure is
///     injected by a decorator of <see cref="IClientMirrorProvisioningService" /> whose <c>SyncMirrorsForClientAsync</c>
///     throws (child database unreachable); everything else, including the reconciliation, is the production service.
/// </summary>
public class ClientMirrorReconciliationTests : IntegrationTestBase
{
    private const string ApiScope = "client-mirror-reconcile-api";
    private static readonly string[] TenantAdminRoles = ["TenantManagement"];

    private readonly WebApplicationFactory<Program> _enabled;
    private readonly WebApplicationFactory<Program> _syncFails;
    private readonly CapturingLoggerProvider _logs = new();

    public ClientMirrorReconciliationTests(CustomWebApplicationFactory factory) : base(factory)
    {
        _enabled = factory.WithWebHostBuilder(b =>
        {
            b.UseSetting("Methods:Identity:EnablePasswordMethods", "true");
            b.ConfigureTestServices(services =>
            {
                // The test host has no broker: drop the bus side of the method host.
                foreach (var descriptor in services
                             .Where(d => d.ImplementationType?.Name is "CkMethodHandlerStartupService"
                                 or "CkMethodHandlerHeartbeatService").ToList())
                {
                    services.Remove(descriptor);
                }

                services.AddLogging(l => l.AddProvider(_logs));
            });
        });
        _syncFails = _enabled.WithWebHostBuilder(b => b.ConfigureTestServices(services =>
        {
            services.RemoveAll<IClientMirrorProvisioningService>();
            services.AddScoped<IClientMirrorProvisioningService>(sp =>
                new FailingSyncMirrorService(ActivatorUtilities.CreateInstance<ClientMirrorProvisioningService>(sp)));
        }));
    }

    [Fact]
    public async Task RemovedSecret_WhenTheMirrorSyncFails_StaysValidInTheChild_UntilTheJobRuns_ThenTheChildTokenFails()
    {
        var ct = TestContext.Current.CancellationToken;
        var client = await CreateFlaggedClientAsync();
        var secret = (await AddAsync(client, ct)).Value!.Value!;
        var child = await CreateChildTenantAsync();
        (await RequestTokenAsync(child, client.ClientId, secret, ct)).Should().Be(HttpStatusCode.OK,
            "the mirror carries the parent's secret");
        using var reconciled = CaptureReconciledMetric();

        var removed = await RemoveAsync(client, secret, ct, _syncFails);

        removed.IsSuccess.Should().BeTrue("the parent write committed; the mirror sync is best effort");
        (await RequestTokenAsync(NormalizedSystemTenantId, client.ClientId, secret, ct)).Should()
            .Be(HttpStatusCode.Unauthorized);
        (await RequestTokenAsync(child, client.ClientId, secret, ct)).Should().Be(HttpStatusCode.OK,
            "the failed sync left the removed secret in the mirror (the gap of AB#8019)");

        var result = await RunJobAsync(ct);

        result.MirrorsRepaired.Should().BeGreaterThanOrEqualTo(1);
        (await RequestTokenAsync(child, client.ClientId, secret, ct)).Should().Be(HttpStatusCode.Unauthorized,
            "the job removed the secret from the mirror");
        var mirror = await GetMirrorAsync(child, client.ClientId);
        mirror.ClientSecrets.Should().NotContain(s => s.Value == Sha256Base64(secret));
        mirror.ClientSecrets.Should().ContainSingle(s => ClientMirrorSecrets.IsOwnSecret(s),
            "the mirror's own secret survives the repair");
        (await GetTrackingRowAsync(client.ClientId, child))!.SecretHashVersion.Should().BeGreaterThan(0);
        reconciled.Measurements.Should().Contain(m => m.Outcome == "repaired" && m.Value >= 1);
        _logs.Messages.Should().NotContain(m => m.Text.Contains(secret), "no secret value in any log line");
        _logs.Messages.Where(m => m.Level >= LogLevel.Information).Should()
            .NotContain(m => m.Text.Contains(Sha256Base64(secret)), "no secret hash in a log line at Information or above");
    }

    [Fact]
    public async Task AddedSecret_WhenTheMirrorSyncFails_ReachesTheChildAfterTheJob()
    {
        var ct = TestContext.Current.CancellationToken;
        var client = await CreateFlaggedClientAsync();
        var child = await CreateChildTenantAsync();

        var secret = (await AddAsync(client, ct, _syncFails)).Value!.Value!;

        (await RequestTokenAsync(NormalizedSystemTenantId, client.ClientId, secret, ct)).Should().Be(HttpStatusCode.OK);
        (await RequestTokenAsync(child, client.ClientId, secret, ct)).Should().Be(HttpStatusCode.Unauthorized,
            "the failed sync did not copy the new secret");

        await RunJobAsync(ct);

        (await RequestTokenAsync(child, client.ClientId, secret, ct)).Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task ExpiredParentSecret_IsExpiredInTheMirrorToo_AfterTheJob()
    {
        var ct = TestContext.Current.CancellationToken;
        var client = await CreateFlaggedClientAsync();
        var secret = (await AddAsync(client, ct)).Value!.Value!;
        var child = await CreateChildTenantAsync();
        (await RequestTokenAsync(child, client.ClientId, secret, ct)).Should().Be(HttpStatusCode.OK);

        // An expiry written without a mirror sync (the stores sync only after their own writes).
        var parentRepo = await RepositoryAsync(NormalizedSystemTenantId);
        using (var session = await parentRepo.GetSessionAsync())
        {
            var stored = (await parentRepo.GetRtEntitiesByTypeAsync<RtClient>(session, ByClientId(client.ClientId)))
                .Items.Single();
            var record = stored.ClientSecrets[0];
            record.ExpirationDateTime = DateTime.UtcNow.AddMinutes(-1);
            stored.ClientSecrets[0] = record;
            await parentRepo.ReplaceOneRtEntityByIdAsync(session, stored.RtId, stored);
        }

        (await RequestTokenAsync(NormalizedSystemTenantId, client.ClientId, secret, ct)).Should()
            .Be(HttpStatusCode.Unauthorized);

        await RunJobAsync(ct);

        (await RequestTokenAsync(child, client.ClientId, secret, ct)).Should().Be(HttpStatusCode.Unauthorized,
            "the mirror copies the expiry, so an expired parent secret is expired in the child too");
        (await GetMirrorAsync(child, client.ClientId)).ClientSecrets.Should()
            .Contain(s => s.Value == Sha256Base64(secret) && s.ExpirationDateTime != null);
    }

    [Fact]
    public async Task MirrorInSync_IsNotWritten()
    {
        var ct = TestContext.Current.CancellationToken;
        var client = await CreateFlaggedClientAsync();
        await AddAsync(client, ct);
        var child = await CreateChildTenantAsync();
        await RunJobAsync(ct);
        var before = await GetMirrorAsync(child, client.ClientId);
        var rowBefore = (await GetTrackingRowAsync(client.ClientId, child))!.SecretHashVersion;

        await RunJobAsync(ct);

        var after = await GetMirrorAsync(child, client.ClientId);
        after.RtVersion.Should().Be(before.RtVersion, "a mirror in sync is not rewritten");
        (await GetTrackingRowAsync(client.ClientId, child))!.SecretHashVersion.Should().Be(rowBefore);
    }

    [Fact]
    public async Task DeletedParentClient_WhoseMirrorCleanupFailed_LosesItsMirror_ThroughTheJob()
    {
        var ct = TestContext.Current.CancellationToken;
        var client = await CreateFlaggedClientAsync();
        var secret = (await AddAsync(client, ct)).Value!.Value!;
        var child = await CreateChildTenantAsync();
        (await RequestTokenAsync(child, client.ClientId, secret, ct)).Should().Be(HttpStatusCode.OK);

        // The parent client is gone, its mirror cleanup never ran.
        var parentRepo = await RepositoryAsync(NormalizedSystemTenantId);
        using (var session = await parentRepo.GetSessionAsync())
        {
            await parentRepo.DeleteOneRtEntityByRtIdAsync<RtClient>(session, client.RtId, DeleteOptions.Erase);
        }

        var result = await RunJobAsync(ct);

        result.MirrorsRemoved.Should().BeGreaterThanOrEqualTo(1);
        (await RequestTokenAsync(child, client.ClientId, secret, ct)).Should().Be(HttpStatusCode.Unauthorized);
        (await FindMirrorAsync(child, client.ClientId)).Should().BeNull();
        (await GetTrackingRowAsync(client.ClientId, child)).Should().BeNull();
    }

    [Fact]
    public async Task ParallelPasses_OnTwoReplicas_ConvergeOnTheSameState_WithoutADuplicateMirror()
    {
        var ct = TestContext.Current.CancellationToken;
        var client = await CreateFlaggedClientAsync();
        var secret = (await AddAsync(client, ct)).Value!.Value!;
        var child = await CreateChildTenantAsync();
        await RemoveAsync(client, secret, ct, _syncFails);

        // Two scopes = two replicas working on the same databases at the same time.
        var passes = await Task.WhenAll(RunJobAsync(ct), RunJobAsync(ct));

        passes.Should().OnlyContain(p => p.MirrorsFailed == 0);
        var clients = await ChildClientsAsync(child, client.ClientId);
        clients.Should().ContainSingle("a concurrent repair never duplicates the mirror");
        clients[0].ClientSecrets.Should().NotContain(s => s.Value == Sha256Base64(secret));
        (await RequestTokenAsync(child, client.ClientId, secret, ct)).Should().Be(HttpStatusCode.Unauthorized);
    }

    #region Helpers

    private const string AdminSubject = "507f1f77bcf86cd799439012";

    private static CkMethodPrincipal Admin() => new(AdminSubject, TenantAdminRoles, ["octo_api"]);

    private static RtEntityQueryOptions ByClientId(string clientId) => RtEntityQueryOptions.Create()
        .FieldFilter(nameof(RtClient.ClientId), FieldFilterOperator.Equals, clientId);

    private async Task<ClientMirrorReconciliationResult> RunJobAsync(CancellationToken ct)
    {
        using var scope = _enabled.Services.CreateScope();
        return await scope.ServiceProvider.GetRequiredService<IClientMirrorReconciliationJob>().RunOnceAsync(ct);
    }

    private async Task<RtClient> CreateFlaggedClientAsync()
    {
        using var scope = _enabled.Services.CreateScope();
        await EnsureApiScopeAsync(await RepositoryAsync(NormalizedSystemTenantId));
        var client = new RtClientBuilder().WithClientId($"m8019-{Guid.NewGuid():N}")
            .WithGrantTypes("client_credentials").WithScopes(ApiScope).RequireClientSecret().RequirePkce(false)
            .WithAutoProvisionInChildTenants().Build();
        await scope.ServiceProvider.GetRequiredService<IOctoClientStore>().CreateAsync(client);
        return client;
    }

    private static async Task EnsureApiScopeAsync(ITenantRepository repo)
    {
        using var session = await repo.GetSessionAsync();
        var existing = await repo.GetRtEntitiesByTypeAsync<RtApiScope>(session, RtEntityQueryOptions.Create()
            .FieldFilter(nameof(RtApiScope.Name), FieldFilterOperator.Equals, ApiScope));
        if (existing.Items.Any())
        {
            return;
        }

        await repo.InsertOneRtEntityAsync(session, new RtApiScope
        {
            RtId = OctoObjectId.GenerateNewId(),
            Name = ApiScope,
            DisplayName = "Client mirror reconciliation API",
            Enabled = true,
            ShowInDiscoveryDocument = true,
            Claims = new AttributeStringValueList(),
            IsEmphasized = false,
            IsRequired = false
        });
    }

    /// <summary>A child tenant of the system tenant; its setup provisions the mirrors of every flagged system client.</summary>
    private async Task<string> CreateChildTenantAsync()
    {
        var childTenantId = $"mrec{Guid.NewGuid():N}"[..20];
        var systemContext = Factory.Services.GetRequiredService<ISystemContext>();
        using (var session = await systemContext.GetAdminSessionAsync())
        {
            session.StartTransaction();
            await systemContext.CreateChildTenantAsync(session, childTenantId, childTenantId);
            await session.CommitTransactionAsync();
        }

        using (var scope = CreateScope())
        {
            await scope.ServiceProvider.GetRequiredService<IDefaultConfigurationCreatorService>()
                .SetupAsync(childTenantId);
        }

        await EnsureApiScopeAsync(await RepositoryAsync(childTenantId));
        await WaitUntilRegistryKnowsAsync(childTenantId);
        return childTenantId;
    }

    private async Task WaitUntilRegistryKnowsAsync(string tenantId)
    {
        var deadline = DateTimeOffset.UtcNow + TenantRegistry.MissRefreshInterval + TimeSpan.FromSeconds(10);
        while (DateTimeOffset.UtcNow < deadline)
        {
            using var scope = CreateScope();
            if (await scope.ServiceProvider.GetRequiredService<ITenantRegistry>().TryGetRepositoryAsync(tenantId) != null)
            {
                return;
            }

            await Task.Delay(TimeSpan.FromMilliseconds(500), TestContext.Current.CancellationToken);
        }

        throw new InvalidOperationException($"Tenant '{tenantId}' did not appear in the tenant registry");
    }

    private async Task<ITenantRepository> RepositoryAsync(string tenantId) =>
        (await Factory.Services.GetRequiredService<ISystemContext>().TryFindTenantRepositoryAsync(tenantId))!;

    private async Task<List<RtClient>> ChildClientsAsync(string childTenantId, string clientId)
    {
        var repo = await RepositoryAsync(childTenantId);
        using var session = await repo.GetSessionAsync();
        return (await repo.GetRtEntitiesByTypeAsync<RtClient>(session, ByClientId(clientId))).Items.ToList();
    }

    private async Task<RtClient?> FindMirrorAsync(string childTenantId, string clientId) =>
        (await ChildClientsAsync(childTenantId, clientId)).SingleOrDefault();

    private async Task<RtClient> GetMirrorAsync(string childTenantId, string clientId) =>
        (await FindMirrorAsync(childTenantId, clientId))!;

    private async Task<RtClientMirror?> GetTrackingRowAsync(string clientId, string childTenantId)
    {
        var repo = await RepositoryAsync(NormalizedSystemTenantId);
        using var session = await repo.GetSessionAsync();
        return (await repo.GetRtEntitiesByTypeAsync<RtClientMirror>(session, RtEntityQueryOptions.Create()
                .FieldFilter(nameof(RtClientMirror.ParentClientId), FieldFilterOperator.Equals, clientId)
                .FieldFilter(nameof(RtClientMirror.ChildTenantId), FieldFilterOperator.Equals, childTenantId)))
            .Items.SingleOrDefault();
    }

    private async Task<HttpStatusCode> RequestTokenAsync(string tenantId, string clientId, string secret,
        CancellationToken ct)
    {
        using var http = _enabled.CreateClient();
        var response = await http.PostAsync("/connect/token", new FormUrlEncodedContent(
            new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = clientId,
                ["client_secret"] = secret,
                ["scope"] = ApiScope,
                ["acr_values"] = $"tenant:{tenantId}"
            }), ct);
        return response.StatusCode;
    }

    private async Task<CkMethodOutcome<ClientAddSecretResult>> AddAsync(RtClient client, CancellationToken ct,
        WebApplicationFactory<Program>? factory = null)
    {
        using var scope = (factory ?? _enabled).Services.CreateScope();
        var handler = ActivatorUtilities.CreateInstance<ClientAddSecretHandler>(scope.ServiceProvider);
        var context = new CkMethodContext<ClientAddSecretParameters>(
            Request(SystemIdentityCkIds.ClientAddSecretMethodId, client.RtId.ToString()),
            new ClientAddSecretParameters()) { CallerPrincipal = Admin() };
        var outcome = await handler.HandleAsync(context, ct);
        outcome.IsSuccess.Should().BeTrue();
        return outcome;
    }

    private async Task<CkMethodOutcome> RemoveAsync(RtClient client, string secretValue, CancellationToken ct,
        WebApplicationFactory<Program> factory)
    {
        using var scope = factory.Services.CreateScope();
        var handler = ActivatorUtilities.CreateInstance<ClientRemoveSecretHandler>(scope.ServiceProvider);
        var context = new CkMethodContext<ClientRemoveSecretParameters>(
            Request(SystemIdentityCkIds.ClientRemoveSecretMethodId, client.RtId.ToString()),
            new ClientRemoveSecretParameters { SecretValue = secretValue }) { CallerPrincipal = Admin() };
        return await handler.HandleAsync(context, ct);
    }

    private CkMethodRequest Request(string methodId, string target) => new(NormalizedSystemTenantId)
    {
        InvocationId = Guid.NewGuid(),
        MethodId = methodId,
        CkTypeId = "System.Identity/Client",
        TargetRtId = target,
        DeadlineUtc = DateTime.UtcNow.AddSeconds(30),
        ParametersJson = "{}"
    };

    private static string Sha256Base64(string value) =>
        Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    private static ReconciledMetricCapture CaptureReconciledMetric() => new();

    /// <summary>Collects <c>identity.client_mirror.reconciled</c> measurements (process wide, so other tests may add to them).</summary>
    private sealed class ReconciledMetricCapture : IDisposable
    {
        private readonly MeterListener _listener = new();

        public ReconciledMetricCapture()
        {
            _listener.InstrumentPublished = (instrument, listener) =>
            {
                if (instrument.Meter.Name == ClientMirrorReconciliationMetrics.MeterName &&
                    instrument.Name == "identity.client_mirror.reconciled")
                {
                    listener.EnableMeasurementEvents(instrument);
                }
            };
            _listener.SetMeasurementEventCallback<long>((_, value, tags, _) =>
            {
                string? outcome = null;
                foreach (var tag in tags)
                {
                    if (tag.Key == "outcome")
                    {
                        outcome = tag.Value as string;
                    }
                }

                Measurements.Add((outcome, value));
            });
            _listener.Start();
        }

        public ConcurrentBag<(string? Outcome, long Value)> Measurements { get; } = new();

        public void Dispose() => _listener.Dispose();
    }

    /// <summary>The production service with a failing immediate sync (child database unreachable).</summary>
    private sealed class FailingSyncMirrorService(IClientMirrorProvisioningService inner)
        : IClientMirrorProvisioningService
    {
        public Task<ClientMirrorSyncResult> SyncMirrorsForClientAsync(string parentTenantId, RtClient parentClient) =>
            throw new TimeoutException("injected: child tenant database not reachable");

        public Task<ClientMirrorReconciliationResult> ReconcileMirrorsAsync(string parentTenantId,
            CancellationToken cancellationToken = default) =>
            inner.ReconcileMirrorsAsync(parentTenantId, cancellationToken);

        public Task<ClientMirrorProvisioningResult> ProvisionForChildTenantAsync(string parentTenantId,
            string childTenantId) => inner.ProvisionForChildTenantAsync(parentTenantId, childTenantId);

        public Task<ClientMirrorCleanupResult> RemoveMirrorsForClientAsync(string parentTenantId,
            string parentClientId) => inner.RemoveMirrorsForClientAsync(parentTenantId, parentClientId);

        public Task<int> RemoveMirrorsForChildTenantAsync(string parentTenantId, string childTenantId) =>
            inner.RemoveMirrorsForChildTenantAsync(parentTenantId, childTenantId);

        public Task<ClientMirrorBackfillResult?> ProvisionForAllChildTenantsAsync(string parentTenantId,
            string parentClientId) => inner.ProvisionForAllChildTenantsAsync(parentTenantId, parentClientId);

        public Task<IReadOnlyList<RtClientMirror>> GetMirrorsAsync(string parentTenantId, string parentClientId) =>
            inner.GetMirrorsAsync(parentTenantId, parentClientId);

        public Task<ClientMirrorProvisioningResult> ProvisionInTenantAsync(string parentTenantId,
            string parentClientId, string childTenantId) =>
            inner.ProvisionInTenantAsync(parentTenantId, parentClientId, childTenantId);

        public Task<bool> RemoveMirrorAsync(string parentTenantId, string parentClientId, string childTenantId) =>
            inner.RemoveMirrorAsync(parentTenantId, parentClientId, childTenantId);

        public Task<MirrorSecretRotationResult?> RotateMirrorSecretAsync(string parentTenantId,
            string parentClientId, string childTenantId) =>
            inner.RotateMirrorSecretAsync(parentTenantId, parentClientId, childTenantId);
    }

    private sealed class CapturingLoggerProvider : ILoggerProvider
    {
        public ConcurrentQueue<(LogLevel Level, string Text)> Messages { get; } = new();

        public ILogger CreateLogger(string categoryName) => new CapturingLogger(this);

        public void Dispose()
        {
        }

        private sealed class CapturingLogger(CapturingLoggerProvider owner) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
                Func<TState, Exception?, string> formatter)
                => owner.Messages.Enqueue((logLevel, formatter(state, exception) + exception));
        }
    }

    #endregion
}
