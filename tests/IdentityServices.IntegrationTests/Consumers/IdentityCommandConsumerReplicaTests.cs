using System.Collections.Concurrent;
using FluentAssertions;
using IdentityServices.IntegrationTests.Fixtures;
using MassTransit;
using Meshmakers.Octo.Backend.IdentityServices.Consumers;
using Meshmakers.Octo.Common.DistributionEventHub;
using Meshmakers.Octo.Common.DistributionEventHub.Configuration;
using Meshmakers.Octo.Common.DistributionEventHub.Configuration.Options;
using Meshmakers.Octo.Common.DistributionEventHub.Services;
using Meshmakers.Octo.Communication.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Commands;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Commands.Payloads;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Testcontainers.RabbitMq;
using Xunit;

namespace IdentityServices.IntegrationTests.Consumers;

/// <summary>
///     AB#6910 — two replicas of the identity service consume <c>CreateIdentityData</c> as competing consumers: every
///     command is processed exactly once, both replicas take a share, the caller gets its answer and the client exists
///     once in the tenant; a rolling update from the old exclusive build loses nothing; and the service no longer logs
///     the AB#6909 deprecation warning at start.
/// </summary>
/// <remarks>
///     The replicas use the production registration (<see cref="IdentityCommandConsumers.AddIdentityCommandConsumers" />)
///     with the real consumer against the fixture's MongoDB and a private RabbitMQ (Testcontainers, needs Docker). The
///     sender uses the classic <c>AddCommandClient</c>, exactly as the asset repository, bot, communication controller,
///     AI, MCP and report service do. A consume observer per replica records which replica processed which command.
/// </remarks>
[Collection("Sequential")]
public class IdentityCommandConsumerReplicaTests : IClassFixture<IdentityServicesFixture>, IAsyncLifetime
{
    private const int Commands = 16;
    private const string DeprecationMarker = "classic EXCLUSIVE";

    private readonly IdentityServicesFixture _fixture;
    private readonly string _instancePrefix = $"id6910-{Guid.NewGuid():N}";
    private readonly List<Replica> _replicas = [];
    private readonly ConcurrentQueue<(string ClientId, string Replica)> _ledger = new();
    private readonly CapturingLoggerProvider _logs = new();

    public IdentityCommandConsumerReplicaTests(IdentityServicesFixture fixture, ITestOutputHelper outputHelper)
    {
        _fixture = fixture;
        _fixture.OutputHelper = outputHelper;
    }

    public async ValueTask InitializeAsync()
    {
        await _fixture.InitializeAsync();
        await _fixture.GetService<IDefaultConfigurationCreatorService>().SetupAsync(SystemTenantId);
    }

    public async ValueTask DisposeAsync()
    {
        foreach (var replica in _replicas.ToList())
        {
            await StopReplicaAsync(replica);
        }
    }

    private string SystemTenantId => _fixture.GetSystemContext().TenantId;

    [Fact]
    public async Task TwoReplicas_EveryCommandIsProcessedOnce_BothReplicasConsume_ClientExistsOnce()
    {
        await StartNewReplicaAsync("Identity-1");
        await StartNewReplicaAsync("Identity-2");
        var sender = await StartSenderAsync();
        await WaitUntilServedAsync(sender);
        _ledger.Clear();

        var clientIds = Enumerable.Range(0, Commands).Select(i => $"replica-6910-{i:D3}-{Guid.NewGuid():N}").ToList();
        var responses = await Task.WhenAll(clientIds.Select(id => SendAsync(sender, id)));

        responses.Should().OnlyContain(r => r.Response == CreateIdentityDataResult.Success ||
                                            r.Response == CreateIdentityDataResult.SuccessIdentityDataSeedPending);
        _ledger.Select(e => e.ClientId).Should().BeEquivalentTo(clientIds, "every command is processed exactly once");
        _ledger.Select(e => e.Replica).Distinct().Should().BeEquivalentTo(["Identity-1", "Identity-2"],
            "both replicas consume the shared queue");
        foreach (var clientId in clientIds)
        {
            (await CountClientsAsync(clientId)).Should().Be(1, $"client '{clientId}' is created once");
        }
    }

    [Fact]
    public async Task Start_LogsNoDeprecationWarning()
    {
        await StartNewReplicaAsync("Identity-1");
        var sender = await StartSenderAsync();
        await WaitUntilServedAsync(sender);

        _logs.Lines.Should().NotContain(l => l.Contains(DeprecationMarker));
        IdentityCommandConsumers.SharedOptions.MigratesLegacyCommand.Should().BeTrue();
    }

    [Fact]
    public async Task RollingUpdate_OldExclusiveAndNewSharedReplica_StartWithoutError_NoCommandLostOrDuplicated()
    {
        // The old build: the same consumer with the classic exclusive registration (before AB#6910).
        var old = await StartReplicaAsync("Old-1", c =>
            c.AddCommandConsumer<CreateIdentityDataCommandRequestConsumer, CreateIdentityDataCommandRequest>(
                QueueNames.CreateIdentityDataCommand));
        var sender = await StartSenderAsync();
        _logs.Lines.Should().Contain(l => l.Contains(DeprecationMarker),
            "positive control: the old build logs the deprecation warning, so its absence elsewhere counts");

        // The new build joins while the old one owns the classic queue: no PRECONDITION_FAILED / RESOURCE_LOCKED.
        await StartNewReplicaAsync("Identity-1");
        await Task.Delay(TimeSpan.FromSeconds(5), TestContext.Current.CancellationToken);

        _ledger.Clear();
        var phaseA = Enumerable.Range(0, 6).Select(i => $"rolling-old-{i}-{Guid.NewGuid():N}").ToList();
        await Task.WhenAll(phaseA.Select(id => SendAsync(sender, id)));
        _ledger.Select(e => e.ClientId).Should().BeEquivalentTo(phaseA);
        _ledger.Should().OnlyContain(e => e.Replica == "Old-1",
            "while an old replica runs, it keeps the classic traffic and the new one stands by");

        // The old replica goes away: the new ones take over the classic address.
        await StopReplicaAsync(old);
        await StartNewReplicaAsync("Identity-2");
        await WaitUntilServedAsync(sender);
        _ledger.Clear();

        var phaseB = Enumerable.Range(0, 6).Select(i => $"rolling-new-{i}-{Guid.NewGuid():N}").ToList();
        await Task.WhenAll(phaseB.Select(id => SendAsync(sender, id)));
        _ledger.Select(e => e.ClientId).Should().BeEquivalentTo(phaseB, "nothing lost, nothing processed twice");
        _ledger.Should().OnlyContain(e => e.Replica == "Identity-1" || e.Replica == "Identity-2");
        foreach (var clientId in phaseA.Concat(phaseB))
        {
            (await CountClientsAsync(clientId)).Should().Be(1);
        }
    }

    // -------------------------------------------------------------------------------------------------------------
    // commands

    private async Task<EnumCommandResponse<CreateIdentityDataResult>> SendAsync(Replica sender, string clientId,
        TimeSpan? timeout = null)
    {
        using var scope = sender.Provider.CreateScope();
        return await scope.ServiceProvider.GetRequiredService<ICommandClient<CreateIdentityDataCommandRequest>>()
            .GetResponse<EnumCommandResponse<CreateIdentityDataResult>>(BuildRequest(clientId),
                TestContext.Current.CancellationToken, timeout ?? TimeSpan.FromSeconds(60));
    }

    private CreateIdentityDataCommandRequest BuildRequest(string clientId) => new(SystemTenantId)
    {
        Clients =
        [
            new DistClientDto(clientId, "AB#6910 replica test client", "https://replica.example.com")
            {
                AllowedGrantTypes = ["client_credentials"],
                RedirectUris = [],
                PostLogoutRedirectUris = [],
                AllowedCorsOrigins = [],
                AllowedScopes = [CommonConstants.OctoApiFullAccess],
                AllowOfflineAccess = false
            }
        ]
    };

    private async Task<int> CountClientsAsync(string clientId)
    {
        var repo = _fixture.GetSystemContext().GetSystemTenantRepositoryAsAdmin();
        using var session = await repo.GetSessionAsync();
        var result = await repo.GetRtEntitiesByTypeAsync<RtClient>(session,
            RtEntityQueryOptions.Create().FieldFilter(nameof(RtClient.ClientId), FieldFilterOperator.Equals, clientId));
        return result.Items.Count();
    }

    /// <summary>
    ///     Probes until a replica answers on the classic address (the bridge serves it once no exclusive consumer is
    ///     alive, after at most one probe interval). Probes create a probe client; they are not in the ledger.
    /// </summary>
    private async Task WaitUntilServedAsync(Replica sender)
    {
        var deadline = DateTime.UtcNow.AddSeconds(60);
        while (DateTime.UtcNow < deadline)
        {
            try
            {
                await SendAsync(sender, "probe-6910", TimeSpan.FromSeconds(2));
                return;
            }
            catch (DistributionException)
            {
                // hand-over window: nothing serves the classic address yet
            }

            await Task.Delay(200, TestContext.Current.CancellationToken);
        }

        throw new TimeoutException("No replica served the classic command address within 60 s.");
    }

    // -------------------------------------------------------------------------------------------------------------
    // replicas

    private sealed record Replica(string Name, ServiceProvider Provider);

    private Task<Replica> StartNewReplicaAsync(string name) =>
        StartReplicaAsync(name, c => c.AddIdentityCommandConsumers());

    private Task<Replica> StartSenderAsync() => StartReplicaAsync("Sender",
        c => c.AddCommandClient<CreateIdentityDataCommandRequest>(QueueNames.CreateIdentityDataCommand));

    private async Task<Replica> StartReplicaAsync(string name, Action<IDistributionEventHubConfiguration> register)
    {
        var broker = await RabbitMqBroker.GetAsync();
        var services = new ServiceCollection();
        services.AddLogging(b => b.AddProvider(_logs).SetMinimumLevel(LogLevel.Information));
        services.AddSingleton(_fixture.GetSystemContext());
        services.AddConsumeObserver(_ => new LedgerObserver(name, _ledger));
        services.Configure<DistributionEventHubOptions>(o =>
        {
            o.InstancePrefix = _instancePrefix;
            o.BrokerHost = broker.Host;
            o.BrokerPort = (ushort)broker.Port;
            o.BrokerUser = RabbitMqBroker.User;
            o.BrokerPassword = RabbitMqBroker.Password;
        });
        services.AddDistributionEventHub(config =>
        {
            config.UniqueServiceAddress = name;
            config.AutomaticallyStartBusDuringStartup = false;
            register(config);
        });

        var provider = services.BuildServiceProvider();
        var replica = new Replica(name, provider);
        _replicas.Add(replica);
        await provider.GetRequiredService<IEventHubControl>().StartAsync(TestContext.Current.CancellationToken);
        return replica;
    }

    private async Task StopReplicaAsync(Replica replica)
    {
        if (!_replicas.Remove(replica))
        {
            return;
        }

        try
        {
            await replica.Provider.GetRequiredService<IEventHubControl>().StopAsync();
        }
        catch
        {
            // best effort
        }

        await replica.Provider.DisposeAsync();
    }

    /// <summary>Records every successfully processed CreateIdentityData command with the replica that processed it.</summary>
    private sealed class LedgerObserver(string replica, ConcurrentQueue<(string ClientId, string Replica)> ledger)
        : IConsumeObserver
    {
        public Task PreConsume<T>(ConsumeContext<T> context) where T : class => Task.CompletedTask;

        public Task PostConsume<T>(ConsumeContext<T> context) where T : class
        {
            if (context.Message is CreateIdentityDataCommandRequest request &&
                request.Clients?.FirstOrDefault()?.ClientId is { } clientId && clientId != "probe-6910")
            {
                ledger.Enqueue((clientId, replica));
            }

            return Task.CompletedTask;
        }

        public Task ConsumeFault<T>(ConsumeContext<T> context, Exception exception) where T : class =>
            Task.CompletedTask;
    }

    // -------------------------------------------------------------------------------------------------------------
    // infrastructure

    /// <summary>One RabbitMQ container for the test run (started on first use, removed by Testcontainers' reaper).</summary>
    private sealed class RabbitMqBroker
    {
        public const string User = "guest";
        public const string Password = "guest";
        private static readonly SemaphoreSlim Gate = new(1, 1);
        private static RabbitMqBroker? _shared;
        private readonly RabbitMqContainer _container;

        private RabbitMqBroker(RabbitMqContainer container) => _container = container;

        public string Host => _container.Hostname;
        public int Port => _container.GetMappedPublicPort(5672);

        public static async Task<RabbitMqBroker> GetAsync()
        {
            if (_shared != null)
            {
                return _shared;
            }

            await Gate.WaitAsync();
            try
            {
                if (_shared == null)
                {
                    var container = new RabbitMqBuilder("rabbitmq:3-management")
                        .WithUsername(User)
                        .WithPassword(Password)
                        .Build();
                    await container.StartAsync();
                    _shared = new RabbitMqBroker(container);
                }

                return _shared;
            }
            finally
            {
                Gate.Release();
            }
        }
    }

    private sealed class CapturingLoggerProvider : ILoggerProvider
    {
        private readonly ConcurrentQueue<string> _lines = new();

        public IReadOnlyCollection<string> Lines => _lines.ToArray();

        public ILogger CreateLogger(string categoryName) => new Logger(_lines);

        public void Dispose()
        {
        }

        private sealed class Logger(ConcurrentQueue<string> lines) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Information;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
                lines.Enqueue($"{logLevel}: {formatter(state, exception)}");
            }
        }
    }
}
