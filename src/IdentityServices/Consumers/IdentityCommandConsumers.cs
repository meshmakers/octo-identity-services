using Meshmakers.Octo.Common.DistributionEventHub.Configuration;
using Meshmakers.Octo.Common.DistributionEventHub.Services;
using Meshmakers.Octo.Communication.Contracts;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Commands;

namespace Meshmakers.Octo.Backend.IdentityServices.Consumers;

/// <summary>
///     The command consumer of the identity service (AB#6910). Every replica consumes it: it is registered on the shared
///     (competing-consumer) topology of the event hub, so each <c>CreateIdentityData</c> command is processed exactly
///     once by one of the running replicas.
/// </summary>
/// <remarks>
///     <para>
///         <see cref="CommandConsumerOptions.MigratesLegacyCommand" /> is required: until AB#6910 the command was served
///         by the classic exclusive consumer, and its senders (asset repository, bot, communication controller, AI, MCP
///         and report service: <c>AddCommandClient</c>) still send to the classic address. With the option the consumer
///         uses the queue <c>{name}::shared</c> and serves the classic address as soon as no old (exclusive) replica is
///         alive, so a rolling update from an old to a new build neither fails to start nor loses or duplicates a
///         command (event hub <c>docs/DEVELOPER.md</c>, "Migrating exclusive command queues").
///     </para>
///     <para>
///         The CK method handlers of this service (<c>IdentityMethodHost</c>) are not affected: they already use the
///         shared per-method queues of octo-common-services. Production code and the two-replica tests
///         (<c>IdentityServices.IntegrationTests/Consumers/IdentityCommandConsumerReplicaTests</c>) use this one
///         registration.
///     </para>
/// </remarks>
internal static class IdentityCommandConsumers
{
    /// <summary>The consumer options of the identity commands: shared, migrating the classic exclusive queue.</summary>
    internal static readonly CommandConsumerOptions SharedOptions = new() { MigratesLegacyCommand = true };

    /// <summary>Registers the command consumers of the identity service on the shared topology.</summary>
    internal static void AddIdentityCommandConsumers(this IDistributionEventHubConfiguration config)
    {
        // Safe under competing consumers: CreateIdentityDataCommandRequestConsumer holds no state between messages and
        // writes in one MongoDB transaction per message (check-then-insert of API scopes, resources and clients keyed
        // by name / client id; an existing client is replaced with the version read in the transaction, AB#8054, so a
        // concurrent writer surfaces as RtVersionConflictException and the message is retried). The classic exclusive
        // endpoint had no concurrency limit, so one replica already processed these commands concurrently; a second
        // replica adds no new race. Senders re-send the same idempotent payload at every start.
        config.AddCommandConsumer<CreateIdentityDataCommandRequestConsumer, CreateIdentityDataCommandRequest>(
            QueueNames.CreateIdentityDataCommand, SharedOptions);
    }
}
