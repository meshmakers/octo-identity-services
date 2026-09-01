using FluentAssertions;
using IdentityServerPersistence.Services;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using NSubstitute;
using NSubstitute.Core;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Shared.TestUtilities.Builders;
using Shared.TestUtilities.Fakes;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Services;

/// <summary>
///     AB#5061 — per-tenant mirror secrets.
/// </summary>
/// <remarks>
///     <para>
///         Mirroring copies a confidential client's secret verbatim into every child tenant, so one
///         credential pair is valid instance-wide and possession of a child tenant's credentials
///         also yields the parent's. Each mirror now additionally carries its <b>own</b> generated
///         secret, which proves exactly one tenant.
///     </para>
///     <para>
///         ⚠️ The inherited parent secret is deliberately still accepted — live fleet credentials
///         (<c>ci-deploy</c>, <c>octo-ai-adapter</c>, <c>claude-agent</c>) authenticate with it
///         against child tenants today. <see cref="InheritedParentSecret_IsStillCopied_SoTheGapIsDocumentedNotClosed" />
///         pins that residual so nobody mistakes this step for the fix being complete.
///     </para>
/// </remarks>
public class ClientMirrorOwnSecretTests
{
    private const string ParentTenantId = "octosystem";
    private const string ChildTenantId = "acme";
    private const string ParentSecretHash = "parent-secret-hash";

    private readonly ISystemContext _systemContext = Substitute.For<ISystemContext>();
    private readonly ITenantRepository _parentRepo = Substitute.For<ITenantRepository>();
    private readonly ITenantRepository _childRepo = Substitute.For<ITenantRepository>();
    private readonly IOctoSession _parentSession = Substitute.For<IOctoSession>();
    private readonly IOctoSession _childSession = Substitute.For<IOctoSession>();
    private readonly CapturingLogger<ClientMirrorProvisioningService> _logger = new();
    private readonly ClientMirrorProvisioningService _sut;

    public ClientMirrorOwnSecretTests()
    {
        _parentRepo.GetSessionAsync().Returns(_parentSession);
        _childRepo.GetSessionAsync().Returns(_childSession);
        _systemContext.TryFindTenantRepositoryAsync(ParentTenantId).Returns(_parentRepo);
        _systemContext.TryFindTenantRepositoryAsync(ChildTenantId).Returns(_childRepo);

        _sut = new ClientMirrorProvisioningService(_logger, _systemContext);
    }

    /// <summary>
    ///     The headline guarantee: a freshly materialized mirror of a confidential client carries a
    ///     secret of its own, and it is <b>not</b> the parent's.
    /// </summary>
    [Fact]
    public async Task NewMirrorOfConfidentialClient_GetsItsOwnSecret_DifferentFromTheParents()
    {
        var parent = ConfidentialFlaggedClient();
        ArrangeProvisioning(parent, existingChildClients: []);

        await _sut.ProvisionForChildTenantAsync(ParentTenantId, ChildTenantId);

        var inserted = CapturedInsertedChildClient();
        var ownSecret = ClientMirrorSecrets.FindOwnSecret(inserted);

        ownSecret.Should().NotBeNull("a mirror of a confidential client must carry a tenant-specific credential");
        ownSecret!.Value.Should().NotBe(ParentSecretHash,
            "an own secret that equals the parent's would prove nothing about the tenant");
        ownSecret.Type.Should().Be(ClientMirrorSecrets.SharedSecretType);
    }

    /// <summary>
    ///     A public client has no secret to scope per tenant. Minting one would silently turn it
    ///     confidential in the child tenant only — and every mirrored client shipped in the
    ///     <c>System.Identity.Bootstrap</c> seed is public.
    /// </summary>
    [Fact]
    public async Task NewMirrorOfPublicClient_GetsNoSecretAtAll()
    {
        var parent = new RtClientBuilder()
            .WithClientId("octo-cli")
            .WithAutoProvisionInChildTenants()
            .Build();
        ArrangeProvisioning(parent, existingChildClients: []);

        await _sut.ProvisionForChildTenantAsync(ParentTenantId, ChildTenantId);

        var inserted = CapturedInsertedChildClient();
        inserted.ClientSecrets.Should().BeEmpty();
        inserted.RequireClientSecret.Should().BeFalse();
    }

    /// <summary>
    ///     🔴 The load-bearing half. Provisioning re-runs on every service start and rebuilds the
    ///     mirror from the <i>parent's</i> state; without carrying the own secret across, every
    ///     restart would silently invalidate every per-tenant credential handed out so far.
    /// </summary>
    [Fact]
    public async Task Reprovisioning_PreservesAnAlreadyIssuedOwnSecret()
    {
        var parent = ConfidentialFlaggedClient();
        var alreadyMirrored = ChildMirrorWithOwnSecret("issued-own-hash");
        ArrangeProvisioning(parent, existingChildClients: [alreadyMirrored]);

        await _sut.ProvisionForChildTenantAsync(ParentTenantId, ChildTenantId);

        var replaced = CapturedReplacedChildClient();
        ClientMirrorSecrets.FindOwnSecret(replaced)!.Value.Should().Be("issued-own-hash");
    }

    /// <summary>
    ///     Same preservation, on the other path that rewrites a mirror wholesale: a secret rotation
    ///     on the parent fanning out to every mirror.
    /// </summary>
    [Fact]
    public async Task ParentSecretRotation_PropagatesTheNewParentSecret_ButKeepsTheOwnSecret()
    {
        var parent = ConfidentialFlaggedClient(secretHash: "rotated-parent-hash");
        ArrangeSync(parent, existingChildClients: [ChildMirrorWithOwnSecret("issued-own-hash")]);

        var result = await _sut.SyncMirrorsForClientAsync(ParentTenantId, parent);

        result.MirrorsSynced.Should().Be(1);
        var replaced = CapturedReplacedChildClient();
        replaced.ClientSecrets.Select(s => s.Value).Should().Contain("rotated-parent-hash");
        ClientMirrorSecrets.FindOwnSecret(replaced)!.Value.Should().Be("issued-own-hash");
    }

    /// <summary>
    ///     ⚠️ Pins the <b>residual risk</b>, deliberately as an assertion rather than a comment: the
    ///     mirror still accepts the parent's secret, so the instance-wide credential is live and
    ///     <c>tenant_id == systemTenant</c> on a client-credentials token remains unusable as proof
    ///     of provenance (AB#5055). When the migration step removes the inherited copy, this test is
    ///     the one that must be inverted — and its failure is the signal that the gap actually closed.
    /// </summary>
    [Fact]
    public async Task InheritedParentSecret_IsStillCopied_SoTheGapIsDocumentedNotClosed()
    {
        var parent = ConfidentialFlaggedClient();
        ArrangeProvisioning(parent, existingChildClients: []);

        await _sut.ProvisionForChildTenantAsync(ParentTenantId, ChildTenantId);

        var inserted = CapturedInsertedChildClient();
        inserted.ClientSecrets.Select(s => s.Value).Should().Contain(ParentSecretHash,
            "callers such as ci-deploy still authenticate with the parent secret against child tenants");
    }

    /// <summary>
    ///     The parent client instance is handed to every child in the sync loop. Copying its secret
    ///     list by reference would make each child's own-secret append land on the parent's list, so
    ///     child N would be written with the secrets of children 1..N-1 — a silent, cumulative
    ///     credential leak between sibling tenants.
    /// </summary>
    [Fact]
    public async Task SyncAcrossTwoChildren_DoesNotLeakOneChildsOwnSecretIntoTheOther()
    {
        const string secondChild = "globex";
        var secondRepo = Substitute.For<ITenantRepository>();
        var secondSession = Substitute.For<IOctoSession>();
        secondRepo.GetSessionAsync().Returns(secondSession);
        _systemContext.TryFindTenantRepositoryAsync(secondChild).Returns(secondRepo);
        SetupChildClientLookup(secondRepo, secondSession, []);

        var parent = ConfidentialFlaggedClient();
        SetupParentMirrorLookup([
            Mirror(ChildTenantId),
            Mirror(secondChild)
        ]);
        SetupChildClientLookup(_childRepo, _childSession, []);

        await _sut.SyncMirrorsForClientAsync(ParentTenantId, parent);

        var first = CapturedChildClient(_childRepo, "InsertOneRtEntityAsync");
        var second = CapturedChildClient(secondRepo, "InsertOneRtEntityAsync");

        var firstOwn = ClientMirrorSecrets.FindOwnSecret(first)!.Value;
        var secondOwn = ClientMirrorSecrets.FindOwnSecret(second)!.Value;

        firstOwn.Should().NotBe(secondOwn, "each tenant must get a distinct credential");
        second.ClientSecrets.Select(s => s.Value).Should().NotContain(firstOwn,
            "one child tenant must never receive another child tenant's secret");
        parent.ClientSecrets.Should().HaveCount(1,
            "the parent's own secret list must not be mutated by mirroring");
    }

    /// <summary>
    ///     Secret material must never reach a log sink. Asserted against the rendered message —
    ///     i.e. what a real sink receives after structured placeholders are interpolated — rather
    ///     than by reading the format strings.
    /// </summary>
    [Fact]
    public async Task Provisioning_NeverWritesSecretMaterialToTheLog()
    {
        var parent = ConfidentialFlaggedClient();
        ArrangeProvisioning(parent, existingChildClients: []);

        await _sut.ProvisionForChildTenantAsync(ParentTenantId, ChildTenantId);

        var inserted = CapturedInsertedChildClient();
        var log = _logger.AllText;

        log.Should().NotBeEmpty("the provisioning of a per-tenant credential is worth an audit line");
        foreach (var secret in inserted.ClientSecrets)
        {
            log.Should().NotContain(secret.Value,
                "neither the generated own secret nor the inherited parent hash may be logged");
        }
    }

    // ----- arrangement ------------------------------------------------------

    private static RtClient ConfidentialFlaggedClient(string secretHash = ParentSecretHash) =>
        new RtClientBuilder()
            .WithClientId("ci-deploy")
            .WithGrantTypes("client_credentials")
            .RequireClientSecret()
            .WithSecret(ClientMirrorSecrets.SharedSecretType, secretHash)
            .WithAutoProvisionInChildTenants()
            .Build();

    private static RtClient ChildMirrorWithOwnSecret(string ownSecretHash) =>
        new RtClientBuilder()
            .WithClientId("ci-deploy")
            .RequireClientSecret()
            .WithSecret(ClientMirrorSecrets.SharedSecretType, ParentSecretHash)
            .WithSecret(ClientMirrorSecrets.SharedSecretType, ownSecretHash,
                ClientMirrorSecrets.OwnSecretDescription)
            .Build();

    private static RtClientMirror Mirror(string childTenantId) =>
        new RtClientMirrorBuilder()
            .WithParentClientId("ci-deploy")
            .WithParentTenantId(ParentTenantId)
            .WithChildTenantId(childTenantId)
            .Build();

    private void ArrangeProvisioning(RtClient parent, RtClient[] existingChildClients)
    {
        SetupParentFlaggedClients(parent);
        SetupParentMirrorLookup([]);
        SetupChildClientLookup(_childRepo, _childSession, existingChildClients);
    }

    private void ArrangeSync(RtClient parent, RtClient[] existingChildClients)
    {
        SetupParentMirrorLookup([Mirror(ChildTenantId)]);
        SetupChildClientLookup(_childRepo, _childSession, existingChildClients);
        _ = parent;
    }

    private void SetupParentFlaggedClients(params RtClient[] clients)
    {
        var queryResult = Substitute.For<IResultSet<RtClient>>();
        queryResult.Items.Returns(clients);
        _parentRepo.GetRtEntitiesByTypeAsync<RtClient>(_parentSession, Arg.Any<RtEntityQueryOptions>())
            .Returns(queryResult);
    }

    private void SetupParentMirrorLookup(RtClientMirror[] mirrors)
    {
        var queryResult = Substitute.For<IResultSet<RtClientMirror>>();
        queryResult.Items.Returns(mirrors);
        _parentRepo.GetRtEntitiesByTypeAsync<RtClientMirror>(_parentSession, Arg.Any<RtEntityQueryOptions>())
            .Returns(queryResult);
    }

    private static void SetupChildClientLookup(
        ITenantRepository repo, IOctoSession session, RtClient[] existingClients)
    {
        var queryResult = Substitute.For<IResultSet<RtClient>>();
        queryResult.Items.Returns(existingClients);
        repo.GetRtEntitiesByTypeAsync<RtClient>(session, Arg.Any<RtEntityQueryOptions>())
            .Returns(queryResult);
    }

    // ----- capture ----------------------------------------------------------

    private RtClient CapturedInsertedChildClient() => CapturedChildClient(_childRepo, "InsertOneRtEntityAsync");

    private RtClient CapturedReplacedChildClient() =>
        CapturedChildClient(_childRepo, "ReplaceOneRtEntityByIdAsync");

    /// <summary>
    ///     Reads the <see cref="RtClient" /> the service actually wrote. Uses
    ///     <c>ReceivedCalls()</c> rather than <c>Arg.Do</c>, which only captures when it is
    ///     configured <i>before</i> the call and silently records nothing inside a
    ///     <c>Received()</c> assertion.
    /// </summary>
    private static RtClient CapturedChildClient(ITenantRepository repo, string methodName)
    {
        var written = repo.ReceivedCalls()
            .Where(c => c.GetMethodInfo().Name == methodName)
            .SelectMany(c => c.GetArguments().OfType<RtClient>())
            .ToList();

        written.Should().NotBeEmpty($"the service was expected to {methodName} a client");
        return written[^1];
    }
}
