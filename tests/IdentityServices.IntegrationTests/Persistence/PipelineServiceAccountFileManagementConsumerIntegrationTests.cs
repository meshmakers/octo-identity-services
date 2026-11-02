using FluentAssertions;
using IdentityServerPersistence;
using IdentityServices.IntegrationTests.Fixtures;
using Meshmakers.Octo.Backend.IdentityServices.Consumers;
using Meshmakers.Octo.Common.DistributionEventHub.Consumers;
using Meshmakers.Octo.Communication.Contracts;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Commands;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Commands.Payloads;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace IdentityServices.IntegrationTests.Persistence;

/// <summary>
///     AB#6467 / AB#6457: every pipeline service account (<c>octo-pipeline-sa-*</c>) holds FileManagement, granted by
///     the identity-data command consumer the moment the Communication Controller creates or touches it and kept by
///     the declarative role sync. Own class (own database) because the other provisioning tests assert exact role
///     sets and must not see the FileManagement role.
/// </summary>
[Collection("Sequential")]
public class PipelineServiceAccountFileManagementConsumerIntegrationTests : IClassFixture<IdentityServicesFixture>
{
    private readonly IdentityServicesFixture _fixture;

    public PipelineServiceAccountFileManagementConsumerIntegrationTests(IdentityServicesFixture fixture,
        ITestOutputHelper outputHelper)
    {
        _fixture = fixture;
        _fixture.OutputHelper = outputHelper;
    }

    [Fact]
    public async Task PipelineServiceAccount_GetsFileManagementOnCreation_AndTheDeclarativeSyncKeepsIt()
    {
        await ArrangeAsync();
        await EnsureRoleAsync(IdentityServiceConstants.FileManagementRole);
        var clientId = NewClientId();

        await ConsumeAsync(BuildServiceAccountRequest(clientId, "plaintext-secret-files-1"));
        var expected = new[] { CommonConstants.CommunicationManagementRole, IdentityServiceConstants.FileManagementRole };
        (await GetAssignedRoleNamesAsync((await LoadClientAsync(clientId))!)).Should().BeEquivalentTo(expected,
            "the controller declares only CommunicationManagement; FileManagement is implicit");

        // A repeated declaration neither duplicates nor removes the implicit role, and a shrunk declaration keeps it.
        await ConsumeAsync(BuildServiceAccountRequest(clientId, "plaintext-secret-files-1"));
        var empty = BuildServiceAccountRequest(clientId, "plaintext-secret-files-1");
        empty.Clients = [empty.Clients!.Single() with { AssignedRoleNames = [] }];
        await ConsumeAsync(empty);
        (await GetAssignedRoleNamesAsync((await LoadClientAsync(clientId))!)).Should()
            .BeEquivalentTo([IdentityServiceConstants.FileManagementRole]);
    }

    [Fact]
    public async Task PipelineServiceAccount_WithANullRoleList_StillGetsFileManagement_WithoutLosingOtherEdges()
    {
        await ArrangeAsync();
        await EnsureRoleAsync(IdentityServiceConstants.FileManagementRole);
        var clientId = NewClientId();
        await ConsumeAsync(BuildServiceAccountRequest(clientId, "plaintext-secret-files-2"));
        await RemoveRoleEdgeAsync((await LoadClientAsync(clientId))!, IdentityServiceConstants.FileManagementRole);
        (await GetAssignedRoleNamesAsync((await LoadClientAsync(clientId))!)).Should()
            .BeEquivalentTo([CommonConstants.CommunicationManagementRole], "precondition: an account without the role");

        // The controller sends null for rotations and legacy accounts: the role edges stay, FileManagement is added.
        var rotation = BuildServiceAccountRequest(clientId, "plaintext-secret-files-2");
        rotation.Clients = [rotation.Clients!.Single() with { AssignedRoleNames = null }];
        await ConsumeAsync(rotation);

        (await GetAssignedRoleNamesAsync((await LoadClientAsync(clientId))!)).Should().BeEquivalentTo(
            [CommonConstants.CommunicationManagementRole, IdentityServiceConstants.FileManagementRole]);
    }

    [Fact]
    public async Task ClientOutsideThePrefix_NeverGetsFileManagementFromTheConsumer()
    {
        await ArrangeAsync();
        await EnsureRoleAsync(IdentityServiceConstants.FileManagementRole);
        var clientId = $"customer-client-{Guid.NewGuid():N}";
        var request = BuildServiceAccountRequest(clientId, "plaintext-secret-files-3");

        await ConsumeAsync(request);

        (await GetAssignedRoleNamesAsync((await LoadClientAsync(clientId))!)).Should()
            .BeEquivalentTo([CommonConstants.CommunicationManagementRole]);
    }

    // ---------- helpers ----------

    private string SystemTenantId => _fixture.GetSystemContext().TenantId;

    private static string NewClientId() => $"octo-pipeline-sa-{Guid.NewGuid():N}";

    private async Task ArrangeAsync()
    {
        await _fixture.InitializeAsync();
        await _fixture.GetService<IDefaultConfigurationCreatorService>().SetupAsync(SystemTenantId);
        await EnsureRoleAsync(CommonConstants.CommunicationManagementRole);
    }

    private async Task EnsureRoleAsync(string roleName)
    {
        var repo = _fixture.GetSystemContext().GetSystemTenantRepositoryAsAdmin();
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        var existing = await repo.GetRtEntitiesByTypeAsync<RtRole>(session,
            RtEntityQueryOptions.Create().FieldFilter(nameof(RtRole.NormalizedName), FieldFilterOperator.Equals,
                roleName.ToUpperInvariant()));
        if (!existing.Items.Any())
        {
            await repo.InsertOneRtEntityAsync(session, new RtRole
            {
                RtId = OctoObjectId.GenerateNewId(), Name = roleName, NormalizedName = roleName.ToUpperInvariant()
            });
        }

        await session.CommitTransactionAsync();
    }

    private CreateIdentityDataCommandRequest BuildServiceAccountRequest(string clientId, string? clientSecret)
    {
        return new CreateIdentityDataCommandRequest(SystemTenantId)
        {
            Clients =
            [
                new DistClientDto(clientId, "Pipeline service account", "https://communication.example.com")
                {
                    AllowedGrantTypes = ["client_credentials", "urn:meshmakers:params:oauth:grant-type:on-behalf-of"],
                    RedirectUris = [],
                    PostLogoutRedirectUris = [],
                    AllowedCorsOrigins = [],
                    AllowedScopes = [CommonConstants.OctoApiFullAccess],
                    AllowOfflineAccess = false,
                    ClientSecret = clientSecret,
                    RequireClientSecret = true,
                    AssignedRoleNames = [CommonConstants.CommunicationManagementRole]
                }
            ]
        };
    }

    private async Task ConsumeAsync(CreateIdentityDataCommandRequest request)
    {
        var consumer = new CreateIdentityDataCommandRequestConsumer(
            NullLogger<CreateIdentityDataCommandRequestConsumer>.Instance, _fixture.GetSystemContext());
        var context = new RecordingContext(request);
        await consumer.ConsumeAsync(context);
        context.Response.Should().NotBeNull();
    }

    private async Task<RtClient?> LoadClientAsync(string clientId)
    {
        var repo = _fixture.GetSystemContext().GetSystemTenantRepositoryAsAdmin();
        using var session = await repo.GetSessionAsync();
        var result = await repo.GetRtEntitiesByTypeAsync<RtClient>(session,
            RtEntityQueryOptions.Create().FieldFilter(nameof(RtClient.ClientId), FieldFilterOperator.Equals, clientId));
        return result.Items.FirstOrDefault();
    }

    private async Task RemoveRoleEdgeAsync(RtClient client, string roleName)
    {
        var repo = _fixture.GetSystemContext().GetSystemTenantRepositoryAsAdmin();
        using var session = await repo.GetSessionAsync();
        session.StartTransaction();
        var role = (await repo.GetRtEntitiesByTypeAsync<RtRole>(session, RtEntityQueryOptions.Create()
            .FieldFilter(nameof(RtRole.NormalizedName), FieldFilterOperator.Equals, roleName.ToUpperInvariant())))
            .Items.Single();
        await repo.ApplyChangesAsync(session,
            new[]
            {
                AssociationUpdateInfo.CreateDelete(new RtEntityId(RtEntityExtensions.GetRtCkTypeId<RtClient>(), client.RtId),
                    new RtEntityId(RtEntityExtensions.GetRtCkTypeId<RtRole>(), role.RtId),
                    IdentityAssociationConstants.AssignedRoleId)
            }, new OperationResult());
        await session.CommitTransactionAsync();
    }

    private async Task<IReadOnlyList<string>> GetAssignedRoleNamesAsync(RtClient client)
    {
        var repo = _fixture.GetSystemContext().GetSystemTenantRepositoryAsAdmin();
        using var session = await repo.GetSessionAsync();
        var associations = await repo.GetRtAssociationsAsync(session,
            new RtEntityId(RtEntityExtensions.GetRtCkTypeId<RtClient>(), client.RtId),
            RtAssociationExtendedQueryOptions.Create(GraphDirections.Outbound,
                roleId: IdentityAssociationConstants.AssignedRoleId));
        var names = new List<string>();
        foreach (var association in associations.Items)
        {
            var role = await repo.GetRtEntityByRtIdAsync<RtRole>(session, association.TargetRtId);
            if (role?.Name != null)
            {
                names.Add(role.Name);
            }
        }

        return names;
    }

    private sealed class RecordingContext(CreateIdentityDataCommandRequest message)
        : IDistributedContext<CreateIdentityDataCommandRequest>
    {
        public CreateIdentityDataCommandRequest Message { get; } = message;

        public object? Response { get; private set; }

        public Task RespondAsync<T>(T responseMessage) where T : class
        {
            Response = responseMessage;
            return Task.CompletedTask;
        }

        public Task PublishAsync<T>(T publishedMessage) where T : class => Task.CompletedTask;
    }
}
