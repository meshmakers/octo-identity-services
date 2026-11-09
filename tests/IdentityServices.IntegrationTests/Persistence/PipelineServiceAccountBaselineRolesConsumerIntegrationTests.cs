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
using Persistence.IdentityCkModel.Generated.System.Identity.v3;
using Xunit;

namespace IdentityServices.IntegrationTests.Persistence;

/// <summary>
///     AB#6467 / AB#6457 / AB#8581: every pipeline service account (<c>octo-pipeline-sa-*</c>) holds the baseline roles
///     FileManagement and StreamDataReader, granted by the identity-data command consumer the moment the Communication
///     Controller creates or touches it and kept by the declarative role sync. Own class (own database) because the other
///     provisioning tests assert exact role sets and must not see the baseline roles.
/// </summary>
[Collection("Sequential")]
public class PipelineServiceAccountBaselineRolesConsumerIntegrationTests : IClassFixture<IdentityServicesFixture>
{
    private const string FileManagement = IdentityServiceConstants.FileManagementRole;
    private const string StreamDataReader = IdentityServiceConstants.StreamDataReaderRole;

    private readonly IdentityServicesFixture _fixture;

    public PipelineServiceAccountBaselineRolesConsumerIntegrationTests(IdentityServicesFixture fixture,
        ITestOutputHelper outputHelper)
    {
        _fixture = fixture;
        _fixture.OutputHelper = outputHelper;
    }

    [Fact]
    public async Task PipelineServiceAccount_GetsTheBaselineRolesOnCreation_AndTheDeclarativeSyncKeepsThem()
    {
        await ArrangeAsync();
        var clientId = NewClientId();

        await ConsumeAsync(BuildServiceAccountRequest(clientId, "plaintext-secret-files-1"));
        (await GetAssignedRoleNamesAsync(clientId)).Should().BeEquivalentTo(
            [CommonConstants.CommunicationManagementRole, FileManagement, StreamDataReader],
            "the declaration names only CommunicationManagement; the baseline roles are implicit");

        // A repeated declaration neither duplicates nor removes the implicit roles, and a shrunk declaration keeps them.
        await ConsumeAsync(BuildServiceAccountRequest(clientId, "plaintext-secret-files-1"));
        var empty = BuildServiceAccountRequest(clientId, "plaintext-secret-files-1");
        empty.Clients = [empty.Clients!.Single() with { AssignedRoleNames = [] }];
        await ConsumeAsync(empty);
        (await GetAssignedRoleNamesAsync(clientId)).Should().BeEquivalentTo([FileManagement, StreamDataReader]);
    }

    [Fact]
    public async Task DeclarativeAccount_DeclaringStreamDataReader_HoldsItOnce_AndKeepsTheDeclaredRoles()
    {
        // AB#8563: the controller now declares StreamDataReader itself; identity also treats it as a baseline role.
        await ArrangeAsync();
        var clientId = NewClientId();
        var request = BuildServiceAccountRequest(clientId, "plaintext-secret-sdr-1",
            [CommonConstants.CommunicationManagementRole, StreamDataReader]);

        await ConsumeAsync(request);
        await ConsumeAsync(request);

        (await GetAssignedRoleNamesAsync(clientId)).Should().BeEquivalentTo(
            [CommonConstants.CommunicationManagementRole, FileManagement, StreamDataReader],
            "every declared role is kept and no role edge is written twice");
    }

    [Fact]
    public async Task LegacyAccount_WithANullRoleList_GetsTheBaselineRoles_WithoutLosingAnyRoleItHad()
    {
        // AB#8581 AC1: a pre-3.32.0 account has no AssignedRoleNames; the controller sends null and cannot add roles.
        await ArrangeAsync();
        await EnsureRoleAsync("LegacyOperatorRole");
        var clientId = NewClientId();
        await ConsumeAsync(BuildServiceAccountRequest(clientId, "plaintext-secret-files-2",
            [CommonConstants.CommunicationManagementRole, "LegacyOperatorRole"]));
        await RemoveRoleEdgeAsync(clientId, FileManagement);
        await RemoveRoleEdgeAsync(clientId, StreamDataReader);
        (await GetAssignedRoleNamesAsync(clientId)).Should().BeEquivalentTo(
            [CommonConstants.CommunicationManagementRole, "LegacyOperatorRole"],
            "precondition: a legacy account with its own roles and without the baseline roles");

        var legacy = BuildServiceAccountRequest(clientId, "plaintext-secret-files-2", assignedRoleNames: null);
        await ConsumeAsync(legacy);

        (await GetAssignedRoleNamesAsync(clientId)).Should().BeEquivalentTo(
            [CommonConstants.CommunicationManagementRole, "LegacyOperatorRole", FileManagement, StreamDataReader]);
    }

    [Fact]
    public async Task ClientOutsideThePrefix_NeverGetsTheBaselineRolesFromTheConsumer()
    {
        await ArrangeAsync();
        var clientId = $"customer-client-{Guid.NewGuid():N}";

        await ConsumeAsync(BuildServiceAccountRequest(clientId, "plaintext-secret-files-3"));

        (await GetAssignedRoleNamesAsync(clientId)).Should().BeEquivalentTo([CommonConstants.CommunicationManagementRole]);
    }

    // ---------- helpers ----------

    private string SystemTenantId => _fixture.GetSystemContext().TenantId;

    private static string NewClientId() => $"octo-pipeline-sa-{Guid.NewGuid():N}";

    private async Task ArrangeAsync()
    {
        await _fixture.InitializeAsync();
        await _fixture.GetService<IDefaultConfigurationCreatorService>().SetupAsync(SystemTenantId);
        await EnsureRoleAsync(CommonConstants.CommunicationManagementRole);
        await EnsureRoleAsync(FileManagement);
        await EnsureRoleAsync(StreamDataReader);
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

    private CreateIdentityDataCommandRequest BuildServiceAccountRequest(string clientId, string? clientSecret) =>
        BuildServiceAccountRequest(clientId, clientSecret, [CommonConstants.CommunicationManagementRole]);

    private CreateIdentityDataCommandRequest BuildServiceAccountRequest(string clientId, string? clientSecret,
        string[]? assignedRoleNames)
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
                    AssignedRoleNames = assignedRoleNames
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

    private async Task RemoveRoleEdgeAsync(string clientId, string roleName)
    {
        var client = (await LoadClientAsync(clientId))!;
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

    /// <summary>The role names of every outbound AssignedRole edge, duplicates included.</summary>
    private async Task<IReadOnlyList<string>> GetAssignedRoleNamesAsync(string clientId)
    {
        var client = (await LoadClientAsync(clientId))!;
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
