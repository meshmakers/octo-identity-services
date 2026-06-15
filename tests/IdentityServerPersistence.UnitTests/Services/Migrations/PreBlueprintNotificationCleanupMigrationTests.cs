using FluentAssertions;
using IdentityServerPersistence;
using IdentityServerPersistence.Services.Migrations;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Runtime.Contracts.RepositoryEntities;
using Meshmakers.Octo.Runtime.Engine.Repositories.Query;
using Meshmakers.Octo.Services.Notifications.Generated.System.Notification.v2;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using Shared.TestUtilities.Fakes;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Services.Migrations;

/// <summary>
///     Coverage for the whitelist gate added to
///     <see cref="PreBlueprintNotificationCleanupMigration"/>. The earlier version of this
///     migration deleted every <see cref="RtMailNotificationConfiguration"/> /
///     <see cref="RtNotificationTemplate"/> outside the 680… range unconditionally. Same shape
///     as the over-deletion bug that hit <see cref="PreBlueprintCleanupMigration"/> on test-2
///     2026-06-15; the only reason it never crashed in production is that no cluster had yet
///     received operator-created Notification entities. The gate here forecloses that path.
/// </summary>
public class PreBlueprintNotificationCleanupMigrationTests
{
    private readonly PreBlueprintNotificationCleanupMigration _sut = new(
        NullLogger<PreBlueprintNotificationCleanupMigration>.Instance);

    private readonly ITenantContext _tenantContext = Substitute.For<ITenantContext>();
    private readonly ITenantRepository _tenantRepository = Substitute.For<ITenantRepository>();
    private readonly IOctoAdminSession _adminSession = Substitute.For<IOctoAdminSession>();
    private readonly FakeOctoSession _session = new();

    private static readonly OctoObjectId BlueprintConfigRtId =
        new("680000000000000000000001");
    private static readonly OctoObjectId BlueprintWelcomeTemplateRtId =
        new("680000000000000000000010");

    public PreBlueprintNotificationCleanupMigrationTests()
    {
        _tenantContext.TenantId.Returns("test-tenant");
        _tenantContext.GetTenantRepositoryAsAdmin().Returns(_tenantRepository);
        _tenantRepository.GetSessionAsync().Returns(Task.FromResult<IOctoSession>(_session));

        SetupEmpty<RtMailNotificationConfiguration>();
        SetupEmpty<RtNotificationTemplate>();
    }

    [Fact]
    public async Task MigrateAsync_PreBlueprintConfigWithWellKnownName_IsDeleted()
    {
        var preBlueprintConfig = new RtMailNotificationConfiguration
        {
            RtId = new OctoObjectId("670000000000000000000001"),
            RtWellKnownName = IdentityServiceConstants.MailNotificationConfigurationName,
        };

        SetupConfigs(preBlueprintConfig);

        await _sut.MigrateAsync(_adminSession, _tenantContext);

        await _tenantRepository.Received(1)
            .DeleteOneRtEntityByRtIdAsync<RtMailNotificationConfiguration>(
                _session, preBlueprintConfig.RtId, DeleteOptions.Erase);
    }

    [Fact]
    public async Task MigrateAsync_OperatorConfigWithUnknownWellKnownName_IsPreserved()
    {
        // Whatever an operator might attach as a custom mail-notification config (e.g. a
        // per-customer override entity) must not be wiped by the cleanup step.
        var operatorConfig = new RtMailNotificationConfiguration
        {
            RtId = new OctoObjectId("670000000000000000000002"),
            RtWellKnownName = "FdaCustomMailConfig",
        };

        SetupConfigs(operatorConfig);

        await _sut.MigrateAsync(_adminSession, _tenantContext);

        await _tenantRepository.DidNotReceive()
            .DeleteOneRtEntityByRtIdAsync<RtMailNotificationConfiguration>(
                _session, operatorConfig.RtId, Arg.Any<DeleteOptions>());
    }

    [Fact]
    public async Task MigrateAsync_OperatorConfigWithoutWellKnownName_IsPreserved()
    {
        // Mirrors the test-2 incident shape: legacy entity that never had rtWellKnownName set.
        // Without the gate, the OLD migration would have deleted it.
        var legacyConfig = new RtMailNotificationConfiguration
        {
            RtId = new OctoObjectId("670000000000000000000003"),
            // RtWellKnownName intentionally not set
        };

        SetupConfigs(legacyConfig);

        await _sut.MigrateAsync(_adminSession, _tenantContext);

        await _tenantRepository.DidNotReceive()
            .DeleteOneRtEntityByRtIdAsync<RtMailNotificationConfiguration>(
                _session, legacyConfig.RtId, Arg.Any<DeleteOptions>());
    }

    [Fact]
    public async Task MigrateAsync_BlueprintConfig_IsPreserved()
    {
        var blueprintConfig = new RtMailNotificationConfiguration
        {
            RtId = BlueprintConfigRtId,
            RtWellKnownName = IdentityServiceConstants.MailNotificationConfigurationName,
        };

        SetupConfigs(blueprintConfig);

        await _sut.MigrateAsync(_adminSession, _tenantContext);

        await _tenantRepository.DidNotReceive()
            .DeleteOneRtEntityByRtIdAsync<RtMailNotificationConfiguration>(
                _session, blueprintConfig.RtId, Arg.Any<DeleteOptions>());
    }

    [Fact]
    public async Task MigrateAsync_PreBlueprintTemplateWithWellKnownName_IsDeleted()
    {
        var preBlueprintWelcomeTemplate = new RtNotificationTemplate
        {
            RtId = new OctoObjectId("670000000000000000000010"),
            RtWellKnownName = IdentityServiceConstants.WelcomeEmailTemplateName,
        };

        SetupTemplates(preBlueprintWelcomeTemplate);

        await _sut.MigrateAsync(_adminSession, _tenantContext);

        await _tenantRepository.Received(1)
            .DeleteOneRtEntityByRtIdAsync<RtNotificationTemplate>(
                _session, preBlueprintWelcomeTemplate.RtId, DeleteOptions.Erase);
    }

    [Fact]
    public async Task MigrateAsync_OperatorCustomTemplate_IsPreserved()
    {
        var customTemplate = new RtNotificationTemplate
        {
            RtId = new OctoObjectId("670000000000000000000011"),
            RtWellKnownName = "Customer_Onboarding_Email_Template",
        };

        SetupTemplates(customTemplate);

        await _sut.MigrateAsync(_adminSession, _tenantContext);

        await _tenantRepository.DidNotReceive()
            .DeleteOneRtEntityByRtIdAsync<RtNotificationTemplate>(
                _session, customTemplate.RtId, Arg.Any<DeleteOptions>());
    }

    [Fact]
    public async Task MigrateAsync_BlueprintTemplate_IsPreserved()
    {
        var blueprintTemplate = new RtNotificationTemplate
        {
            RtId = BlueprintWelcomeTemplateRtId,
            RtWellKnownName = IdentityServiceConstants.WelcomeEmailTemplateName,
        };

        SetupTemplates(blueprintTemplate);

        await _sut.MigrateAsync(_adminSession, _tenantContext);

        await _tenantRepository.DidNotReceive()
            .DeleteOneRtEntityByRtIdAsync<RtNotificationTemplate>(
                _session, blueprintTemplate.RtId, Arg.Any<DeleteOptions>());
    }

    // -------- Helpers --------------------------------------------------------------------------

    private void SetupEmpty<TEntity>() where TEntity : RtEntity, new()
    {
        _tenantRepository
            .GetRtEntitiesByTypeAsync<TEntity>(_session, Arg.Any<RtEntityQueryOptions>())
            .Returns(Task.FromResult<IResultSet<TEntity>>(
                new ResultSet<TEntity>(Array.Empty<TEntity>(), 0, null, null)));
    }

    private void SetupConfigs(params RtMailNotificationConfiguration[] configs)
    {
        _tenantRepository
            .GetRtEntitiesByTypeAsync<RtMailNotificationConfiguration>(
                _session, Arg.Any<RtEntityQueryOptions>())
            .Returns(Task.FromResult<IResultSet<RtMailNotificationConfiguration>>(
                new ResultSet<RtMailNotificationConfiguration>(configs, configs.Length, null, null)));
    }

    private void SetupTemplates(params RtNotificationTemplate[] templates)
    {
        _tenantRepository
            .GetRtEntitiesByTypeAsync<RtNotificationTemplate>(
                _session, Arg.Any<RtEntityQueryOptions>())
            .Returns(Task.FromResult<IResultSet<RtNotificationTemplate>>(
                new ResultSet<RtNotificationTemplate>(templates, templates.Length, null, null)));
    }
}
