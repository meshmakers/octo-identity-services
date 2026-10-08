using FluentAssertions;
using IdentityServerPersistence.Configuration.Options;
using IdentityServerPersistence.Services;
using Meshmakers.Octo.Runtime.Contracts;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NSubstitute;
using NSubstitute.ExceptionExtensions;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace IdentityServerPersistence.UnitTests.Services;

/// <summary>
///     AB#5540 — a tenant whose setup failed at cold start is skipped by the startup initializers
///     (e.g. auth scheme registration). The <see cref="ITenantSetupCompletedHandler"/> hook is how it
///     catches up once the background setup retry (or any later tenant event) completes the setup:
///     the base class calls <c>RefreshTenantStateAsync</c> after every successful non-cold-start setup.
/// </summary>
public class DefaultConfigurationCreatorServiceTenantSetupHandlerTests
{
    private const string SystemTenantId = "octosystem";

    private readonly ISystemContext _systemContext = Substitute.For<ISystemContext>();

    public DefaultConfigurationCreatorServiceTenantSetupHandlerTests()
    {
        _systemContext.TenantId.Returns(SystemTenantId);

        // RefreshTenantStateAsync runs the blueprint URI capture/expand/restore passes against the
        // tenant repository before the hook; give them an empty client list so they are no-ops.
        var repository = Substitute.For<ITenantRepository>();
        var session = Substitute.For<IOctoSession>();
        repository.GetSessionAsync().Returns(session);
        var noClients = Substitute.For<IResultSet<RtClient>>();
        noClients.Items.Returns(Array.Empty<RtClient>());
        repository.GetRtEntitiesByTypeAsync<RtClient>(session, Arg.Any<RtEntityQueryOptions>()).Returns(noClients);
        _systemContext.GetTenantRepositoryAsAdmin().Returns(repository);
    }

    [Fact]
    public async Task RefreshTenantState_AfterSetupRetrySucceeded_RunsTenantSetupCompletedHandlers()
    {
        var handler = Substitute.For<ITenantSetupCompletedHandler>();
        var sut = CreateSut(handler);

        await sut.InvokeRefreshTenantStateAsync(SystemTenantId);

        await handler.Received(1).OnTenantSetupCompletedAsync(SystemTenantId);
    }

    [Fact]
    public async Task NotifyTenantSetupCompleted_FailingHandler_DoesNotThrowAndRunsTheOthers()
    {
        var failing = Substitute.For<ITenantSetupCompletedHandler>();
        failing.OnTenantSetupCompletedAsync("meshtest")
            .ThrowsAsync(new InvalidOperationException("boom"));
        var healthy = Substitute.For<ITenantSetupCompletedHandler>();
        var sut = CreateSut(failing, healthy);

        var act = () => sut.NotifyTenantSetupCompletedAsync("meshtest");

        await act.Should().NotThrowAsync();
        await failing.Received(1).OnTenantSetupCompletedAsync("meshtest");
        await healthy.Received(1).OnTenantSetupCompletedAsync("meshtest");
    }

    [Fact]
    public async Task NotifyTenantSetupCompleted_NoHandlersRegistered_IsNoOp()
    {
        var sut = new TestableCreator(_systemContext, null);

        var act = () => sut.NotifyTenantSetupCompletedAsync("meshtest");

        await act.Should().NotThrowAsync();
    }

    private TestableCreator CreateSut(params ITenantSetupCompletedHandler[] handlers) =>
        new(_systemContext, handlers);

    private sealed class TestableCreator(
        ISystemContext systemContext,
        IEnumerable<ITenantSetupCompletedHandler>? handlers)
        : DefaultConfigurationCreatorService(
            NullLogger<DefaultConfigurationCreatorService>.Instance,
            systemContext,
            Substitute.For<IDiagnosticsService>(),
            Options.Create(new OctoIdentityServicesOptions { AutoMapperLicenseKey = "not-a-real-key" }),
            migrationService: null,
            tenantSetupCompletedHandlers: handlers)
    {
        public Task InvokeRefreshTenantStateAsync(string tenantId) => RefreshTenantStateAsync(tenantId);
    }
}
