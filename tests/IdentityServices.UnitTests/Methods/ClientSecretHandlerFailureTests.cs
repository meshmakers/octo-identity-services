using FluentAssertions;
using Meshmakers.Octo.Backend.IdentityServices.Methods;
using Meshmakers.Octo.Services.Contracts.DistributionEventHub.Methods;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Meshmakers.Octo.Services.Methods;
using Meshmakers.Octo.Services.Methods.Authorization;
using Microsoft.Extensions.DependencyInjection;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Xunit;

namespace IdentityServices.UnitTests.Methods;

/// <summary>AB#7780: a call that throws is still audited once, as <c>METHOD_HANDLER_FAILED</c>, and the exception reaches the host.</summary>
public class ClientSecretHandlerFailureTests
{
    private const string Target = "507f1f77bcf86cd799439011";

    [Fact]
    public async Task AddSecret_RepositoryFailure_Throws_AndIsAuditedAsHandlerFailed()
    {
        var (services, audit) = Services();
        var handler = new ClientAddSecretHandler(services);
        var context = new CkMethodContext<ClientAddSecretParameters>(Request(SystemIdentityCkIds.ClientAddSecretMethodId),
            new ClientAddSecretParameters()) { CallerPrincipal = Admin() };

        var act = () => handler.HandleAsync(context, CancellationToken.None);

        await act.Should().ThrowAsync<InvalidOperationException>();
        audit.Records.Should().ContainSingle().Which.Should().Be(
            (SystemIdentityCkIds.ClientAddSecretMethodId, Target, "admin", "METHOD_HANDLER_FAILED"));
    }

    [Fact]
    public async Task RemoveSecret_RepositoryFailure_Throws_AndIsAuditedAsHandlerFailed()
    {
        var (services, audit) = Services();
        var handler = new ClientRemoveSecretHandler(services);
        var context = new CkMethodContext<ClientRemoveSecretParameters>(
            Request(SystemIdentityCkIds.ClientRemoveSecretMethodId),
            new ClientRemoveSecretParameters { SecretValue = "value-7780" }) { CallerPrincipal = Admin() };

        var act = () => handler.HandleAsync(context, CancellationToken.None);

        await act.Should().ThrowAsync<InvalidOperationException>();
        audit.Records.Should().ContainSingle().Which.Should().Be(
            (SystemIdentityCkIds.ClientRemoveSecretMethodId, Target, "admin", "METHOD_HANDLER_FAILED"));
        audit.DetailValues.Should().NotContain(v => v.Contains("value-7780"));
    }

    private static CkMethodPrincipal Admin() => new("admin", ["TenantManagement"], ["octo_api"]);

    private static CkMethodRequest Request(string methodId) => new("t1")
    {
        InvocationId = Guid.NewGuid(),
        MethodId = methodId,
        CkTypeId = "System.Identity/Client",
        TargetRtId = Target,
        DeadlineUtc = DateTime.UtcNow.AddSeconds(30)
    };

    private static (IServiceProvider Services, RecordingAudit Audit) Services()
    {
        var resolver = Substitute.For<IMultiTenancyResolverService>();
        resolver.GetTenantRepository().Returns(_ => throw new InvalidOperationException("database down"));
        var audit = new RecordingAudit();
        var services = new ServiceCollection()
            .AddSingleton<IMethodTenantAccessor>(new BoundTenant())
            .AddSingleton(resolver)
            .AddSingleton<IIdentityMethodAuditWriter>(audit)
            .BuildServiceProvider();
        return (services, audit);
    }

    private sealed class BoundTenant : IMethodTenantAccessor
    {
        public Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories.ITenantRepository? TenantRepository => null;

        public Task<bool> BindAsync(string tenantId) => Task.FromResult(true);
    }

    private sealed class RecordingAudit : IIdentityMethodAuditWriter
    {
        public List<(string MethodId, string? Target, string? Caller, string Outcome)> Records { get; } = [];

        public List<string> DetailValues { get; } = [];

        public Task RecordAsync(string tenantId, string methodId, Guid invocationId, string? targetRtId,
            string? callerSubject, string outcome, IReadOnlyDictionary<string, string>? extraDetails = null)
        {
            Records.Add((methodId, targetRtId, callerSubject, outcome));
            DetailValues.AddRange(extraDetails?.Values ?? []);
            return Task.CompletedTask;
        }
    }
}
