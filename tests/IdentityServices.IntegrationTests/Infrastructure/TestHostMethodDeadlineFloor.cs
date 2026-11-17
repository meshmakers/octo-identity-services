using Meshmakers.Octo.Services.Methods;
using Microsoft.Extensions.DependencyInjection;

namespace IdentityServices.IntegrationTests.Infrastructure;

/// <summary>
///     Test-host method deadline floor: wraps the production <see cref="ICkMethodTimeoutResolver" /> of the
///     <see cref="CustomWebApplicationFactory" /> host and raises every CK method timeout to at least <see cref="Floor" />.
/// </summary>
/// <remarks>
///     <para>
///         The REST endpoints of the identity service run CK methods through <c>IdentityMethodFacade</c> and the
///         in-process dispatcher with the deadline of the method's CK definition; a method without
///         <c>timeoutSeconds</c> (e.g. <c>User.AddRole</c>) gets the CK default of 15 s. On a machine that runs other
///         builds or suites at the same time a single call of the full integration suite took longer than that and
///         the REST call answered <c>METHOD_TIMEOUT</c> / HTTP 504 although the handler was correct - a result of the
///         machine, not of the code under test.
///     </para>
///     <para>
///         The floor changes only how long the test host waits. Every authorization, guard and REST/method parity
///         assertion is unchanged. The deadline mechanics themselves (the CK timeout becomes the deadline,
///         <c>METHOD_TIMEOUT</c> at the deadline, clamping) are proven in octo-common-services by
///         <c>Methods.Tests/Dispatching/CkMethodTimeoutResolverTests</c>, <c>Methods.Tests/InProcess/InProcessTransportTests</c>
///         and <c>Methods.IntegrationTests/CkMethodDispatcherBusTests</c>, which do not use this host. A test that needs
///         the real CK deadline in the identity service builds its own host instead of the factory (the floor is
///         registered only here) or removes this decorator.
///     </para>
/// </remarks>
internal sealed class TestHostMethodDeadlineFloor(ICkMethodTimeoutResolver inner, TimeProvider timeProvider)
    : ICkMethodTimeoutResolver
{
    /// <summary>The lowest method timeout the test host uses.</summary>
    public static readonly TimeSpan Floor = TimeSpan.FromSeconds(120);

    public bool TryGetTimeout(string tenantId, string ckTypeId, string methodId, out TimeSpan timeout)
    {
        var known = inner.TryGetTimeout(tenantId, ckTypeId, methodId, out timeout);
        if (known && timeout < Floor)
        {
            timeout = Floor;
        }

        return known;
    }

    public TimeSpan GetTimeout(string tenantId, string ckTypeId, string methodId)
    {
        var timeout = inner.GetTimeout(tenantId, ckTypeId, methodId);
        return timeout < Floor ? Floor : timeout;
    }

    public DateTime GetDeadlineUtc(string tenantId, string ckTypeId, string methodId)
    {
        var deadline = inner.GetDeadlineUtc(tenantId, ckTypeId, methodId);
        var floor = timeProvider.GetUtcNow().UtcDateTime + Floor;
        return deadline < floor ? floor : deadline;
    }

    /// <summary>Replaces the registered resolver with this decorator over it.</summary>
    public static void Register(IServiceCollection services)
    {
        var descriptor = services.LastOrDefault(d => d.ServiceType == typeof(ICkMethodTimeoutResolver)) ??
                         throw new InvalidOperationException(
                             "ICkMethodTimeoutResolver is not registered; adapt the test-host method deadline floor.");
        var implementation = descriptor.ImplementationType ?? throw new InvalidOperationException(
            "ICkMethodTimeoutResolver is expected as a type registration; adapt the test-host method deadline floor.");
        services.Remove(descriptor);
        services.AddSingleton<ICkMethodTimeoutResolver>(sp => new TestHostMethodDeadlineFloor(
            (ICkMethodTimeoutResolver)ActivatorUtilities.CreateInstance(sp, implementation),
            sp.GetService<TimeProvider>() ?? TimeProvider.System));
    }
}
