using System.Collections.Concurrent;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;

namespace IdentityServices.IntegrationTests.Infrastructure;

/// <summary>
///     Disposes the rate limiters of ASP.NET Core's <c>RateLimitingMiddleware</c> when a test host stops (AB#8337).
/// </summary>
/// <remarks>
///     <para>
///         <c>app.UseRateLimiter()</c> (Program.cs: policies <c>tenant-discovery</c> and <c>dcr</c>) builds a
///         <c>DefaultPartitionedRateLimiter</c> whose 100 ms heartbeat timer runs until the limiter is disposed — and the
///         middleware never disposes it (it is not <see cref="IDisposable" />, ASP.NET Core 10.0). The timer is a GC root
///         for the limiter, the limiter's partitioner captures the middleware, and the middleware's <c>_next</c> is the
///         whole rest of the request pipeline with the host's services. On top of that the timer captured the
///         <see cref="ExecutionContext" /> of the test that started the host, i.e. xUnit's <c>TestContext</c> and through it
///         the class fixtures of that test class.
///     </para>
///     <para>
///         A production process builds one pipeline and keeps it for its lifetime, so this costs nothing there. The
///         integration suite builds ~300 in-process hosts (every <see cref="CustomWebApplicationFactory" /> and every
///         <c>WithWebHostBuilder</c> derivative) and none of them was ever collected: the test host reached 10 GB working set
///         (5.4 GB gen2, 4.5 GB LOH, 3.6 GB of it OpenTelemetry <c>MetricPoint[]</c> of 295 live meter providers) and ran
///         into the 9 GiB GC heap hard limit of a 12 Gi CI agent (AB#8337, builds 65745 and 65817).
///     </para>
///     <para>
///         The middleware is internal, so this walks the built pipeline by reflection: from the <see cref="IServer" /> (the
///         <c>TestServer</c>) through the hosting application to the <see cref="RequestDelegate" /> chain, following only
///         delegates, their targets and <c>_next</c>-style fields, and disposes every <see cref="PartitionedRateLimiter{TResource}" />
///         field of each <c>RateLimitingMiddleware</c> it finds. <c>RateLimiterReleaserTests</c> pins that it still finds the
///         middleware: if a framework update changes the shape, that test fails instead of the suite silently leaking again.
///     </para>
/// </remarks>
internal sealed class RateLimiterReleaser(IServer server) : IHostedService
{
    private const string RateLimitingMiddlewareTypeName = "Microsoft.AspNetCore.RateLimiting.RateLimitingMiddleware";

    /// <summary>Upper bound for the walk; the identity pipeline has a few dozen nodes.</summary>
    private const int MaxVisitedObjects = 10_000;

    private readonly ConcurrentDictionary<object, byte> _disposed = new(ReferenceEqualityComparer.Instance);

    /// <summary>Number of distinct rate limiters this releaser disposed when its host stopped. Test seam.</summary>
    internal int DisposedLimiterCount => _disposed.Count;

    public Task StartAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        // StopAsync can run more than once per host, also concurrently (WebApplicationFactory stops the host from Dispose
        // and from DisposeAsync). It must never throw: an exception here aborts the factory's dispose before the host's
        // service provider is disposed, which leaks the host - the opposite of the purpose.
        try
        {
            foreach (var limiter in FindRateLimitingMiddlewareLimiters(server))
            {
                if (_disposed.TryAdd(limiter, 0))
                {
                    await limiter.DisposeAsync();
                }
            }
        }
        catch (Exception ex)
        {
            await Console.Error.WriteLineAsync($"[RateLimiterReleaser] Releasing the rate limiter failed: {ex.GetType().Name}: {ex.Message}");
        }
    }

    /// <summary>
    ///     Finds the <see cref="PartitionedRateLimiter{TResource}" /> instances held by every <c>RateLimitingMiddleware</c>
    ///     reachable from <paramref name="root" />.
    /// </summary>
    internal static IReadOnlyList<PartitionedRateLimiter<HttpContext>> FindRateLimitingMiddlewareLimiters(object root)
    {
        var result = new List<PartitionedRateLimiter<HttpContext>>();
        var visited = new HashSet<object>(ReferenceEqualityComparer.Instance);
        var pending = new Queue<object>();
        pending.Enqueue(root);

        while (pending.Count > 0 && visited.Count < MaxVisitedObjects)
        {
            var current = pending.Dequeue();
            if (!visited.Add(current))
            {
                continue;
            }

            if (current is Delegate @delegate)
            {
                foreach (var single in @delegate.GetInvocationList())
                {
                    if (single.Target is { } target)
                    {
                        pending.Enqueue(target);
                    }
                }

                continue;
            }

            var type = current.GetType();
            var isRateLimitingMiddleware = type.FullName == RateLimitingMiddlewareTypeName;

            foreach (var field in GetInstanceFields(type))
            {
                var value = field.GetValue(current);
                if (value is null)
                {
                    continue;
                }

                if (isRateLimitingMiddleware && value is PartitionedRateLimiter<HttpContext> limiter)
                {
                    result.Add(limiter);
                }
                else if (value is Delegate || IsPipelineNode(value.GetType()))
                {
                    pending.Enqueue(value);
                }
            }
        }

        return result;
    }

    /// <summary>
    ///     The objects between the server and the middleware: the test server's application wrapper, the hosting
    ///     application, middleware instances and the closures <c>app.Use(next =&gt; ...)</c> compiles to. Everything else
    ///     (services, endpoint data sources, options) is not followed, so the walk stays small.
    /// </summary>
    private static bool IsPipelineNode(Type type)
    {
        var fullName = type.FullName ?? string.Empty;
        return fullName.StartsWith("Microsoft.AspNetCore.TestHost.", StringComparison.Ordinal)
               || fullName.StartsWith("Microsoft.AspNetCore.Hosting.HostingApplication", StringComparison.Ordinal)
               || type.Name.EndsWith("Middleware", StringComparison.Ordinal)
               || type.IsDefined(typeof(CompilerGeneratedAttribute), inherit: false);
    }

    private static IEnumerable<FieldInfo> GetInstanceFields(Type type)
    {
        for (var current = type; current is not null && current != typeof(object); current = current.BaseType)
        {
            foreach (var field in current.GetFields(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic |
                                                    BindingFlags.DeclaredOnly))
            {
                yield return field;
            }
        }
    }
}
