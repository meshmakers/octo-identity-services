using IdentityServices.IntegrationTests.Configuration;
using Testcontainers.MongoDb;
using Xunit;

[assembly: AssemblyFixture<IdentityServices.IntegrationTests.Fixtures.SharedMongoDbContainerDisposer>]

namespace IdentityServices.IntegrationTests.Fixtures;

/// <summary>
///     One MongoDB replica-set Testcontainer for the whole test process instead of one per fixture
///     (AB#5117). Every <see cref="ConfigurationFixture" />-derived fixture and every
///     <c>CustomWebApplicationFactory</c> instance now gets its own
///     <see cref="ConfigurationFixture.SystemDatabaseName" /> (GUID-suffixed), so they no longer need
///     a private server to avoid colliding on the same database — they can share the one server this
///     class starts on first use.
/// </summary>
/// <remarks>
///     Started lazily (the first fixture that needs a database wins the race) and stopped exactly once
///     per test process by <see cref="SharedMongoDbContainerDisposer" />, which xUnit disposes after the
///     last test in the assembly. Testcontainers' Ryuk reaper remains the safety net for a crashed run.
/// </remarks>
internal static class SharedMongoDbContainer
{
    private static readonly SemaphoreSlim Gate = new(1, 1);
    private static MongoDbContainer? _container;
    private static string? _host;

    /// <summary>
    ///     Connection string of the already-started shared container. Only valid after a fixture has
    ///     awaited <see cref="GetHostAsync" />.
    /// </summary>
    public static string ConnectionString =>
        _container?.GetConnectionString()
        ?? throw new InvalidOperationException(
            "The shared MongoDB container has not been started yet. Await GetHostAsync first.");

    /// <summary>
    ///     Returns <c>localhost:{mappedPort}</c> of the shared container, starting it on first use.
    ///     localhost (rather than the container's bridge address) also works in DinD with a shared
    ///     docker.sock, which is how the CI agent runs.
    /// </summary>
    public static async Task<string> GetHostAsync(IntegrationTestOptions options)
    {
        if (_host != null)
        {
            return _host;
        }

        await Gate.WaitAsync();
        try
        {
            if (_host != null)
            {
                return _host;
            }

            await StartAsync(options);
            return _host!;
        }
        finally
        {
            Gate.Release();
        }
    }

    /// <summary>
    ///     Stops and removes the shared container. Called once per test process by
    ///     <see cref="SharedMongoDbContainerDisposer" />; never by an individual fixture.
    /// </summary>
    public static async ValueTask DisposeContainerAsync()
    {
        await Gate.WaitAsync();
        try
        {
            if (_container == null)
            {
                return;
            }

            try
            {
                await _container.DisposeAsync();
                Console.WriteLine("[Testcontainers] Shared MongoDB container disposed");
            }
            catch (Exception ex)
            {
                Console.WriteLine(
                    $"[Testcontainers] Disposal of the shared MongoDB container failed: {ex.GetType().Name}: {ex.Message}");
            }
            finally
            {
                _container = null;
                _host = null;
            }
        }
        finally
        {
            Gate.Release();
        }
    }

    private static async Task StartAsync(IntegrationTestOptions options)
    {
        Console.WriteLine($"[Testcontainers] Starting shared MongoDB container with image: {options.MongoDbImage}");
        Console.WriteLine(
            $"[Testcontainers] DOCKER_HOST: {Environment.GetEnvironmentVariable("DOCKER_HOST") ?? "(not set)"}");
        Console.WriteLine(
            $"[Testcontainers] TESTCONTAINERS_HOST_OVERRIDE: {Environment.GetEnvironmentVariable("TESTCONTAINERS_HOST_OVERRIDE") ?? "(not set)"}");
        Console.WriteLine(
            $"[Testcontainers] TESTCONTAINERS_RYUK_DISABLED: {Environment.GetEnvironmentVariable("TESTCONTAINERS_RYUK_DISABLED") ?? "(not set)"}");

        // Same retry rationale as the former per-fixture start: Testcontainers' rs.initiate()
        // handshake and mongo's keyfile-init entrypoint race with port binding on CI agents under
        // load. A *fresh* container per attempt is the proven fix.
        const int maxAttempts = 3;
        var perAttemptTimeout = TimeSpan.FromMinutes(2);

        for (var attempt = 1; attempt <= maxAttempts; attempt++)
        {
            Console.WriteLine($"[Testcontainers] StartAsync attempt {attempt}/{maxAttempts}");

            var container = new MongoDbBuilder(options.MongoDbImage)
                .WithReplicaSet()
                .WithName($"mongodb-identity-test-shared-{Guid.NewGuid():N}")
                .WithUsername(options.AdminUser)
                .WithPassword(options.AdminUserPassword)
                .Build();

            using var startCts = new CancellationTokenSource(perAttemptTimeout);
            var startTime = DateTime.UtcNow;

            try
            {
                await container.StartAsync(startCts.Token);

                _container = container;
                _host = $"localhost:{container.GetMappedPublicPort()}";

                var elapsed = DateTime.UtcNow - startTime;
                Console.WriteLine(
                    $"[Testcontainers] Shared container started in {elapsed.TotalSeconds:F1}s, MongoDB available at: {_host}");
                return;
            }
            catch (Exception ex)
            {
                Console.WriteLine(
                    $"[Testcontainers] StartAsync attempt {attempt}/{maxAttempts} failed: {ex.GetType().Name}: {ex.Message}");

                try
                {
                    await container.DisposeAsync();
                }
                catch (Exception disposeEx)
                {
                    Console.WriteLine(
                        $"[Testcontainers]   Disposal of failed container also threw: {disposeEx.Message}");
                }

                if (attempt == maxAttempts)
                {
                    throw;
                }

                await Task.Delay(TimeSpan.FromSeconds(2 * attempt));
            }
        }
    }
}

/// <summary>
///     Assembly fixture whose only job is to tear the shared container down deterministically after the
///     last test in the assembly, instead of relying on Ryuk alone (the CI agent has run with
///     <c>TESTCONTAINERS_RYUK_DISABLED</c> in the past). It never starts anything itself.
/// </summary>
public sealed class SharedMongoDbContainerDisposer : IAsyncDisposable
{
    public ValueTask DisposeAsync()
    {
        return SharedMongoDbContainer.DisposeContainerAsync();
    }
}
