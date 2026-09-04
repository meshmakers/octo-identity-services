using Microsoft.Extensions.Logging;

namespace IdentityServices.IntegrationTests.Fixtures;

/// <summary>
///     Minimum log level for every logger the integration tests build, both in the fixtures and in the
///     test web host.
/// </summary>
/// <remarks>
///     The fixtures used to log at <see cref="LogLevel.Trace" />. Combined with the pipeline's
///     <c>--logger "console;verbosity=detailed"</c>, which writes xUnit's per-test output for passing
///     tests as well, one run produced ~308,000 lines of build log — 144,000 of them
///     <c>dbug:</c> from the CK model bootstrap and the Mongo repository clients. Writing that to an
///     Azure DevOps agent costs far more than writing it locally: the identical run is 46 s on a dev
///     machine and 6.5 min on the CI agent (AB#5117).
///     <para>
///         Default is therefore <see cref="LogLevel.Warning" />, which still carries every
///         <c>warn:</c> and <c>fail:</c> line a failing test needs. Set <c>OCTO_TEST_LOG_LEVEL</c>
///         (e.g. <c>Debug</c> or <c>Trace</c>) to get the verbose output back when diagnosing one.
///     </para>
/// </remarks>
internal static class TestLogging
{
    private const string LevelEnvironmentVariable = "OCTO_TEST_LOG_LEVEL";

    public static LogLevel MinimumLevel { get; } = ResolveMinimumLevel();

    private static LogLevel ResolveMinimumLevel()
    {
        var configured = Environment.GetEnvironmentVariable(LevelEnvironmentVariable);

        // Enum.TryParse also accepts any numeric string, so "999" would parse into an undefined
        // LogLevel and silence every provider. Enum.IsDefined rejects those and keeps the default.
        return !string.IsNullOrWhiteSpace(configured)
               && Enum.TryParse<LogLevel>(configured, true, out var level)
               && Enum.IsDefined(level)
            ? level
            : LogLevel.Warning;
    }
}
