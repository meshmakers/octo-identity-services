using Microsoft.Extensions.Configuration.Json;

namespace Meshmakers.Octo.Backend.IdentityServices.Configuration;

/// <summary>
///     User secrets of the service (<c>dotnet user-secrets</c>) and the switch that keeps them out of a host (AB#8949).
/// </summary>
/// <remarks>
///     <c>WebApplication.CreateBuilder</c> adds the user secrets in the Development environment, and <c>Program</c> adds them
///     once more after the <c>OCTO_</c> environment variables. A host started with the setting <see cref="DisableSettingKey" />
///     (the integration test host passes it with <c>UseSetting</c>, so it arrives as a command-line argument before
///     <c>Program</c> reads anything) reads no user secrets at all: <see cref="RemoveFrom" /> runs right after
///     <c>CreateBuilder</c>, before any value is read while the services are registered. Without the setting nothing changes.
/// </remarks>
internal static class UserSecretsConfiguration
{
    /// <summary>
    ///     Host setting that switches the user secrets off (<c>true</c>). Not meant for deployments: they have no user secrets.
    /// </summary>
    public const string DisableSettingKey = "DisableUserSecrets";

    /// <summary>
    ///     File name of the user secrets file.
    /// </summary>
    public const string FileName = "secrets.json";

    /// <summary>
    ///     Whether the host was started with <see cref="DisableSettingKey" /> = <c>true</c>.
    /// </summary>
    public static bool IsDisabled(IConfiguration configuration) =>
        configuration.GetValue<bool>(DisableSettingKey);

    /// <summary>
    ///     Removes every user secrets source from <paramref name="configuration" />; returns how many were removed.
    /// </summary>
    public static int RemoveFrom(IConfigurationBuilder configuration)
    {
        var sources = configuration.Sources
            .OfType<JsonConfigurationSource>()
            .Where(IsUserSecrets)
            .ToList();
        foreach (var source in sources)
        {
            configuration.Sources.Remove(source);
        }

        return sources.Count;
    }

    /// <summary>
    ///     Whether <paramref name="source" /> is a user secrets file.
    /// </summary>
    public static bool IsUserSecrets(FileConfigurationSource source) =>
        string.Equals(source.Path, FileName, StringComparison.OrdinalIgnoreCase);
}
