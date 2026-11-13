using FluentAssertions;
using Meshmakers.Octo.Backend.IdentityServices.Configuration;
using Meshmakers.Octo.Backend.IdentityServices.Methods;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.FileProviders;
using Xunit;

namespace IdentityServices.UnitTests.Configuration;

/// <summary>
///     AB#8949: a host started with <see cref="UserSecretsConfiguration.DisableSettingKey" /> reads no user secrets, also
///     not for the values <c>Program</c> reads while it registers the services (e.g. the password method switch).
/// </summary>
public sealed class UserSecretsConfigurationTests : IDisposable
{
    private readonly string _secretsDirectory =
        Path.Combine(Path.GetTempPath(), $"ab8949-user-secrets-{Guid.NewGuid():N}");

    public UserSecretsConfigurationTests()
    {
        Directory.CreateDirectory(_secretsDirectory);
        File.WriteAllText(Path.Combine(_secretsDirectory, UserSecretsConfiguration.FileName),
            """{ "Methods": { "Identity": { "EnablePasswordMethods": true } } }""");
    }

    public void Dispose() => Directory.Delete(_secretsDirectory, recursive: true);

    [Fact]
    public void AnEagerlyReadValue_IsTakenFromTheUserSecrets_WhileTheyAreLoaded()
    {
        using var configuration = WithUserSecrets();

        IdentityMethodHost.ReadOptions(configuration).EnablePasswordMethods.Should().BeTrue("control: the secret is read");
    }

    [Fact]
    public void AnEagerlyReadValue_IsNotTakenFromTheUserSecrets_AfterTheyAreRemoved()
    {
        using var configuration = WithUserSecrets();

        UserSecretsConfiguration.RemoveFrom(configuration).Should().Be(1);

        IdentityMethodHost.ReadOptions(configuration).EnablePasswordMethods.Should().BeFalse();
        configuration.Sources.OfType<FileConfigurationSource>().Should().NotContain(s => UserSecretsConfiguration.IsUserSecrets(s));
        configuration["Other:Key"].Should().Be("value", "the other sources stay");
    }

    [Theory]
    [InlineData("true", true)]
    [InlineData("True", true)]
    [InlineData("false", false)]
    [InlineData(null, false)]
    public void IsDisabled_ReadsTheHostSetting(string? value, bool expected)
    {
        using var configuration = new ConfigurationManager();
        configuration.AddInMemoryCollection(new Dictionary<string, string?>
        {
            [UserSecretsConfiguration.DisableSettingKey] = value
        });

        UserSecretsConfiguration.IsDisabled(configuration).Should().Be(expected);
    }

    private ConfigurationManager WithUserSecrets()
    {
        var configuration = new ConfigurationManager();
        configuration.AddInMemoryCollection(new Dictionary<string, string?> { ["Other:Key"] = "value" });
        configuration.AddJsonFile(new PhysicalFileProvider(_secretsDirectory), UserSecretsConfiguration.FileName,
            optional: false, reloadOnChange: false);
        return configuration;
    }
}
