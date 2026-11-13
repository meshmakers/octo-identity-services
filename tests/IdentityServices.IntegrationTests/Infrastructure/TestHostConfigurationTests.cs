using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.Json;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace IdentityServices.IntegrationTests.Infrastructure;

/// <summary>
///     AB#8019: the test hosts load their configuration files without file watchers, so the suite does not run into the
///     inotify instance limit of a Linux CI agent (see <see cref="CustomWebApplicationFactory" />). AB#8949: they do not read
///     the developer's user secrets.
/// </summary>
public class TestHostConfigurationTests(CustomWebApplicationFactory factory) : IntegrationTestBase(factory)
{
    [Fact]
    public void TheTestHost_LoadsItsJsonConfigurationFiles_WithoutReloadOnChange()
    {
        var root = (IConfigurationRoot)Factory.Services.GetRequiredService<IConfiguration>();

        var jsonSources = root.Providers.OfType<JsonConfigurationProvider>().Select(p => p.Source).ToList();

        jsonSources.Should().NotBeEmpty("the host reads appsettings files");
        jsonSources.Should().OnlyContain(s => !s.ReloadOnChange, "a file watcher per host exhausts the inotify limit");
    }

    [Fact]
    public void ADerivedHost_LoadsItsJsonConfigurationFiles_WithoutReloadOnChange()
    {
        using var derived = Factory.WithWebHostBuilder(_ => { });
        var root = (IConfigurationRoot)derived.Services.GetRequiredService<IConfiguration>();

        root.Providers.OfType<JsonConfigurationProvider>().Should().OnlyContain(p => !p.Source.ReloadOnChange);
    }

    /// <summary>
    ///     AB#8949: <c>WebApplication.CreateBuilder</c> (Development environment) and <c>Program</c> both add the user secrets of
    ///     the service. A developer's secret (e.g. <c>Identity:DataProtectionKeysPath</c>) must not change the test host.
    /// </summary>
    [Fact]
    public void TheTestHost_DoesNotReadUserSecrets()
    {
        var root = (IConfigurationRoot)Factory.Services.GetRequiredService<IConfiguration>();

        UserSecretsSources(root).Should().BeEmpty("the tests depend on their own configuration only");
    }

    [Fact]
    public void ADerivedHost_DoesNotReadUserSecrets()
    {
        using var derived = Factory.WithWebHostBuilder(_ => { });
        var root = (IConfigurationRoot)derived.Services.GetRequiredService<IConfiguration>();

        UserSecretsSources(root).Should().BeEmpty("a derived host inherits the configuration of the factory");
    }

    private static List<FileConfigurationSource> UserSecretsSources(IConfigurationRoot root) =>
        root.Providers.OfType<JsonConfigurationProvider>()
            .Select(p => p.Source)
            .Where(s => string.Equals(s.Path, CustomWebApplicationFactory.UserSecretsFileName,
                StringComparison.OrdinalIgnoreCase))
            .ToList();
}
