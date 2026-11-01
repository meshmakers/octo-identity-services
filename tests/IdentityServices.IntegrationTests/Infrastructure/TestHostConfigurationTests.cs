using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.Json;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace IdentityServices.IntegrationTests.Infrastructure;

/// <summary>
///     AB#8019: the test hosts load their configuration files without file watchers, so the suite does not run into the
///     inotify instance limit of a Linux CI agent (see <see cref="CustomWebApplicationFactory" />).
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
}
