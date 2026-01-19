using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace IdentityServices.IntegrationTests.Infrastructure;

public abstract class IntegrationTestBase : IClassFixture<CustomWebApplicationFactory>
{
    protected readonly HttpClient Client;
    protected readonly CustomWebApplicationFactory Factory;

    protected IntegrationTestBase(CustomWebApplicationFactory factory)
    {
        Console.Error.WriteLine("[IntegrationTestBase] Constructor called, creating HTTP client...");
        Console.Error.Flush();
        Factory = factory;
        Client = factory.CreateClient();
        Console.Error.WriteLine("[IntegrationTestBase] HTTP client created");
        Console.Error.Flush();
        Client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", "test-token");
    }

    protected async Task<T?> GetAsync<T>(string url)
    {
        var response = await Client.GetAsync(url);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<T>();
    }

    protected async Task<HttpResponseMessage> PostAsync<T>(string url, T content)
    {
        return await Client.PostAsJsonAsync(url, content);
    }

    protected async Task<HttpResponseMessage> PutAsync<T>(string url, T content)
    {
        return await Client.PutAsJsonAsync(url, content);
    }

    protected async Task<HttpResponseMessage> DeleteAsync(string url)
    {
        return await Client.DeleteAsync(url);
    }

    protected IServiceScope CreateScope() => Factory.Services.CreateScope();
}
