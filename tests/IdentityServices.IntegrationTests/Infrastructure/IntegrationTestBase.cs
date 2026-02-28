using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using IdentityServerPersistence.SystemStores;
using Meshmakers.Octo.Backend.IdentityServices.Controllers.Api;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Configuration;
using Meshmakers.Octo.Runtime.Contracts.MongoDb.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories;
using Meshmakers.Octo.Runtime.Contracts.Repositories.Query;
using Meshmakers.Octo.Services.Infrastructure.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Persistence.IdentityCkModel.Generated.System.Identity.v2;
using Shared.TestUtilities.Builders;
using Xunit;

namespace IdentityServices.IntegrationTests.Infrastructure;

public abstract class IntegrationTestBase : IClassFixture<CustomWebApplicationFactory>
{
    protected const string DefaultTenantId = "System";
    protected const string DefaultPassword = "Test123!";

    protected readonly HttpClient Client;
    protected readonly CustomWebApplicationFactory Factory;

    /// <summary>
    /// The normalized system tenant ID resolved from <see cref="OctoSystemConfiguration"/>.
    /// </summary>
    protected string NormalizedSystemTenantId { get; }

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

        var systemConfig = factory.Services.GetRequiredService<IOptions<OctoSystemConfiguration>>();
        NormalizedSystemTenantId = systemConfig.Value.SystemTenantId.Trim().ToLowerInvariant();
    }

    #region HTTP Helper Methods

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

    protected async Task<TResponse?> PostAndReadAsync<TRequest, TResponse>(string url, TRequest content)
    {
        var response = await Client.PostAsJsonAsync(url, content);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<TResponse>();
    }

    #endregion

    #region Client Factory Methods

    /// <summary>
    /// Creates an HTTP client that simulates an unauthenticated user (no Bearer token).
    /// </summary>
    protected HttpClient CreateAnonymousClient()
    {
        var client = Factory.CreateClient();
        // No authorization header
        return client;
    }

    /// <summary>
    /// Creates an HTTP client with custom authentication options.
    /// </summary>
    protected HttpClient CreateAuthenticatedClient(
        string userId = "test-user-id",
        string userName = "testuser",
        string email = "test@example.com",
        IEnumerable<string>? roles = null,
        IEnumerable<string>? scopes = null)
    {
        var client = Factory.CreateClient();

        // Configure the test auth handler via service configuration
        // For now, we use a simple bearer token approach
        // In a more sophisticated setup, we would configure TestAuthHandlerOptions
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", "test-token");

        // Add custom headers that can be read by the test auth handler
        client.DefaultRequestHeaders.Add("X-Test-UserId", userId);
        client.DefaultRequestHeaders.Add("X-Test-UserName", userName);
        client.DefaultRequestHeaders.Add("X-Test-Email", email);

        if (roles != null)
        {
            foreach (var role in roles)
            {
                client.DefaultRequestHeaders.Add("X-Test-Role", role);
            }
        }

        if (scopes != null)
        {
            foreach (var scope in scopes)
            {
                client.DefaultRequestHeaders.Add("X-Test-Scope", scope);
            }
        }

        return client;
    }

    /// <summary>
    /// Creates an HTTP client with cookie support that can perform real login.
    /// This client preserves cookies across requests, enabling cookie-based authentication.
    /// </summary>
    protected HttpClient CreateCookieClient()
    {
        // Create client with cookie handling enabled
        var client = Factory.CreateClient(new Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactoryClientOptions
        {
            HandleCookies = true,
            AllowAutoRedirect = false // Don't auto-redirect so we can capture cookies
        });
        return client;
    }

    /// <summary>
    /// Performs a real login and returns an HTTP client with the authentication cookie.
    /// This enables testing of endpoints that require cookie-based authentication.
    /// </summary>
    /// <param name="userName">The username to login with</param>
    /// <param name="password">The password to login with</param>
    /// <returns>An HTTP client with authentication cookies, or null if login failed</returns>
    protected async Task<HttpClient?> LoginAndGetAuthenticatedClientAsync(
        string userName,
        string password,
        CancellationToken ct = default)
    {
        var client = CreateCookieClient();

        var loginRequest = new { Username = userName, Password = password, RememberLogin = true };
        var response = await client.PostAsJsonAsync(AuthApiUrl("login"), loginRequest, ct);

        if (!response.IsSuccessStatusCode)
        {
            return null;
        }

        var result = await response.Content.ReadFromJsonAsync<LoginResultDto>(ct);
        if (result?.Success != true)
        {
            return null;
        }

        // The client now has the authentication cookie set
        return client;
    }

    #endregion

    #region Test Data Creation Methods

    protected IServiceScope CreateScope() => Factory.Services.CreateScope();

    /// <summary>
    /// Creates a test user in the database.
    /// </summary>
    protected async Task<RtUser> CreateTestUserAsync(
        string userName,
        string? email = null,
        string? password = null,
        bool emailConfirmed = true,
        bool lockedOut = false,
        bool twoFactorEnabled = false)
    {
        email ??= $"{userName}@example.com";
        password ??= DefaultPassword;

        using var scope = CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<RtUser>>();

        var builder = new RtUserBuilder()
            .WithUserName(userName)
            .WithEmail(email)
            .WithEmailConfirmed(emailConfirmed);

        if (twoFactorEnabled)
        {
            builder.WithTwoFactorEnabled();
        }

        if (lockedOut)
        {
            builder.WithLockedOut(DateTimeOffset.UtcNow.AddHours(1));
        }

        var user = builder.Build();

        var result = await userManager.CreateAsync(user, password);
        if (!result.Succeeded)
        {
            throw new InvalidOperationException(
                $"Failed to create test user: {string.Join(", ", result.Errors.Select(e => e.Description))}");
        }

        return user;
    }

    /// <summary>
    /// Creates a test OAuth client in the database.
    /// </summary>
    protected async Task<RtClient> CreateTestClientAsync(
        string clientId,
        string? clientName = null,
        string? frontChannelLogoutUri = null,
        IEnumerable<string>? allowedScopes = null,
        IEnumerable<string>? grantTypes = null,
        IEnumerable<string>? redirectUris = null)
    {
        using var scope = CreateScope();
        var clientStore = scope.ServiceProvider.GetRequiredService<IOctoClientStore>();

        var builder = new RtClientBuilder()
            .WithClientId(clientId)
            .WithClientName(clientName ?? clientId);

        if (frontChannelLogoutUri != null)
        {
            builder.WithFrontChannelLogoutUri(frontChannelLogoutUri);
        }

        if (allowedScopes != null)
        {
            builder.WithScopes(allowedScopes.ToArray());
        }

        if (grantTypes != null)
        {
            builder.WithGrantTypes(grantTypes.ToArray());
        }

        if (redirectUris != null)
        {
            builder.WithRedirectUris(redirectUris.ToArray());
        }

        var client = builder.Build();
        await clientStore.CreateAsync(client);

        return client;
    }

    /// <summary>
    /// Creates a persisted grant (e.g., refresh token) in the database.
    /// </summary>
    protected async Task<RtPersistedGrant> CreatePersistedGrantAsync(
        string subjectId,
        string clientId,
        string grantType = "refresh_token",
        string? sessionId = null,
        DateTime? expiration = null)
    {
        using var scope = CreateScope();
        var grantStore = scope.ServiceProvider.GetRequiredService<IOctoPersistentGrantStore>();

        var grant = new RtPersistedGrantBuilder()
            .WithSubjectId(subjectId)
            .WithClientId(clientId)
            .WithGrantType(grantType)
            .WithExpiration(expiration ?? DateTime.UtcNow.AddDays(30))
            .Build();

        if (sessionId != null)
        {
            grant.SessionId = sessionId;
        }

        await grantStore.StoreAsync(grant);

        return grant;
    }

    /// <summary>
    /// Gets the count of persisted grants for a subject.
    /// </summary>
    protected async Task<int> GetGrantCountForSubjectAsync(string subjectId)
    {
        using var scope = CreateScope();
        var multiTenancyResolver = scope.ServiceProvider.GetRequiredService<IMultiTenancyResolverService>();
        var tenantRepository = multiTenancyResolver.GetTenantRepository();

        var session = await tenantRepository.GetSessionAsync();
        session.StartTransaction();

        try
        {
            var queryOptions = RtEntityQueryOptions.Create()
                .FieldFilter(nameof(RtPersistedGrant.SubjectId), FieldFilterOperator.Equals, subjectId);

            var result = await tenantRepository.GetRtEntitiesByTypeAsync<RtPersistedGrant>(session, queryOptions);
            await session.CommitTransactionAsync();

            return (int)result.TotalCount;
        }
        catch
        {
            await session.AbortTransactionAsync();
            throw;
        }
    }

    /// <summary>
    /// Deletes all persisted grants for a subject (cleanup helper).
    /// </summary>
    protected async Task DeleteAllGrantsForSubjectAsync(string subjectId)
    {
        using var scope = CreateScope();
        var multiTenancyResolver = scope.ServiceProvider.GetRequiredService<IMultiTenancyResolverService>();
        var tenantRepository = multiTenancyResolver.GetTenantRepository();

        var session = await tenantRepository.GetSessionAsync();
        session.StartTransaction();

        try
        {
            var fieldFilter = FieldFilterCriteria
                .Create(LogicalOperators.And)
                .FieldEquals(nameof(RtPersistedGrant.SubjectId), subjectId);

            await tenantRepository.DeleteManyRtEntitiesAsync<RtPersistedGrant>(
                session, fieldFilter, DeleteOptions.Erase);

            await session.CommitTransactionAsync();
        }
        catch
        {
            await session.AbortTransactionAsync();
            throw;
        }
    }

    #endregion

    #region URL Helper Methods

    /// <summary>
    /// Builds a versioned tenant API URL (e.g., /{tenantId}/v1/...).
    /// Uses the normalized system tenant ID from configuration by default.
    /// </summary>
    protected string TenantApiUrl(string path, string? tenantId = null)
    {
        tenantId ??= NormalizedSystemTenantId;
        return $"/{tenantId}/v1/{path.TrimStart('/')}";
    }

    /// <summary>
    /// Builds an API URL with the tenant ID prefix.
    /// </summary>
    protected static string ApiUrl(string path, string tenantId = DefaultTenantId)
    {
        return $"/{tenantId}/api/{path.TrimStart('/')}";
    }

    /// <summary>
    /// Builds an auth API URL.
    /// </summary>
    protected static string AuthApiUrl(string endpoint, string tenantId = DefaultTenantId)
    {
        return ApiUrl($"auth/{endpoint}", tenantId);
    }

    /// <summary>
    /// Builds a consent API URL.
    /// </summary>
    protected static string ConsentApiUrl(string? endpoint = null, string tenantId = DefaultTenantId)
    {
        return endpoint == null
            ? ApiUrl("consent", tenantId)
            : ApiUrl($"consent/{endpoint}", tenantId);
    }

    /// <summary>
    /// Builds a device API URL.
    /// </summary>
    protected static string DeviceApiUrl(string? endpoint = null, string tenantId = DefaultTenantId)
    {
        return endpoint == null
            ? ApiUrl("device", tenantId)
            : ApiUrl($"device/{endpoint}", tenantId);
    }

    /// <summary>
    /// Builds a grants API URL.
    /// </summary>
    protected static string GrantsApiUrl(string? endpoint = null, string tenantId = DefaultTenantId)
    {
        return endpoint == null
            ? ApiUrl("grants", tenantId)
            : ApiUrl($"grants/{endpoint}", tenantId);
    }

    /// <summary>
    /// Builds a manage API URL.
    /// </summary>
    protected static string ManageApiUrl(string endpoint, string tenantId = DefaultTenantId)
    {
        return ApiUrl($"manage/{endpoint}", tenantId);
    }

    #endregion

    #region JSON Helper Methods

    protected static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true
    };

    protected static string ToJson<T>(T obj)
    {
        return JsonSerializer.Serialize(obj, JsonOptions);
    }

    protected static T? FromJson<T>(string json)
    {
        return JsonSerializer.Deserialize<T>(json, JsonOptions);
    }

    #endregion
}
