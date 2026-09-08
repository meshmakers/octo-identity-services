using IdentityServices.IntegrationTests.Infrastructure;

using Xunit;

namespace IdentityServices.IntegrationTests.Collections;

/// <summary>
///     Its own <see cref="CustomWebApplicationFactory" /> instance — and therefore its own MongoDB container
///     and test host (AB#5160).
/// </summary>
/// <remarks>
///     <c>SetupApiTests</c> drives the first-run setup endpoint, which is only active while the tenant has
///     no users at all; <c>CreateAdmin_WhenPasswordMismatch_ReturnsError</c> therefore deletes EVERY user
///     first. On the shared fixture of <see cref="WebFactoryCollection" /> that would wipe the users the
///     other fifteen classes seeded. The correct fix is a second container, not a softer precondition.
/// </remarks>
[CollectionDefinition(Name)]
public class SetupApiCollection : ICollectionFixture<CustomWebApplicationFactory>
{
    public const string Name = "ZSetupApi";
}
