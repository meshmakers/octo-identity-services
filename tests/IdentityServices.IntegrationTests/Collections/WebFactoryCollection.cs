using IdentityServices.IntegrationTests.Infrastructure;

using Xunit;

namespace IdentityServices.IntegrationTests.Collections;

/// <summary>
///     Shares one <see cref="CustomWebApplicationFactory" /> — and therefore one MongoDB container plus one
///     ASP.NET test host — across every HTTP integration test class that joins this collection, replacing
///     the per-class <c>IClassFixture&lt;CustomWebApplicationFactory&gt;</c> on
///     <see cref="IntegrationTestBase" /> (AB#5160).
/// </summary>
/// <remarks>
///     The name starts with "Z" so the host-based collections run after the store-level ones, matching
///     octo-communication-controller-services. Every class in here seeds its users under GUID-suffixed
///     names and its clients under a class-unique prefix, so no two classes collide. The one class that
///     manipulates the database as a whole — <c>SetupApiTests</c>, which deletes ALL users to reach the
///     fresh-install state — lives in <see cref="SetupApiCollection" /> instead.
/// </remarks>
[CollectionDefinition(Name)]
public class WebFactoryCollection : ICollectionFixture<CustomWebApplicationFactory>
{
    public const string Name = "ZWebFactory";
}
