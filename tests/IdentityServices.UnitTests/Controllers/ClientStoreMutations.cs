using IdentityServerPersistence.SystemStores;
using NSubstitute;
using Persistence.IdentityCkModel.Generated.System.Identity.v3;

namespace IdentityServices.UnitTests.Controllers;

/// <summary>
///     Makes <see cref="IOctoClientStore.MutateAsync" /> of a substitute behave like the real store for controller tests
///     (AB#8015): the client is looked up through the substitute's own <see cref="IOctoClientStore.FindRtClientByIdAsync" />
///     (or, if that returns nothing, <see cref="IOctoClientStore.GetClients" />), the change is applied to it, and the
///     client id is recorded when the change asked for a write.
/// </summary>
internal static class ClientStoreMutations
{
    /// <returns>The ids of the clients written, in call order.</returns>
    public static List<string> Attach(IOctoClientStore store)
    {
        var written = new List<string>();
        store.MutateAsync(Arg.Any<string>(), Arg.Any<Func<RtClient, bool>>()).Returns(async call =>
        {
            var clientId = call.ArgAt<string>(0);
            var mutate = call.ArgAt<Func<RtClient, bool>>(1);
            var client = await store.FindRtClientByIdAsync(clientId) ??
                         (await store.GetClients()).FirstOrDefault(c => c.ClientId == clientId);
            if (client == null)
            {
                return null;
            }

            if (mutate(client))
            {
                written.Add(clientId);
            }

            return client;
        });
        return written;
    }
}
