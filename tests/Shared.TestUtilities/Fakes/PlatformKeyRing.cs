using System.Security.Cryptography;
using Meshmakers.Octo.Runtime.Contracts.Secrets;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Shared.TestUtilities.Fakes;

/// <summary>
///     A real platform key ring (<c>SecretEncryption</c>, the engine's <see cref="ISecretAttributeProtector" />) with
///     keys generated per test run (AB#5530). Several instances can share key material to model pods of one cluster
///     or a key rotation.
/// </summary>
public sealed class PlatformKeyRing : IDisposable
{
    private readonly ServiceProvider _serviceProvider;

    private PlatformKeyRing(IReadOnlyDictionary<string, byte[]> keys, string? activeKeyId)
    {
        Keys = keys;
        var values = new Dictionary<string, string?>();
        foreach (var (keyId, key) in keys)
        {
            values[$"SecretEncryption:Keys:{keyId}"] = Convert.ToBase64String(key);
        }

        if (activeKeyId != null)
        {
            values["SecretEncryption:ActiveKeyId"] = activeKeyId;
        }

        var configuration = new ConfigurationBuilder().AddInMemoryCollection(values).Build();
        var services = new ServiceCollection();
        services.AddSingleton<IConfiguration>(configuration);
        services.AddLogging();
        services.AddRuntimeEngine();
        _serviceProvider = services.BuildServiceProvider();
        Protector = _serviceProvider.GetRequiredService<ISecretAttributeProtector>();
    }

    /// <summary>Key id to key material.</summary>
    public IReadOnlyDictionary<string, byte[]> Keys { get; }

    /// <summary>The engine's protector over these keys.</summary>
    public ISecretAttributeProtector Protector { get; }

    /// <summary>A ring with one generated key <c>k1</c>, active.</summary>
    public static PlatformKeyRing CreateK1()
    {
        return Create(new Dictionary<string, byte[]> { ["k1"] = RandomNumberGenerator.GetBytes(32) }, "k1");
    }

    /// <summary>A ring with the given keys and active key id (<c>null</c> = no active key).</summary>
    public static PlatformKeyRing Create(IReadOnlyDictionary<string, byte[]> keys, string? activeKeyId)
    {
        return new PlatformKeyRing(keys, activeKeyId);
    }

    /// <summary>A ring without any key (SecretEncryption not configured).</summary>
    public static PlatformKeyRing CreateEmpty()
    {
        return new PlatformKeyRing(new Dictionary<string, byte[]>(), null);
    }

    /// <summary>
    ///     The same keys plus a new generated key <paramref name="newKeyId" />, which becomes active (rotation with the
    ///     old keys kept).
    /// </summary>
    public PlatformKeyRing RotateTo(string newKeyId)
    {
        var keys = new Dictionary<string, byte[]>(Keys) { [newKeyId] = RandomNumberGenerator.GetBytes(32) };
        return new PlatformKeyRing(keys, newKeyId);
    }

    /// <summary>The same keys without <paramref name="keyId" />; the active key id is kept.</summary>
    public PlatformKeyRing Without(string keyId, string activeKeyId)
    {
        var keys = Keys.Where(k => k.Key != keyId).ToDictionary(k => k.Key, k => k.Value);
        return new PlatformKeyRing(keys, activeKeyId);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        _serviceProvider.Dispose();
    }
}
