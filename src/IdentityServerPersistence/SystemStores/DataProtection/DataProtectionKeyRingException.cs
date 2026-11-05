namespace IdentityServerPersistence.SystemStores.DataProtection;

/// <summary>
///     The Data Protection key ring cannot be used safely with the configured platform key ring (AB#5530): a stored
///     key is wrapped with a missing key id, or encryption is required and no key is configured. Identity refuses to
///     start instead of falling back to clear text.
/// </summary>
public sealed class DataProtectionKeyRingException(string message) : InvalidOperationException(message);
