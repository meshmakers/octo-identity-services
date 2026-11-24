using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using Meshmakers.Octo.ConstructionKit.Contracts;
using Meshmakers.Octo.ConstructionKit.Contracts.DataTransferObjects;
using Meshmakers.Octo.ConstructionKit.Contracts.ModelCatalogs;
using Meshmakers.Octo.Runtime.Contracts.MongoDb;

namespace IdentityServices.IntegrationTests.Fixtures;

/// <summary>
///     An in-memory CK catalog for tests that put a tenant on a historic or published model version (for example the
///     published System.Identity 2.30.0). Such a model is installed through the service path,
///     <c>ITenantContext.ImportCkModelAsync(CkModelId, OperationResult)</c>, which loads it from the catalogs - the
///     caller overload <c>ImportCkModelAsync(CkCompiledModelRoot)</c> refuses service-managed models (<c>System</c>,
///     <c>System.*</c>, error <c>CK_SERVICE_MANAGED_MODEL</c>). A model is visible only while a test holds it (see
///     <see cref="ImportThroughServicePathAsync" />), and the catalog is asked first, so it never hides or replaces a
///     model of another catalog for other tests.
/// </summary>
public sealed class TestCkModelCatalog : ICatalog
{
    private readonly ConcurrentDictionary<string, CkCompiledModelRoot> _models = new(StringComparer.Ordinal);

    /// <inheritdoc />
    public int Order => -1000;

    /// <inheritdoc />
    public string CatalogName => "TestInMemory";

    /// <inheritdoc />
    public string Description => "In-memory catalog of the integration tests";

    /// <inheritdoc />
    public bool CanWrite => false;

    /// <inheritdoc />
    public bool CanRead => true;

    /// <summary>
    ///     Installs <paramref name="model" /> the way a starting service installs its embedded model: the model is put into
    ///     this catalog, imported by id through the downgrade-guarded service path, and removed from the catalog again.
    /// </summary>
    /// <returns>The messages of the import (a skipped or failed import is reported here, not thrown).</returns>
    public async Task<OperationResult> ImportThroughServicePathAsync(ITenantContext tenant, CkCompiledModelRoot model)
    {
        _models[model.ModelId.FullName] = model;
        try
        {
            var result = new OperationResult();
            await tenant.ImportCkModelAsync(model.ModelId, result);
            return result;
        }
        finally
        {
            _models.TryRemove(model.ModelId.FullName, out _);
        }
    }

    /// <inheritdoc />
    public Task RefreshCatalogAsync(object? sourceIdentifier = null, bool forceRefresh = false) => Task.CompletedTask;

    /// <inheritdoc />
    public bool IsSupportingSourceIdentifier(object? sourceIdentifier = null) => sourceIdentifier == null;

    /// <inheritdoc />
    public Task<ModelExistingResult> IsExistingAsync(CkModelIdVersionRange modelIdVersionRange,
        object? sourceIdentifier = null)
    {
        var best = _models.Values
            .Where(m => m.ModelId.Name == modelIdVersionRange.Name &&
                        modelIdVersionRange.ModelVersionRange.IsSatisfiedBy(m.ModelId.Version))
            .OrderBy(m => m.ModelId.Version)
            .LastOrDefault();
        return Task.FromResult(new ModelExistingResult
        {
            Exists = best != null, ModelId = best?.ModelId, CatalogName = best == null ? null : CatalogName
        });
    }

    /// <inheritdoc />
    public Task<bool> IsExistingAsync(CkModelId modelId, object? sourceIdentifier = null) =>
        Task.FromResult(_models.ContainsKey(modelId.FullName));

    /// <inheritdoc />
    public Task<CkCompiledModelRoot> GetAsync(CkModelId modelId, OperationResult operationResult,
        object? sourceIdentifier = null, CancellationToken? cancellationToken = null) =>
        _models.TryGetValue(modelId.FullName, out var model)
            ? Task.FromResult(model)
            : throw new InvalidOperationException($"'{modelId}' is not in the test catalog.");

    /// <inheritdoc />
    public Task PublishAsync(CkCompiledModelRoot ckCompiledModel, bool force = false, object? sourceIdentifier = null,
        CancellationToken? cancellationToken = null) =>
        throw new NotSupportedException("The test catalog is read-only.");

    /// <inheritdoc />
    public Task<CatalogUnpublishResult> UnpublishAsync(CkModelId modelId, string? reason = null,
        object? sourceIdentifier = null, CancellationToken? cancellationToken = null) =>
        throw new NotSupportedException("The test catalog is read-only.");

    /// <inheritdoc />
    public IAsyncEnumerable<CatalogResultItem> ListAsync(object? sourceIdentifier) => Empty();

    /// <inheritdoc />
    public IAsyncEnumerable<CatalogResultItem> SearchAsync(string searchTerm, object? sourceIdentifier) => Empty();

    private static async IAsyncEnumerable<CatalogResultItem> Empty([EnumeratorCancellation] CancellationToken _ = default)
    {
        await Task.CompletedTask;
        yield break;
    }
}
