using IdentityServerPersistence.Services.FileRoles;
using Microsoft.Extensions.DependencyInjection;

namespace IdentityServices.IntegrationTests.Fixtures;

/// <summary>
///     The identity fixture with a probe that reports System.Files as present in every tenant (AB#6467), so the
///     tenant-setup path of the pipeline service account grant is exercised without importing the model.
/// </summary>
public class IdentityServicesWithFilesModelFixture : IdentityServicesFixture
{
    public IdentityServicesWithFilesModelFixture()
    {
        Services.AddSingleton<IFilesModelProbe>(new AlwaysPresentProbe());
    }

    private sealed class AlwaysPresentProbe : IFilesModelProbe
    {
        public bool HasFilesModel(string tenantId) => true;
    }
}
