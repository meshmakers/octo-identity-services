using Duende.IdentityServer.Models;

#pragma warning disable 1591

namespace Meshmakers.Octo.Backend.IdentityServices.ViewModels.Shared;

public class ErrorViewModel
{
    public ErrorViewModel()
    {
    }
    
    public ErrorViewModel(string error)
    {
        Error = new ErrorMessage { Error = error };
    }

    public ErrorMessage? Error { get; set; }
}
