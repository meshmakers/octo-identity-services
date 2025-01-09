using Duende.IdentityServer.Models;

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