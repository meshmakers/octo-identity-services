namespace Meshmakers.Octo.Backend.IdentityServices.ViewModels.Shared;

public class SuccessViewModel
{
    public string Operation { get; set; } = null!;
    public string Text { get; set; } = null!;

    public string? NextStepLink { get; set; }
}
