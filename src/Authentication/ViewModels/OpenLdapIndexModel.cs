using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace Meshmakers.Octo.Backend.Authentication.ViewModels;

public class OpenLdapIndexModel
{
    [BindRequired]
    [FromQuery(Name = ".redirect")]
    public string RedirectUri { get; set; } = null!;

    [BindRequired]
    [FromQuery(Name = "LoginProvider")]
    public string LoginProvider { get; set; } = null!;

    [FromQuery] public string? XsrfId { get; set; }
}