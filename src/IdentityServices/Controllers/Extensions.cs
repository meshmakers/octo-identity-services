using System;
using Duende.IdentityServer.Models;
using Meshmakers.Octo.Backend.IdentityServices.ViewModels.Account;
using Microsoft.AspNetCore.Mvc;

namespace Meshmakers.Octo.Backend.IdentityServices.Controllers;

/// <summary>
///     Internal used extensions
/// </summary>
internal static class Extensions
{
    // /// <summary>
    // /// Determines whether the client is configured to use PKCE.
    // /// </summary>
    // /// <param name="store">The store.</param>
    // /// <param name="client_id">The client identifier.</param>
    // /// <returns></returns>
    // public static async Task<bool> IsPkceClientAsync(this IClientStore store, string client_id)
    // {
    //     if (!string.IsNullOrWhiteSpace(client_id))
    //     {
    //         var client = await store.FindEnabledClientByIdAsync(client_id);
    //         return client?.RequirePkce == true;
    //     }
    //
    //     return false;
    // }

    /// <summary>
    ///     Checks if the redirect URI is for a native client.
    /// </summary>
    /// <returns></returns>
    public static bool IsNativeClient(this AuthorizationRequest context)
    {
        return !context.RedirectUri.StartsWith("https", StringComparison.Ordinal)
               && !context.RedirectUri.StartsWith("http", StringComparison.Ordinal);
    }

    public static IActionResult LoadingPage(this Controller controller, string viewName, string? redirectUri)
    {
        controller.HttpContext.Response.StatusCode = 200;
        controller.HttpContext.Response.Headers["Location"] = "";

        return controller.View(viewName, new RedirectViewModel { RedirectUrl = redirectUri });
    }
}
