using System.Text;
using IdentityModel;
using Microsoft.AspNetCore.Authentication;
using Newtonsoft.Json;

namespace Meshmakers.Octo.Backend.IdentityServices.ViewModels.Diagnostics;

public class DiagnosticsViewModel
{
    public DiagnosticsViewModel(AuthenticateResult? result)
    {
        AuthenticateResult = result;

        if (result?.Properties != null && result.Properties.Items.TryGetValue("client_list", out var item) && item != null)
        {
            var bytes = Base64Url.Decode(item);
            var value = Encoding.UTF8.GetString(bytes);

            Clients = JsonConvert.DeserializeObject<string[]>(value);
        }
    }

    public AuthenticateResult? AuthenticateResult { get; }

    public IEnumerable<string>? Clients { get; } = new List<string>();
}