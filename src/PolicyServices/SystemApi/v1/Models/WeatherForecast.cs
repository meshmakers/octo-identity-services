namespace Meshmakers.Octo.Backend.PolicyServices.SystemApi.v1.Models;

/// <summary>
/// </summary>
public class WeatherForecast
{
    /// <summary>
    /// </summary>
    public WeatherForecast()
    {
    }

    /// <summary>
    /// </summary>
    public DateTime Date { get; set; }

    /// <summary>
    /// </summary>
    public int TemperatureC { get; set; }

    /// <summary>
    /// </summary>
    public int TemperatureF => 32 + (int)(TemperatureC / 0.5556);

    /// <summary>
    /// </summary>
    public string? Summary { get; set; }
}