using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace AuthService.Mcp;

public static class ReleasePinner
{
    private static readonly HttpClient Client = CreateClient();

    // README.md ("Releasing") warns against floating :latest — this is what lets the
    // integrate tool pin a real tag instead of relying on the caller to know one.
    public static async Task<string> GetLatestTagAsync()
    {
        try
        {
            var release = await Client.GetFromJsonAsync<GitHubRelease>(
                "https://api.github.com/repos/konradcinkusz/authservice/releases/latest");
            return release?.TagName ?? "latest";
        }
        catch (Exception ex) when (ex is HttpRequestException or JsonException or TaskCanceledException)
        {
            return "latest";
        }
    }

    private static HttpClient CreateClient()
    {
        var client = new HttpClient();
        // The GitHub REST API rejects unauthenticated requests with no User-Agent.
        client.DefaultRequestHeaders.UserAgent.ParseAdd("AuthService.Mcp");
        client.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");
        return client;
    }

    private sealed record GitHubRelease([property: JsonPropertyName("tag_name")] string TagName);
}
