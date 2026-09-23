using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace AuthService.Mcp;

public static class ReleasePinner
{
    private const string Releases = "https://api.github.com/repos/konradcinkusz/authservice/releases";

    private static readonly HttpClient Client = CreateClient();

    // README.md ("Releasing") warns against floating :latest — this is what lets the
    // integrate tool pin a real tag instead of relying on the caller to know one.
    public static async Task<string> GetLatestTagAsync()
    {
        try
        {
            // GitHub's latest release is the newest on either of this repository's release lines:
            // v* for the service image, and mcp-v* for this tool's own binaries (publish-mcp.yml).
            // Only a v* tag names an image, so an mcp-v* latest falls back to the newest v* release.
            var latest = await Client.GetFromJsonAsync<GitHubRelease>($"{Releases}/latest");
            if (latest is not null && IsServiceTag(latest.TagName))
                return latest.TagName;

            var releases = await Client.GetFromJsonAsync<GitHubRelease[]>($"{Releases}?per_page=100");
            return NewestServiceTag(releases ?? []) ?? "latest";
        }
        catch (Exception ex) when (ex is HttpRequestException or JsonException or TaskCanceledException)
        {
            return "latest";
        }
    }

    /// <summary>Whether <paramref name="tag"/> is a service release — <c>v</c> and a version — the form the image is tagged with.</summary>
    public static bool IsServiceTag(string? tag) =>
        tag is not null && tag.StartsWith('v') && Version.TryParse(tag[1..], out _);

    /// <summary>The highest published, non-prerelease service release among <paramref name="releases"/>, or null when there is none.</summary>
    public static string? NewestServiceTag(IEnumerable<GitHubRelease> releases) =>
        releases
            .Where(r => !r.Draft && !r.Prerelease && IsServiceTag(r.TagName))
            .OrderByDescending(r => Version.Parse(r.TagName[1..]))
            .Select(r => r.TagName)
            .FirstOrDefault();

    private static HttpClient CreateClient()
    {
        var client = new HttpClient();
        // The GitHub REST API rejects unauthenticated requests with no User-Agent.
        client.DefaultRequestHeaders.UserAgent.ParseAdd("AuthService.Mcp");
        client.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");
        return client;
    }

    public sealed record GitHubRelease(
        [property: JsonPropertyName("tag_name")] string TagName,
        [property: JsonPropertyName("draft")] bool Draft = false,
        [property: JsonPropertyName("prerelease")] bool Prerelease = false);
}
