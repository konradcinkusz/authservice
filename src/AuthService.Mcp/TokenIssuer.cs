using System.Text.RegularExpressions;

namespace AuthService.Mcp;

public static partial class TokenIssuer
{
    private const string Fallback = "authservice-consumer";

    // docs/DEPLOYMENT.md: two products left on authservice's default issuer and audience would
    // accept each other's tokens, so each project gets its own. The value is quoted into C#,
    // JavaScript and Python by JwtConfigGenerator, so it is kept to characters none of them
    // needs escaped.
    public static string Resolve(string? issuer, string targetPath)
    {
        if (issuer is not null)
        {
            issuer = issuer.Trim();
            if (!Allowed().IsMatch(issuer))
            {
                throw new ArgumentException(
                    $"issuer '{issuer}' may contain only letters, digits and . _ : / -", nameof(issuer));
            }

            return issuer;
        }

        var name = Path.GetFileName(Path.TrimEndingDirectorySeparator(targetPath));
        name = Disallowed().Replace(name, "-").Trim('-', '.');
        return name.Length > 0 ? name : Fallback;
    }

    [GeneratedRegex("^[A-Za-z0-9._:/-]+$")]
    private static partial Regex Allowed();

    [GeneratedRegex("[^A-Za-z0-9._-]+")]
    private static partial Regex Disallowed();
}
