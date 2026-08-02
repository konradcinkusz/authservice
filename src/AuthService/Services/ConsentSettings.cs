namespace AuthService.Services;

/// <summary>
/// Configured versions of the legal documents that users must accept.
/// Bumping any version forces existing users through the consent gate.
/// </summary>
public class ConsentSettings
{
    public const string SectionName = "ConsentVersions";

    /// <summary>Current Terms of Use version (e.g. "2026-01-01").</summary>
    public string Terms { get; set; } = "2026-01-01";

    /// <summary>Current Privacy Policy version.</summary>
    public string Privacy { get; set; } = "2026-01-01";

    /// <summary>Current Cookie Policy version.</summary>
    public string Cookies { get; set; } = "2026-01-01";
}
