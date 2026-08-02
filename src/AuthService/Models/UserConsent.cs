using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Text.Json.Serialization;

namespace AuthService.Models;

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum ConsentType
{
    Terms = 0,
    Privacy = 1,
    Cookies = 2
}

/// <summary>
/// Records a user's acceptance (or rejection) of a versioned legal document
/// such as the Terms of Use, Privacy Policy, or Cookie Policy. Retained to
/// satisfy GDPR-style accountability requirements.
/// </summary>
public class UserConsent
{
    public Guid Id { get; set; } = Guid.NewGuid();

    [Required]
    [MaxLength(450)]
    public string UserId { get; set; } = string.Empty;

    public ConsentType Type { get; set; }

    /// <summary>Version string of the document accepted (e.g. "2026-04-19").</summary>
    [Required]
    [MaxLength(50)]
    public string Version { get; set; } = string.Empty;

    public bool Accepted { get; set; }

    public DateTime AcceptedAt { get; set; } = DateTime.UtcNow;

    [MaxLength(64)]
    public string? IpAddress { get; set; }

    [MaxLength(512)]
    public string? UserAgent { get; set; }

    [MaxLength(16)]
    public string? Locale { get; set; }

    /// <summary>
    /// JSON-encoded cookie category preferences (only meaningful when <see cref="Type"/> is <see cref="ConsentType.Cookies"/>).
    /// Example: {"necessary":true,"preferences":true,"analytics":false,"thirdParty":false}
    /// </summary>
    public string? CookieCategories { get; set; }

    [ForeignKey(nameof(UserId))]
    public ApplicationUser? User { get; set; }
}
