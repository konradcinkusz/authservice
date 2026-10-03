using Microsoft.AspNetCore.Identity;

namespace AuthService.Tests.Infrastructure;

internal static class IdentityResultExtensions
{
    /// <summary>For test setup, where an Identity failure is a broken fixture rather than a result to assert.</summary>
    public static void ThrowIfFailed(this IdentityResult result)
    {
        if (!result.Succeeded)
            throw new InvalidOperationException(string.Join("; ", result.Errors.Select(e => e.Description)));
    }
}
