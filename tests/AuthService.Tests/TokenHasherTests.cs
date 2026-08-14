using AuthService.Services;
using Xunit;

namespace AuthService.Tests;

public class TokenHasherTests
{
    [Fact]
    public void Hash_is_deterministic()
    {
        const string token = "a-refresh-token-value";

        Assert.Equal(TokenHasher.Hash(token), TokenHasher.Hash(token));
    }

    [Fact]
    public void Hash_differs_for_different_tokens()
    {
        Assert.NotEqual(TokenHasher.Hash("token-a"), TokenHasher.Hash("token-b"));
    }

    [Fact]
    public void Hash_does_not_contain_the_original_token()
    {
        const string token = "sensitive-token";

        Assert.DoesNotContain(token, TokenHasher.Hash(token));
    }

    [Fact]
    public void Hash_fits_the_persisted_column()
    {
        // TokenHash is mapped as nvarchar(64); Base64 of SHA-256 is 44 characters.
        Assert.Equal(44, TokenHasher.Hash("anything").Length);
    }

    [Theory]
    [InlineData(16)]
    [InlineData(32)]
    [InlineData(64)]
    public void Generated_tokens_are_url_safe_and_unique(int byteLength)
    {
        var first = TokenHasher.GenerateUrlSafeToken(byteLength);
        var second = TokenHasher.GenerateUrlSafeToken(byteLength);

        Assert.NotEqual(first, second);
        Assert.DoesNotContain('+', first);
        Assert.DoesNotContain('/', first);
        Assert.DoesNotContain('=', first);
    }
}
