using AuthService.Mcp;
using Xunit;

namespace AuthService.Mcp.Tests;

public class TokenIssuerTests
{
    [Theory]
    [InlineData("/work/my-shop", "my-shop")]
    [InlineData("/work/my-shop/", "my-shop")]
    [InlineData("/work/My Shop", "My-Shop")]
    [InlineData("/work/\"quoted\"", "quoted")]
    public void Resolve_DefaultsToTheProjectDirectoryName_InCharactersTheSnippetsCanQuote(string targetPath, string expected)
    {
        Assert.Equal(expected, TokenIssuer.Resolve(null, targetPath));
    }

    [Fact]
    public void Resolve_FallsBack_WhenTheDirectoryNameHasNothingUsable()
    {
        Assert.Equal("authservice-consumer", TokenIssuer.Resolve(null, "/work/!!!"));
    }

    [Theory]
    [InlineData("MyShop")]
    [InlineData("https://shop.example")]
    public void Resolve_KeepsAnExplicitIssuer(string issuer)
    {
        Assert.Equal(issuer, TokenIssuer.Resolve(issuer, "/work/my-shop"));
    }

    [Theory]
    [InlineData("my shop")]
    [InlineData("a\"b")]
    [InlineData("")]
    public void Resolve_RejectsAnIssuerTheSnippetsWouldHaveToEscape(string issuer)
    {
        Assert.Throws<ArgumentException>(() => TokenIssuer.Resolve(issuer, "/work/my-shop"));
    }
}
