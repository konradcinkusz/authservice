using AuthService.Extensions;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace AuthService.Tests;

public class DatabaseProviderExtensionsTests
{
    private static IConfiguration BuildConfig(string? databaseProvider)
    {
        var data = new Dictionary<string, string?>();
        if (databaseProvider != null)
            data["DatabaseProvider"] = databaseProvider;

        return new ConfigurationBuilder()
            .AddInMemoryCollection(data)
            .Build();
    }

    [Fact]
    public void GetDatabaseProvider_DefaultsToPostgreSQL()
    {
        var config = BuildConfig(null);
        Assert.Equal(DatabaseProviderType.PostgreSQL, config.GetDatabaseProvider());
    }

    [Theory]
    [InlineData("SqlServer")]
    [InlineData("sqlserver")]
    [InlineData("MsSql")]
    public void GetDatabaseProvider_RecognizesSqlServer(string value)
    {
        var config = BuildConfig(value);
        Assert.Equal(DatabaseProviderType.SqlServer, config.GetDatabaseProvider());
    }

    [Fact]
    public void GetDatabaseProvider_UnknownValue_FallsBackToPostgreSQL()
    {
        var config = BuildConfig("something-else");
        Assert.Equal(DatabaseProviderType.PostgreSQL, config.GetDatabaseProvider());
    }
}
