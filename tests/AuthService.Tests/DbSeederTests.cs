using AuthService.Data;
using Xunit;

namespace AuthService.Tests;

public class DbSeederTests
{
    [Fact]
    public void DefaultRoles_ContainsExpectedRoles()
    {
        Assert.Contains("SuperAdmin", DbSeeder.DefaultRoles);
        Assert.Contains("Admin", DbSeeder.DefaultRoles);
        Assert.Contains("User", DbSeeder.DefaultRoles);
        Assert.Equal(3, DbSeeder.DefaultRoles.Length);
    }
}
