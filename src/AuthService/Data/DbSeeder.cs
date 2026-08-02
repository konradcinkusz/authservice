using Microsoft.AspNetCore.Identity;
using AuthService.Models;

namespace AuthService.Data;

/// <summary>
/// Seeds identity roles and an optional initial SuperAdmin account from configuration.
/// Does not create any demo users, organizations, or other sample data — bring your own.
/// </summary>
public static class DbSeeder
{
    public static readonly string[] DefaultRoles = { "SuperAdmin", "Admin", "User" };

    public static async Task SeedAsync(IServiceProvider serviceProvider)
    {
        var userManager = serviceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var roleManager = serviceProvider.GetRequiredService<RoleManager<IdentityRole>>();
        var logger = serviceProvider.GetRequiredService<ILogger<Program>>();
        var configuration = serviceProvider.GetRequiredService<IConfiguration>();

        try
        {
            await SeedRolesAsync(roleManager, logger);

            // Seed initial SuperAdmin from configuration (all environments).
            // Set InitialAdmin:Email and InitialAdmin:Password via environment variables or user-secrets.
            // Skipped automatically once any SuperAdmin already exists.
            await SeedInitialAdminAsync(userManager, configuration, logger);

            logger.LogInformation("Database seeding completed successfully");
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "An error occurred while seeding the database");
            throw;
        }
    }

    /// <summary>
    /// Creates the initial SuperAdmin account from configuration when no SuperAdmin exists yet.
    /// Idempotent — skipped on subsequent startups once the account has been created.
    /// </summary>
    public static async Task SeedInitialAdminAsync(
        UserManager<ApplicationUser> userManager,
        IConfiguration configuration,
        ILogger logger)
    {
        var email = configuration["InitialAdmin:Email"];
        var password = configuration["InitialAdmin:Password"];

        if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password))
            return;

        // Skip if any SuperAdmin already exists — avoids re-running on every restart
        var existingSuperAdmins = await userManager.GetUsersInRoleAsync("SuperAdmin");
        if (existingSuperAdmins.Count > 0)
        {
            logger.LogInformation("SuperAdmin already exists — skipping InitialAdmin seeding");
            return;
        }

        var existing = await userManager.FindByEmailAsync(email);
        if (existing != null)
        {
            // Account exists but has no SuperAdmin role yet — promote it
            await userManager.AddToRoleAsync(existing, "SuperAdmin");
            logger.LogInformation("Promoted existing user {Email} to SuperAdmin via InitialAdmin config", email);
            return;
        }

        var user = new ApplicationUser
        {
            UserName = email.Split('@')[0].Replace(".", "").Replace("+", ""),
            Email = email,
            EmailConfirmed = true,
            CreatedAt = DateTime.UtcNow,
        };

        var result = await userManager.CreateAsync(user, password);
        if (!result.Succeeded)
        {
            var errors = string.Join(", ", result.Errors.Select(e => e.Description));
            logger.LogError("Failed to create InitialAdmin {Email}: {Errors}", email, errors);
            return;
        }

        await userManager.AddToRoleAsync(user, "SuperAdmin");
        logger.LogInformation("Created InitialAdmin SuperAdmin account for {Email}", email);
    }

    private static async Task SeedRolesAsync(RoleManager<IdentityRole> roleManager, ILogger logger)
    {
        foreach (var roleName in DefaultRoles)
        {
            if (!await roleManager.RoleExistsAsync(roleName))
            {
                var result = await roleManager.CreateAsync(new IdentityRole(roleName));
                if (result.Succeeded)
                {
                    logger.LogInformation("Created role: {RoleName}", roleName);
                }
                else
                {
                    logger.LogError("Failed to create role: {RoleName}. Errors: {Errors}",
                        roleName, string.Join(", ", result.Errors.Select(e => e.Description)));
                }
            }
        }
    }
}
