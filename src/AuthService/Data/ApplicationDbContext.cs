using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using AuthService.Models;

namespace AuthService.Data;

public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }

    public DbSet<Organization> Organizations => Set<Organization>();
    public DbSet<OrganizationMembership> OrganizationMemberships => Set<OrganizationMembership>();
    public DbSet<OrganizationInvitation> OrganizationInvitations => Set<OrganizationInvitation>();
    public DbSet<InvitationEmailAttempt> InvitationEmailAttempts => Set<InvitationEmailAttempt>();
    public DbSet<RefreshToken> RefreshTokens => Set<RefreshToken>();
    public DbSet<UserConsent> UserConsents => Set<UserConsent>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        // Detect provider for conditional filtered index syntax
        var isSqlServer = Database.ProviderName == "Microsoft.EntityFrameworkCore.SqlServer";

        // Organization
        builder.Entity<Organization>(entity =>
        {
            entity.HasKey(o => o.Id);
            entity.Property(o => o.Name).IsRequired().HasMaxLength(200);
            entity.HasIndex(o => o.Name);

            // Soft delete configuration — filtered indexes are provider-specific
            entity.HasIndex(o => o.IsDeleted);
            var deletionIndex = entity.HasIndex(o => o.ScheduledPermanentDeletionAt);
            if (isSqlServer) deletionIndex.HasFilter("[IsDeleted] = 1");
            else deletionIndex.HasFilter("\"IsDeleted\" = true");

            // Global query filter to exclude deleted organizations
            entity.HasQueryFilter(o => !o.IsDeleted);
        });

        // OrganizationMembership
        builder.Entity<OrganizationMembership>(entity =>
        {
            entity.HasKey(om => om.Id);
            entity.HasIndex(om => new { om.UserId, om.OrganizationId }).IsUnique();

            entity.HasOne(om => om.User)
                .WithMany(u => u.OrganizationMemberships)
                .HasForeignKey(om => om.UserId)
                .OnDelete(DeleteBehavior.Cascade);

            entity.HasOne(om => om.Organization)
                .WithMany(o => o.Members)
                .HasForeignKey(om => om.OrganizationId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        // OrganizationInvitation
        builder.Entity<OrganizationInvitation>(entity =>
        {
            entity.HasKey(oi => oi.Id);
            entity.Property(oi => oi.Email).IsRequired().HasMaxLength(256);
            entity.HasIndex(oi => oi.Token).IsUnique();
            entity.HasIndex(oi => new { oi.OrganizationId, oi.Email });
            entity.HasIndex(oi => oi.NextRetryAt);

            entity.HasOne(oi => oi.Organization)
                .WithMany()
                .HasForeignKey(oi => oi.OrganizationId)
                .OnDelete(DeleteBehavior.Cascade);

            entity.HasMany(oi => oi.EmailAttempts)
                .WithOne(ea => ea.Invitation)
                .HasForeignKey(ea => ea.InvitationId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        // InvitationEmailAttempt
        builder.Entity<InvitationEmailAttempt>(entity =>
        {
            entity.HasKey(ea => ea.Id);
            entity.HasIndex(ea => new { ea.InvitationId, ea.AttemptedAt });
        });

        // RefreshToken
        builder.Entity<RefreshToken>(entity =>
        {
            entity.HasKey(rt => rt.Id);
            entity.HasIndex(rt => rt.Token).IsUnique();
            entity.HasIndex(rt => new { rt.UserId, rt.IsRevoked });

            entity.HasOne(rt => rt.User)
                .WithMany()
                .HasForeignKey(rt => rt.UserId)
                .OnDelete(DeleteBehavior.Cascade);
        });

        // UserConsent
        builder.Entity<UserConsent>(entity =>
        {
            entity.HasKey(c => c.Id);
            entity.Property(c => c.UserId).IsRequired().HasMaxLength(450);
            entity.Property(c => c.Version).IsRequired().HasMaxLength(50);
            entity.Property(c => c.IpAddress).HasMaxLength(64);
            entity.Property(c => c.UserAgent).HasMaxLength(512);
            entity.Property(c => c.Locale).HasMaxLength(16);

            entity.HasIndex(c => new { c.UserId, c.Type, c.AcceptedAt });
            entity.HasIndex(c => new { c.UserId, c.Type, c.Version });

            entity.HasOne(c => c.User)
                .WithMany()
                .HasForeignKey(c => c.UserId)
                .OnDelete(DeleteBehavior.Cascade);
        });
    }
}
