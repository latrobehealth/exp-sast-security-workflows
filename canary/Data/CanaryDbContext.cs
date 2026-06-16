using Microsoft.EntityFrameworkCore;

namespace Sast.Canary.Data;

public sealed class CanaryDbContext : DbContext
{
    public CanaryDbContext(DbContextOptions<CanaryDbContext> options) : base(options) { }
    public DbSet<CanaryItem> Items => Set<CanaryItem>();
}

public sealed class CanaryItem
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
}
