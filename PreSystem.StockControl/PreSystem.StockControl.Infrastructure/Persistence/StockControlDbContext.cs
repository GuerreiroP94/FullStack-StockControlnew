namespace PreSystem.StockControl.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using PreSystem.StockControl.Domain.Entities;

public class StockControlDbContext : DbContext
{
    public StockControlDbContext(DbContextOptions<StockControlDbContext> options)
        : base(options)
    {
    }

    public DbSet<Component> Components { get; set; }
    public DbSet<Product> Products { get; set; }
    public DbSet<ProductComponent> ProductComponents { get; set; }
    public DbSet<StockMovement> StockMovements { get; set; }
    public DbSet<StockAlert> StockAlerts { get; set; }
    public DbSet<User> Users { get; set; }



    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        modelBuilder.ApplyConfigurationsFromAssembly(typeof(StockControlDbContext).Assembly);
    }
}
