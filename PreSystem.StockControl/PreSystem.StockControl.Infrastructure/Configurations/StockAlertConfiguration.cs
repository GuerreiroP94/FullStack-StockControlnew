using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using PreSystem.StockControl.Domain.Entities;

namespace PreSystem.StockControl.Infrastructure.Configurations
{
    public class StockAlertConfiguration : IEntityTypeConfiguration<StockAlert>
    {
        public void Configure(EntityTypeBuilder<StockAlert> builder)
        {
            builder.HasKey(a => a.Id);

            builder.Property(a => a.Message)
                   .IsRequired()
                   .HasMaxLength(255);

            builder.HasOne(a => a.Component)
                   .WithMany(c => c.StockAlerts)
                   .HasForeignKey(a => a.ComponentId);
        }
    }
}
