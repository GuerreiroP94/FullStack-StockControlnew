using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using PreSystem.StockControl.Domain.Entities;

namespace PreSystem.StockControl.Infrastructure.Configurations
{
    // Configurações da entidade StockMovement para o Entity Framework
    public class StockMovementConfiguration : IEntityTypeConfiguration<StockMovement>
    {
        public void Configure(EntityTypeBuilder<StockMovement> builder)
        {
            // Define a chave primária
            builder.HasKey(sm => sm.Id);

            // Relação com Component (1 Componente -> N Movimentações)
            builder.HasOne(sm => sm.Component)
                   .WithMany() // Sem necessidade de navegação reversa
                   .HasForeignKey(sm => sm.ComponentId)
                   .OnDelete(DeleteBehavior.Cascade);

            // Campos obrigatórios
            builder.Property(sm => sm.MovementType)
                   .IsRequired()
                   .HasMaxLength(100);

            builder.Property(sm => sm.PerformedBy)
                   .IsRequired()
                   .HasMaxLength(100);

            builder.Property(sm => sm.QuantityChanged)
                   .IsRequired();

            builder.Property(sm => sm.PerformedAt)
                   .IsRequired();
        }
    }
}
