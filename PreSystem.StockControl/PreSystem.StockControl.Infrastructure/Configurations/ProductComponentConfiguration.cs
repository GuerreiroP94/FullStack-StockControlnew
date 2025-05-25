using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using PreSystem.StockControl.Domain.Entities;

namespace PreSystem.StockControl.Infrastructure.Configurations
{
    public class ProductComponentConfiguration : IEntityTypeConfiguration<ProductComponent>
    {
        public void Configure(EntityTypeBuilder<ProductComponent> builder)
        {
            // Define a chave primária composta (ProductId + ComponentId)
            builder.HasKey(pc => new { pc.ProductId, pc.ComponentId });

            // Relacionamento com Product (1 Product -> N ProductComponents)
            builder.HasOne(pc => pc.Product)
                .WithMany(p => p.ProductComponents)
                .HasForeignKey(pc => pc.ProductId);

            // Relacionamento com Component (1 Component -> N ProductComponents)
            builder.HasOne(pc => pc.Component)
                .WithMany(c => c.ProductComponents)
                .HasForeignKey(pc => pc.ComponentId);

            // Quantidade obrigatória para cada combinação de Produto + Componente
            builder.Property(pc => pc.Quantity).IsRequired();
        }
    }
}
