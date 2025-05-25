using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Configuration;
using PreSystem.StockControl.Infrastructure.Persistence;




namespace PreSystem.StockControl.Infrastructure
{
    // Essa fábrica permite que o EF Core crie instâncias do contexto no momento de design (ex: migration)
    public class StockControlDbContextFactory : IDesignTimeDbContextFactory<StockControlDbContext>
    {
        public StockControlDbContext CreateDbContext(string[] args)
        {
            // Caminho para o appsettings.json
            var configuration = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json")
                .Build();

            // Pega a connection string
            var connectionString = configuration.GetConnectionString("DefaultConnection");

            var optionsBuilder = new DbContextOptionsBuilder<StockControlDbContext>();
            optionsBuilder.UseSqlServer(connectionString);

            return new StockControlDbContext(optionsBuilder.Options);
        }
    }
}
