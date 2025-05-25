using Microsoft.EntityFrameworkCore;
using PreSystem.StockControl.Application.Interfaces.Services;
using PreSystem.StockControl.Application.Services;
using PreSystem.StockControl.Domain.Interfaces.Repositories;
using PreSystem.StockControl.Infrastructure.Persistence;
using PreSystem.StockControl.Infrastructure.Repositories;
namespace PreSystem.StockControl.WebApi.Configurations
{
    public static class DependencyInjectionConfiguration
    {
        public static IServiceCollection AddProjectDependencies(this IServiceCollection services, IConfiguration configuration)
        {
            // 🔌 Configuração do DbContext com o SQL Server
            services.AddDbContext<StockControlDbContext>(options =>
            options.UseSqlServer(configuration.GetConnectionString("DefaultConnection")));


            // Repositórios
            services.AddScoped<IComponentRepository, ComponentRepository>();
            services.AddScoped<IProductRepository, ProductRepository>();
            services.AddScoped<IProductComponentRepository, ProductComponentRepository>();
            services.AddScoped<IStockMovementRepository, StockMovementRepository>();
            services.AddScoped<IStockAlertRepository, StockAlertRepository>();



            // Services
            services.AddScoped<IComponentService, ComponentService>();
            services.AddScoped<IProductService, ProductService>();
            services.AddScoped<IStockMovementService, StockMovementService>();
            services.AddScoped<IStockAlertService, StockAlertService>();



            return services;
        }
    }
}
