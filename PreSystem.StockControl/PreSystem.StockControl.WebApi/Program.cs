using PreSystem.StockControl.Application.Interfaces.Services;
using PreSystem.StockControl.Application.Services;
using PreSystem.StockControl.Domain.Interfaces.Repositories;
using PreSystem.StockControl.Infrastructure.Repositories;
using PreSystem.StockControl.WebApi.Configurations;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using PreSystem.StockControl.Application.Validators;
using FluentValidation;
using FluentValidation.AspNetCore;

try
{
    Console.WriteLine("=== INICIANDO APLICAÇÃO ===");

    var builder = WebApplication.CreateBuilder(args);
    Console.WriteLine("✅ WebApplication.CreateBuilder OK");

    // CORREÇÃO 1: Carregar .env apenas em desenvolvimento
    if (builder.Environment.IsDevelopment())
    {
        Console.WriteLine("📁 Carregando arquivo .env (Development)");
        DotNetEnv.Env.Load();
    }
    else
    {
        Console.WriteLine("🌐 Modo Production - usando variáveis de ambiente");
    }

    // CORREÇÃO 2: Configuração de environment variables melhorada
    Console.WriteLine("⚙️ Configurando variáveis de ambiente...");
    builder.Configuration.AddInMemoryCollection(new Dictionary<string, string?>
    {
        ["EmailSettings:SmtpUser"] = Environment.GetEnvironmentVariable("EMAIL_SMTP_USER"),
        ["EmailSettings:SmtpPassword"] = Environment.GetEnvironmentVariable("EMAIL_SMTP_PASSWORD"),
        ["EmailSettings:FromEmail"] = Environment.GetEnvironmentVariable("EMAIL_FROM"),
        ["FrontendUrl"] = Environment.GetEnvironmentVariable("FRONTEND_URL") ?? "http://localhost:3000"
    });
    Console.WriteLine("✅ Variáveis de ambiente configuradas");

    // CORREÇÃO 3: Connection String dinâmica para Railway
    var databaseUrl = Environment.GetEnvironmentVariable("DATABASE_URL");
    var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");

    Console.WriteLine($"🗄️ DATABASE_URL env: {(string.IsNullOrEmpty(databaseUrl) ? "VAZIA" : "CONFIGURADA")}");
    Console.WriteLine($"🗄️ ConnectionString config: {(string.IsNullOrEmpty(connectionString) ? "VAZIA" : "CONFIGURADA")}");

    if (!string.IsNullOrEmpty(databaseUrl))
    {
        builder.Configuration["ConnectionStrings:DefaultConnection"] = databaseUrl;
        Console.WriteLine("✅ DATABASE_URL aplicada à ConnectionString");
    }

    // CORREÇÃO 4: JWT Secret dinâmico
    var jwtSecretEnv = Environment.GetEnvironmentVariable("JWT_SECRET");
    Console.WriteLine($"🔐 JWT_SECRET env: {(string.IsNullOrEmpty(jwtSecretEnv) ? "VAZIA" : "CONFIGURADA")}");

    if (!string.IsNullOrEmpty(jwtSecretEnv))
    {
        builder.Configuration["JwtSettings:Secret"] = jwtSecretEnv;
        Console.WriteLine("✅ JWT_SECRET aplicado");
    }

    // Registro de dependências da aplicação
    Console.WriteLine("🔧 Registrando dependências...");
    builder.Services.AddScoped<IComponentRepository, ComponentRepository>();
    builder.Services.AddScoped<IComponentService, ComponentService>();
    builder.Services.AddHttpContextAccessor();
    builder.Services.AddScoped<IUserContextService, UserContextService>();
    builder.Services.AddScoped<IUserRepository, UserRepository>();
    builder.Services.AddScoped<IUserService, UserService>();
    builder.Services.AddScoped<IPasswordResetTokenRepository, PasswordResetTokenRepository>();
    builder.Services.AddScoped<IEmailService, EmailService>();
    Console.WriteLine("✅ Dependências registradas");

    // CORREÇÃO 5: CORS dinâmico para produção
    Console.WriteLine("🌍 Configurando CORS...");
    builder.Services.AddCors(options =>
    {
        options.AddPolicy("AllowFrontend", corsBuilder =>
        {
            var frontendUrl = Environment.GetEnvironmentVariable("FRONTEND_URL") ?? "http://localhost:3000";
            var allowedOrigins = new List<string>
            {
                "http://localhost:3000",
                "http://localhost:5173",
                frontendUrl
            };

            if (builder.Environment.IsProduction())
            {
                allowedOrigins.Add("https://*.pages.dev");
                allowedOrigins.Add("https://*.workers.dev");
            }

            corsBuilder.WithOrigins(allowedOrigins.ToArray())
                .AllowAnyHeader()
                .AllowAnyMethod()
                .AllowCredentials();
        });
    });
    Console.WriteLine("✅ CORS configurado");

    // Serviços padrões da aplicação
    Console.WriteLine("📦 Adicionando dependências do projeto...");
    builder.Services.AddProjectDependencies(builder.Configuration);
    Console.WriteLine("✅ Dependências do projeto adicionadas");

    builder.Services.AddControllers();
    Console.WriteLine("✅ Controllers adicionados");

    Console.WriteLine("✔️ Adicionando validadores...");
    builder.Services.AddValidatorsFromAssemblyContaining<ProductCreateDtoValidator>();
    builder.Services.AddFluentValidationAutoValidation();
    Console.WriteLine("✅ Validadores adicionados");

    // Documentação da API com Swagger
    Console.WriteLine("📚 Configurando Swagger...");
    builder.Services.AddEndpointsApiExplorer();
    builder.Services.AddSwaggerGen(c =>
    {
        c.SwaggerDoc("v1", new() { Title = "PreSystem.StockControl", Version = "v1" });

        c.AddSecurityDefinition("Bearer", new Microsoft.OpenApi.Models.OpenApiSecurityScheme
        {
            Description = @"JWT Authorization header usando o esquema Bearer. 
Digite assim: 'Bearer {seu token}' (sem aspas)",
            Name = "Authorization",
            In = Microsoft.OpenApi.Models.ParameterLocation.Header,
            Type = Microsoft.OpenApi.Models.SecuritySchemeType.ApiKey,
            Scheme = "Bearer"
        });

        c.AddSecurityRequirement(new Microsoft.OpenApi.Models.OpenApiSecurityRequirement()
        {
            {
                new Microsoft.OpenApi.Models.OpenApiSecurityScheme
                {
                    Reference = new Microsoft.OpenApi.Models.OpenApiReference
                    {
                        Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme,
                        Id = "Bearer"
                    },
                    Scheme = "oauth2",
                    Name = "Bearer",
                    In = Microsoft.OpenApi.Models.ParameterLocation.Header,
                },
                new List<string>()
            }
        });
    });
    Console.WriteLine("✅ Swagger configurado");

    // Configuração JWT
    Console.WriteLine("🔐 Configurando JWT...");
    var jwtSettings = builder.Configuration.GetSection("JwtSettings");
    var secretKey = jwtSettings.GetValue<string>("Secret");

    Console.WriteLine($"🔐 JWT Secret recuperado: {(string.IsNullOrEmpty(secretKey) ? "VAZIO" : "OK")}");

    if (string.IsNullOrEmpty(secretKey))
    {
        Console.WriteLine("❌ ERRO: JWT Secret Key está vazia!");
        throw new InvalidOperationException("JWT Secret Key is missing in configuration");
    }

    var key = Encoding.ASCII.GetBytes(secretKey);

    builder.Services.AddAuthentication(options =>
    {
        options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    })
    .AddJwtBearer(options =>
    {
        options.RequireHttpsMetadata = builder.Environment.IsProduction();
        options.SaveToken = true;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(key),
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidIssuer = jwtSettings.GetValue<string>("Issuer"),
            ValidAudience = jwtSettings.GetValue<string>("Audience")
        };
    });
    Console.WriteLine("✅ JWT configurado");

    Console.WriteLine("🏗️ Construindo aplicação...");
    var app = builder.Build();
    Console.WriteLine("✅ Aplicação construída");

    // CORREÇÃO 7: Swagger apenas em desenvolvimento
    if (app.Environment.IsDevelopment())
    {
        Console.WriteLine("📚 Habilitando Swagger (Development)");
        app.UseSwagger();
        app.UseSwaggerUI();
    }

    Console.WriteLine("🌍 Aplicando CORS...");
    app.UseCors("AllowFrontend");

    // CORREÇÃO 8: HTTPS redirection apenas em produção
    if (app.Environment.IsProduction())
    {
        Console.WriteLine("🔒 Habilitando HTTPS Redirection (Production)");
        app.UseHttpsRedirection();
    }

    Console.WriteLine("🔐 Aplicando Authentication...");
    app.UseAuthentication();
    Console.WriteLine("🛡️ Aplicando Authorization...");
    app.UseAuthorization();

    Console.WriteLine("🎯 Mapeando Controllers...");
    app.MapControllers();

    // CORREÇÃO 9: PORT dinâmica para Railway
    var port = Environment.GetEnvironmentVariable("PORT") ?? "5123";
    var url = $"http://0.0.0.0:{port}";

    Console.WriteLine($"🚀 Starting server on {url}");
    Console.WriteLine($"🌍 Environment: {app.Environment.EnvironmentName}");
    Console.WriteLine($"🔗 Frontend URL: {Environment.GetEnvironmentVariable("FRONTEND_URL") ?? "http://localhost:3000"}");
    Console.WriteLine("=== APLICAÇÃO INICIADA COM SUCESSO ===");

    app.Run(url);
}
catch (Exception ex)
{
    Console.WriteLine("💥 ERRO FATAL NA APLICAÇÃO:");
    Console.WriteLine($"Tipo: {ex.GetType().Name}");
    Console.WriteLine($"Mensagem: {ex.Message}");
    Console.WriteLine($"StackTrace: {ex.StackTrace}");

    if (ex.InnerException != null)
    {
        Console.WriteLine($"InnerException: {ex.InnerException.Message}");
    }

    throw;
}