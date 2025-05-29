using CsvHelper;
using CsvHelper.Configuration;
using Microsoft.Extensions.Logging;
using PreSystem.StockControl.Application.DTOs;
using PreSystem.StockControl.Application.DTOs.Filters;
using PreSystem.StockControl.Application.Interfaces.Services;
using PreSystem.StockControl.Domain.Entities;
using PreSystem.StockControl.Domain.Interfaces.Repositories;
using System.Formats.Asn1;
using System.Globalization;

namespace PreSystem.StockControl.Application.Services
{
    // Serviço responsável pelas regras de negócio dos Componentes
    public class ComponentService : IComponentService
    {
        private readonly IComponentRepository _componentRepository;
        private readonly ILogger<ComponentService> _logger;

        public ComponentService(IComponentRepository componentRepository, ILogger<ComponentService> logger)
        {
            _componentRepository = componentRepository;
            _logger = logger;
        }

        // Adiciona um novo componente com base nos dados do DTO
        public async Task<ComponentDto> AddComponentAsync(ComponentCreateDto dto)
        {
            var component = new Component
            {
                Name = dto.Name,
                Description = dto.Description,
                Group = dto.Group,
                Device = dto.Device,
                Value = dto.Value,
                Package = dto.Package,
                Characteristics = dto.Characteristics,
                InternalCode = dto.InternalCode,
                Price = dto.Price,
                Environment = dto.Environment,
                Drawer = dto.Drawer,
                Division = dto.Division,
                NCM = dto.NCM,
                NVE = dto.NVE,
                QuantityInStock = dto.QuantityInStock,
                MinimumQuantity = dto.MinimumQuantity,
                CreatedAt = DateTime.UtcNow,
                UpdatedAt = DateTime.UtcNow
            };

            await _componentRepository.AddAsync(component);

            _logger.LogInformation("Componente criado: {Nome}, Grupo: {Grupo}, Device: {Device}, Quantidade: {Quantidade}",
                component.Name, component.Group, component.Device, component.QuantityInStock);

            return MapToDto(component);
        }

        // Retorna todos os componentes como uma lista de DTOs
        public async Task<IEnumerable<ComponentDto>> GetAllComponentsAsync(ComponentFilterDto filter)
        {
            var query = await _componentRepository.GetAllAsync();

            // Aplica filtros se existirem
            if (!string.IsNullOrWhiteSpace(filter.Name))
                query = query.Where(c => c.Name.Contains(filter.Name, StringComparison.OrdinalIgnoreCase));

            if (!string.IsNullOrWhiteSpace(filter.Group))
                query = query.Where(c => c.Group.Contains(filter.Group, StringComparison.OrdinalIgnoreCase));

            if (!string.IsNullOrWhiteSpace(filter.Device))
                query = query.Where(c => c.Device != null && c.Device.Contains(filter.Device, StringComparison.OrdinalIgnoreCase));

            if (!string.IsNullOrWhiteSpace(filter.Package))
                query = query.Where(c => c.Package != null && c.Package.Contains(filter.Package, StringComparison.OrdinalIgnoreCase));

            if (!string.IsNullOrWhiteSpace(filter.Value))
                query = query.Where(c => c.Value != null && c.Value.Contains(filter.Value, StringComparison.OrdinalIgnoreCase));

            if (!string.IsNullOrWhiteSpace(filter.SearchTerm))
            {
                query = query.Where(c =>
                    c.Name.Contains(filter.SearchTerm, StringComparison.OrdinalIgnoreCase) ||
                    (c.Description != null && c.Description.Contains(filter.SearchTerm, StringComparison.OrdinalIgnoreCase)) ||
                    (c.InternalCode != null && c.InternalCode.Contains(filter.SearchTerm, StringComparison.OrdinalIgnoreCase)) ||
                    (c.Device != null && c.Device.Contains(filter.SearchTerm, StringComparison.OrdinalIgnoreCase)) ||
                    (c.Value != null && c.Value.Contains(filter.SearchTerm, StringComparison.OrdinalIgnoreCase))
                );
            }

            // Aplica paginação
            query = query
                .Skip((filter.PageNumber - 1) * filter.PageSize)
                .Take(filter.PageSize);

            return query.Select(MapToDto);
        }

        // Retorna um único componente pelo ID como DTO
        public async Task<ComponentDto?> GetComponentByIdAsync(int id)
        {
            var component = await _componentRepository.GetByIdAsync(id);
            return component == null ? null : MapToDto(component);
        }

        // Atualiza um componente existente
        public async Task<ComponentDto?> UpdateComponentAsync(int id, ComponentCreateDto dto)
        {
            var component = await _componentRepository.GetByIdAsync(id);
            if (component == null) return null;

            // Atualiza os dados
            component.Name = dto.Name;
            component.Description = dto.Description;
            component.Group = dto.Group;
            component.Device = dto.Device;
            component.Value = dto.Value;
            component.Package = dto.Package;
            component.Characteristics = dto.Characteristics;
            component.InternalCode = dto.InternalCode;
            component.Price = dto.Price;
            component.Environment = dto.Environment;
            component.Drawer = dto.Drawer;
            component.Division = dto.Division;
            component.NCM = dto.NCM;
            component.NVE = dto.NVE;
            component.QuantityInStock = dto.QuantityInStock;
            component.MinimumQuantity = dto.MinimumQuantity;
            component.UpdatedAt = DateTime.UtcNow;

            await _componentRepository.UpdateAsync(component);

            _logger.LogInformation("Componente atualizado: {Id}, Nome: {Nome}, Quantidade: {Quantidade}",
                component.Id, component.Name, component.QuantityInStock);

            return MapToDto(component);
        }

        // Remove um componente com base no ID
        public async Task<bool> DeleteComponentAsync(int id)
        {
            var component = await _componentRepository.GetByIdAsync(id);
            if (component == null)
            {
                _logger.LogWarning("Tentativa de deletar componente inexistente: ID {Id}", id);
                return false;
            }

            await _componentRepository.DeleteAsync(component);
            _logger.LogInformation("Componente deletado: {Id} - {Nome}", component.Id, component.Name);
            return true;
        }

        // Importação em massa de componentes
        public async Task<ImportResultDto> ImportComponentsAsync(Stream csvStream)
        {
            var result = new ImportResultDto();
            var errors = new List<string>();
            var componentsToAdd = new List<Component>();

            try
            {
                using var reader = new StreamReader(csvStream);
                using var csv = new CsvReader(reader, new CsvConfiguration(CultureInfo.InvariantCulture)
                {
                    HasHeaderRecord = true,
                    Delimiter = ";",
                    BadDataFound = null
                });

                var records = csv.GetRecords<ComponentImportDto>().ToList();
                result.TotalRecords = records.Count;

                foreach (var record in records)
                {
                    try
                    {
                        // Validações básicas
                        if (string.IsNullOrWhiteSpace(record.Name))
                        {
                            errors.Add($"Nome é obrigatório para o componente na linha {result.SuccessCount + result.ErrorCount + 2}");
                            result.ErrorCount++;
                            continue;
                        }

                        if (string.IsNullOrWhiteSpace(record.Group))
                        {
                            errors.Add($"Grupo é obrigatório para o componente '{record.Name}'");
                            result.ErrorCount++;
                            continue;
                        }

                        var component = new Component
                        {
                            Name = record.Name,
                            Description = record.Description,
                            Group = record.Group,
                            Device = record.Device,
                            Value = record.Value,
                            Package = record.Package,
                            Characteristics = record.Characteristics,
                            InternalCode = record.InternalCode,
                            Price = record.Price,
                            Environment = record.Environment,
                            Drawer = record.Drawer,
                            Division = record.Division,
                            NCM = record.NCM,
                            NVE = record.NVE,
                            QuantityInStock = record.QuantityInStock,
                            MinimumQuantity = record.MinimumQuantity,
                            CreatedAt = DateTime.UtcNow,
                            UpdatedAt = DateTime.UtcNow
                        };

                        componentsToAdd.Add(component);
                        result.SuccessCount++;
                    }
                    catch (Exception ex)
                    {
                        errors.Add($"Erro ao processar componente '{record.Name}': {ex.Message}");
                        result.ErrorCount++;
                    }
                }

                // Adiciona todos os componentes válidos
                if (componentsToAdd.Any())
                {
                    await _componentRepository.AddRangeAsync(componentsToAdd);
                    _logger.LogInformation("Importação em massa concluída: {Success} componentes importados, {Error} erros",
                        result.SuccessCount, result.ErrorCount);
                }

                result.Success = result.ErrorCount == 0;
                result.Errors = errors;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro durante importação em massa de componentes");
                result.Success = false;
                result.Errors.Add($"Erro geral na importação: {ex.Message}");
            }

            return result;
        }

        // Deleta múltiplos componentes
        public async Task<bool> DeleteMultipleComponentsAsync(List<int> componentIds)
        {
            try
            {
                var components = new List<Component>();

                foreach (var id in componentIds)
                {
                    var component = await _componentRepository.GetByIdAsync(id);
                    if (component != null)
                    {
                        components.Add(component);
                    }
                }

                if (components.Any())
                {
                    await _componentRepository.DeleteRangeAsync(components);
                    _logger.LogInformation("Deletados {Count} componentes em massa", components.Count);
                }

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro ao deletar componentes em massa");
                return false;
            }
        }

        // Método auxiliar para mapear Component para ComponentDto
        private ComponentDto MapToDto(Component component)
        {
            return new ComponentDto
            {
                Id = component.Id,
                Name = component.Name,
                Description = component.Description,
                Group = component.Group,
                Device = component.Device,
                Value = component.Value,
                Package = component.Package,
                Characteristics = component.Characteristics,
                InternalCode = component.InternalCode,
                Price = component.Price,
                Environment = component.Environment,
                Drawer = component.Drawer,
                Division = component.Division,
                NCM = component.NCM,
                NVE = component.NVE,
                LastEntryDate = component.LastEntryDate,
                LastEntryQuantity = component.LastEntryQuantity,
                LastExitQuantity = component.LastExitQuantity,
                QuantityInStock = component.QuantityInStock,
                MinimumQuantity = component.MinimumQuantity,
                CreatedAt = component.CreatedAt,
                UpdatedAt = component.UpdatedAt
            };
        }
    }
}