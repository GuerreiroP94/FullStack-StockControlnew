#pragma warning disable IDE0290
using PreSystem.StockControl.Application.DTOs;
using PreSystem.StockControl.Application.DTOs.Filters;
using PreSystem.StockControl.Application.Interfaces.Services;
using PreSystem.StockControl.Domain.Entities;
using PreSystem.StockControl.Domain.Interfaces.Repositories;
using Microsoft.Extensions.Logging;

namespace PreSystem.StockControl.Application.Services
{
    // Implementação do serviço de movimentações de estoque
    public class StockMovementService : IStockMovementService
    {
        private readonly IStockMovementRepository _movementRepository;
        private readonly IStockAlertRepository _alertRepository;
        private readonly IComponentRepository _componentRepository;
        private readonly IUserContextService _userContextService;
        private readonly ILogger<StockMovementService> _logger; // Logger para registrar ações e erros

        public StockMovementService(
            IStockMovementRepository movementRepository,
            IStockAlertRepository alertRepository,
            IComponentRepository componentRepository,
            IUserContextService userContextService,
            ILogger<StockMovementService> logger) // Injeção do logger
        {
            _movementRepository = movementRepository;
            _alertRepository = alertRepository;
            _componentRepository = componentRepository;
            _userContextService = userContextService;
            _logger = logger;
        }

        // Registra uma nova movimentação com base no DTO
        public async Task<StockMovementDto> RegisterMovementAsync(StockMovementCreateDto dto)
        {
            try
            {
                // Recupera o ID do usuário logado via token JWT
                var userId = _userContextService.GetCurrentUserId();

                // Cria uma nova movimentação de estoque com os dados fornecidos
                var movement = new StockMovement
                {
                    ComponentId = dto.ComponentId,
                    MovementType = dto.MovementType,
                    QuantityChanged = dto.Quantity,
                    PerformedAt = DateTime.UtcNow,
                    PerformedBy = _userContextService.GetCurrentUsername() ?? "Desconhecido",
                    UserId = userId
                };

                await _movementRepository.AddAsync(movement);

                _logger.LogInformation("Movimentação registrada: {Quantidade} unidades do componente {ComponenteId} por {Usuario}",
                    movement.QuantityChanged, movement.ComponentId, movement.PerformedBy);

                // Se for uma saída, verifica se o estoque está abaixo do mínimo
                if (dto.Quantity < 0)
                {
                    var component = await _componentRepository.GetByIdAsync(dto.ComponentId);
                    if (component != null && component.QuantityInStock < component.MinimumQuantity)
                    {
                        var alert = new StockAlert
                        {
                            ComponentId = component.Id,
                            Message = $"Estoque baixo: {component.Name} está com {component.QuantityInStock} unidades.",
                            CreatedAt = DateTime.UtcNow
                        };

                        await _alertRepository.AddAsync(alert);
                    }
                }

                return new StockMovementDto
                {
                    Id = movement.Id,
                    ComponentId = movement.ComponentId,
                    MovementType = movement.MovementType,
                    Quantity = movement.QuantityChanged,
                    MovementDate = movement.PerformedAt,
                    PerformedBy = movement.PerformedBy,
                    UserId = movement.UserId
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro ao registrar movimentação para o componente {ComponentId}", dto.ComponentId);
                throw;
            }
        }

        // Retorna todas as movimentações como DTO com filtros e paginação
        public async Task<IEnumerable<StockMovementDto>> GetAllMovementsAsync(StockMovementQueryParameters parameters)
        {
            var allMovements = await _movementRepository.GetAllAsync();
            var filtered = allMovements.AsQueryable();

            if (parameters.ComponentId.HasValue)
                filtered = filtered.Where(m => m.ComponentId == parameters.ComponentId.Value);

            if (!string.IsNullOrEmpty(parameters.MovementType))
                filtered = filtered.Where(m => m.MovementType == parameters.MovementType);

            if (parameters.StartDate.HasValue)
                filtered = filtered.Where(m => m.PerformedAt >= parameters.StartDate.Value);

            if (parameters.EndDate.HasValue)
                filtered = filtered.Where(m => m.PerformedAt <= parameters.EndDate.Value);

            // Paginação
            var skip = (parameters.Page - 1) * parameters.PageSize;
            var paged = filtered.Skip(skip).Take(parameters.PageSize);

            _logger.LogInformation("Movimentações listadas com filtros: ComponentId={ComponentId}, MovementType={MovementType}, Page={Page}, PageSize={PageSize}",
                parameters.ComponentId, parameters.MovementType, parameters.Page, parameters.PageSize);

            return paged.Select(m => new StockMovementDto
            {
                Id = m.Id,
                ComponentId = m.ComponentId,
                MovementType = m.MovementType,
                Quantity = m.QuantityChanged,
                MovementDate = m.PerformedAt,
                PerformedBy = m.PerformedBy,
                UserId = m.UserId
            }).ToList();
        }

        // Retorna uma movimentação específica pelo ID
        public async Task<StockMovementDto?> GetMovementByIdAsync(int id)
        {
            var movement = await _movementRepository.GetByIdAsync(id);
            if (movement == null) return null;

            _logger.LogInformation("Movimentação ID {Id} consultada por {Usuario}", id, _userContextService.GetCurrentUsername());

            return new StockMovementDto
            {
                Id = movement.Id,
                ComponentId = movement.ComponentId,
                MovementType = movement.MovementType,
                Quantity = movement.QuantityChanged,
                MovementDate = movement.PerformedAt,
                PerformedBy = movement.PerformedBy,
                UserName = movement.User?.Name
            };
        }

        // Registra múltiplas movimentações de uma vez (movimentação em massa)
        public async Task<BulkMovementResultDto> RegisterBulkMovementsAsync(BulkStockMovementDto dto)
        {
            var result = new BulkMovementResultDto
            {
                TotalMovements = dto.Movements.Count,
                SuccessCount = 0,
                ErrorCount = 0,
                Errors = new List<string>(),
                AlertsGenerated = new List<int>()
            };

            try
            {
                foreach (var movement in dto.Movements)
                {
                    try
                    {
                        // Busca o componente para validação
                        var component = await _componentRepository.GetByIdAsync(movement.ComponentId);
                        if (component == null)
                        {
                            result.Errors.Add($"Componente ID {movement.ComponentId} não encontrado");
                            result.ErrorCount++;
                            continue;
                        }

                        // Valida se há estoque suficiente para saída
                        if (movement.MovementType == "Saida" && movement.Quantity > component.QuantityInStock)
                        {
                            result.Errors.Add($"Estoque insuficiente para o componente {component.Name}. Disponível: {component.QuantityInStock}, Solicitado: {movement.Quantity}");
                            result.ErrorCount++;
                            continue;
                        }

                        // Cria a movimentação
                        var stockMovement = new StockMovement
                        {
                            ComponentId = movement.ComponentId,
                            MovementType = movement.MovementType,
                            QuantityChanged = movement.Quantity,
                            PerformedAt = DateTime.UtcNow,
                            PerformedBy = _userContextService.GetCurrentUsername() ?? "Sistema",
                            UserId = _userContextService.GetCurrentUserId()
                        };

                        await _movementRepository.AddAsync(stockMovement);

                        // Atualiza o estoque do componente
                        if (movement.MovementType == "Entrada")
                        {
                            component.QuantityInStock += movement.Quantity;
                            component.LastEntryDate = DateTime.UtcNow;
                            component.LastEntryQuantity = movement.Quantity;
                        }
                        else if (movement.MovementType == "Saida")
                        {
                            component.QuantityInStock -= movement.Quantity;
                            component.LastExitQuantity = movement.Quantity;
                        }

                        component.UpdatedAt = DateTime.UtcNow;
                        await _componentRepository.UpdateAsync(component);

                        // Verifica se precisa gerar alerta
                        if (component.QuantityInStock <= component.MinimumQuantity)
                        {
                            var alert = new StockAlert
                            {
                                ComponentId = component.Id,
                                Message = component.QuantityInStock == 0
                                    ? $"CRÍTICO: {component.Name} está com estoque zerado!"
                                    : $"Estoque baixo: {component.Name} está com apenas {component.QuantityInStock} unidades (mínimo: {component.MinimumQuantity})",
                                CreatedAt = DateTime.UtcNow
                            };

                            await _alertRepository.AddAsync(alert);
                            result.AlertsGenerated.Add(alert.Id);
                        }

                        result.SuccessCount++;

                        _logger.LogInformation(
                            "Movimentação em massa registrada: {Tipo} de {Quantidade} unidades do componente {ComponenteId}",
                            movement.MovementType, movement.Quantity, movement.ComponentId
                        );
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Erro ao processar movimentação do componente {ComponentId}", movement.ComponentId);
                        result.Errors.Add($"Erro ao processar componente {movement.ComponentId}: {ex.Message}");
                        result.ErrorCount++;
                    }
                }

                result.Success = result.ErrorCount == 0;
                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Erro geral ao processar movimentações em massa");
                result.Success = false;
                result.Errors.Add($"Erro geral: {ex.Message}");
                return result;
            }
        }
    }
}
