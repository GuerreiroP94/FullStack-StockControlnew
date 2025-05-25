using FluentValidation;
using PreSystem.StockControl.Application.DTOs;

namespace PreSystem.StockControl.Application.Validators
{
    // Validador para o DTO de criação de movimentação de estoque
    public class StockMovementCreateDtoValidator : AbstractValidator<StockMovementCreateDto>
    {
        public StockMovementCreateDtoValidator()
        {
            // O ID do componente é obrigatório e deve ser maior que 0
            RuleFor(m => m.ComponentId)
                .GreaterThan(0).WithMessage("O ID do componente deve ser maior que zero.");

            // O tipo de movimentação não pode ser nulo ou vazio (Entrada ou Saída)
            RuleFor(m => m.MovementType)
                .NotEmpty().WithMessage("O tipo de movimentação é obrigatório.")
                .Must(type => type == "Entrada" || type == "Saida")
                .WithMessage("O tipo de movimentação deve ser 'Entrada' ou 'Saida'.");

            // A quantidade deve ser diferente de zero
            RuleFor(m => m.Quantity)
                .NotEqual(0).WithMessage("A quantidade deve ser diferente de zero.");
        }
    }
}
