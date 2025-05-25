using FluentValidation;
using PreSystem.StockControl.Application.DTOs;

namespace PreSystem.StockControl.Application.Validators
{
    // Validador para criação de componentes
    public class ComponentCreateDtoValidator : AbstractValidator<ComponentCreateDto>
    {
        public ComponentCreateDtoValidator()
        {
            RuleFor(c => c.Name)
                .NotEmpty().WithMessage("O nome do componente é obrigatório.")
                .MaximumLength(100).WithMessage("O nome não pode exceder 100 caracteres.");

            RuleFor(c => c.Group)
                .NotEmpty().WithMessage("O grupo do componente é obrigatório.")
                .MaximumLength(50).WithMessage("O grupo não pode exceder 50 caracteres.");

            RuleFor(c => c.QuantityInStock)
                .GreaterThanOrEqualTo(0).WithMessage("A quantidade em estoque não pode ser negativa.");

            RuleFor(c => c.MinimumQuantity)
                .GreaterThanOrEqualTo(0).WithMessage("A quantidade mínima deve ser zero ou maior.");
        }
    }
}
