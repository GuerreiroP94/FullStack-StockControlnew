using FluentValidation;
using PreSystem.StockControl.Application.DTOs;

namespace PreSystem.StockControl.Application.Validators
{
    public class ProductComponentCreateDtoValidator : AbstractValidator<ProductComponentCreateDto>
    {
        public ProductComponentCreateDtoValidator()
        {
            RuleFor(c => c.ComponentId)
                .GreaterThan(0).WithMessage("O ID do componente deve ser maior que zero.");

            RuleFor(c => c.Quantity)
                .GreaterThan(0).WithMessage("A quantidade do componente deve ser maior que zero.");
        }
    }
}
