﻿namespace PreSystem.StockControl.Application.DTOs.Filters
{
    // Esse DTO define os parâmetros de filtro e paginação usados na listagem de componentes
    public class ComponentFilterDto
    {
        public string? Name { get; set; }             // Filtro opcional por nome
        public string? Group { get; set; }            // Filtro opcional por grupo
        public int PageNumber { get; set; } = 1;      // Página atual (padrão 1)
        public int PageSize { get; set; } = 10;       // Quantidade de itens por página (padrão 10)
        public string? Device { get; set; }       // Filtro opcional por dispositivo
        public string? Package { get; set; }       // Filtro opcional por pacote
        public string? Value { get; set; }      // Filtro opcional por valor
        public string? SearchTerm { get; set; }     // Termo de pesquisa opcional para busca por nome, descrição ou código interno(geral search term)
    }
}
