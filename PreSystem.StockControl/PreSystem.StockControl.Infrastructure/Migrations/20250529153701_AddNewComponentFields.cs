using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PreSystem.StockControl.Infrastructure.Migrations
{
    public partial class AddNewComponentFields : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Adicionar novos campos na tabela Components
            migrationBuilder.AddColumn<string>(
                name: "InternalCode",
                table: "Components",
                type: "nvarchar(50)",
                maxLength: 50,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Device",
                table: "Components",
                type: "nvarchar(100)",
                maxLength: 100,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Value",
                table: "Components",
                type: "nvarchar(50)",
                maxLength: 50,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Package",
                table: "Components",
                type: "nvarchar(50)",
                maxLength: 50,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Characteristics",
                table: "Components",
                type: "nvarchar(500)",
                maxLength: 500,
                nullable: true);

            migrationBuilder.AddColumn<decimal>(
                name: "Price",
                table: "Components",
                type: "decimal(18,2)",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Environment",
                table: "Components",
                type: "nvarchar(50)",
                maxLength: 50,
                nullable: false,
                defaultValue: "estoque");

            migrationBuilder.AddColumn<string>(
                name: "Drawer",
                table: "Components",
                type: "nvarchar(50)",
                maxLength: 50,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Division",
                table: "Components",
                type: "nvarchar(50)",
                maxLength: 50,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "NCM",
                table: "Components",
                type: "nvarchar(20)",
                maxLength: 20,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "NVE",
                table: "Components",
                type: "nvarchar(20)",
                maxLength: 20,
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "LastEntryDate",
                table: "Components",
                type: "datetime2",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "LastEntryQuantity",
                table: "Components",
                type: "int",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "LastExitQuantity",
                table: "Components",
                type: "int",
                nullable: true);
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(name: "InternalCode", table: "Components");
            migrationBuilder.DropColumn(name: "Device", table: "Components");
            migrationBuilder.DropColumn(name: "Value", table: "Components");
            migrationBuilder.DropColumn(name: "Package", table: "Components");
            migrationBuilder.DropColumn(name: "Characteristics", table: "Components");
            migrationBuilder.DropColumn(name: "Price", table: "Components");
            migrationBuilder.DropColumn(name: "Environment", table: "Components");
            migrationBuilder.DropColumn(name: "Drawer", table: "Components");
            migrationBuilder.DropColumn(name: "Division", table: "Components");
            migrationBuilder.DropColumn(name: "NCM", table: "Components");
            migrationBuilder.DropColumn(name: "NVE", table: "Components");
            migrationBuilder.DropColumn(name: "LastEntryDate", table: "Components");
            migrationBuilder.DropColumn(name: "LastEntryQuantity", table: "Components");
            migrationBuilder.DropColumn(name: "LastExitQuantity", table: "Components");
        }
    }
}