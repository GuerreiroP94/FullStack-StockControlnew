using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PreSystem.StockControl.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class SyncDatabaseModel : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_StockMovements_User_UserId",
                table: "StockMovements");

            migrationBuilder.DropPrimaryKey(
                name: "PK_User",
                table: "User");

            migrationBuilder.RenameTable(
                name: "User",
                newName: "Users");

            migrationBuilder.AddColumn<string>(
                name: "Characteristics",
                table: "Components",
                type: "nvarchar(max)",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Device",
                table: "Components",
                type: "nvarchar(max)",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Division",
                table: "Components",
                type: "nvarchar(max)",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Drawer",
                table: "Components",
                type: "nvarchar(max)",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Environment",
                table: "Components",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<string>(
                name: "InternalCode",
                table: "Components",
                type: "nvarchar(max)",
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

            migrationBuilder.AddColumn<string>(
                name: "NCM",
                table: "Components",
                type: "nvarchar(max)",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "NVE",
                table: "Components",
                type: "nvarchar(max)",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Package",
                table: "Components",
                type: "nvarchar(max)",
                nullable: true);

            migrationBuilder.AddColumn<decimal>(
                name: "Price",
                table: "Components",
                type: "decimal(18,2)",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Value",
                table: "Components",
                type: "nvarchar(max)",
                nullable: true);

            migrationBuilder.AddPrimaryKey(
                name: "PK_Users",
                table: "Users",
                column: "Id");

            migrationBuilder.AddForeignKey(
                name: "FK_StockMovements_Users_UserId",
                table: "StockMovements",
                column: "UserId",
                principalTable: "Users",
                principalColumn: "Id");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_StockMovements_Users_UserId",
                table: "StockMovements");

            migrationBuilder.DropPrimaryKey(
                name: "PK_Users",
                table: "Users");

            migrationBuilder.DropColumn(
                name: "Characteristics",
                table: "Components");

            migrationBuilder.DropColumn(
                name: "Device",
                table: "Components");

            migrationBuilder.DropColumn(
                name: "Division",
                table: "Components");

            migrationBuilder.DropColumn(
                name: "Drawer",
                table: "Components");

            migrationBuilder.DropColumn(
                name: "Environment",
                table: "Components");

            migrationBuilder.DropColumn(
                name: "InternalCode",
                table: "Components");

            migrationBuilder.DropColumn(
                name: "LastEntryDate",
                table: "Components");

            migrationBuilder.DropColumn(
                name: "LastEntryQuantity",
                table: "Components");

            migrationBuilder.DropColumn(
                name: "LastExitQuantity",
                table: "Components");

            migrationBuilder.DropColumn(
                name: "NCM",
                table: "Components");

            migrationBuilder.DropColumn(
                name: "NVE",
                table: "Components");

            migrationBuilder.DropColumn(
                name: "Package",
                table: "Components");

            migrationBuilder.DropColumn(
                name: "Price",
                table: "Components");

            migrationBuilder.DropColumn(
                name: "Value",
                table: "Components");

            migrationBuilder.RenameTable(
                name: "Users",
                newName: "User");

            migrationBuilder.AddPrimaryKey(
                name: "PK_User",
                table: "User",
                column: "Id");

            migrationBuilder.AddForeignKey(
                name: "FK_StockMovements_User_UserId",
                table: "StockMovements",
                column: "UserId",
                principalTable: "User",
                principalColumn: "Id");
        }
    }
}
