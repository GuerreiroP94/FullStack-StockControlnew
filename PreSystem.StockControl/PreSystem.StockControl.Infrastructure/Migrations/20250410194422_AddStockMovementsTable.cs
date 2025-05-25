using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace PreSystem.StockControl.Infrastructure.Migrations
{
    /// <inheritdoc />
    public partial class AddStockMovementsTable : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_StockMovement_Components_ComponentId",
                table: "StockMovement");

            migrationBuilder.DropPrimaryKey(
                name: "PK_StockMovement",
                table: "StockMovement");

            migrationBuilder.RenameTable(
                name: "StockMovement",
                newName: "StockMovements");

            migrationBuilder.RenameIndex(
                name: "IX_StockMovement_ComponentId",
                table: "StockMovements",
                newName: "IX_StockMovements_ComponentId");

            migrationBuilder.AddPrimaryKey(
                name: "PK_StockMovements",
                table: "StockMovements",
                column: "Id");

            migrationBuilder.AddForeignKey(
                name: "FK_StockMovements_Components_ComponentId",
                table: "StockMovements",
                column: "ComponentId",
                principalTable: "Components",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_StockMovements_Components_ComponentId",
                table: "StockMovements");

            migrationBuilder.DropPrimaryKey(
                name: "PK_StockMovements",
                table: "StockMovements");

            migrationBuilder.RenameTable(
                name: "StockMovements",
                newName: "StockMovement");

            migrationBuilder.RenameIndex(
                name: "IX_StockMovements_ComponentId",
                table: "StockMovement",
                newName: "IX_StockMovement_ComponentId");

            migrationBuilder.AddPrimaryKey(
                name: "PK_StockMovement",
                table: "StockMovement",
                column: "Id");

            migrationBuilder.AddForeignKey(
                name: "FK_StockMovement_Components_ComponentId",
                table: "StockMovement",
                column: "ComponentId",
                principalTable: "Components",
                principalColumn: "Id",
                onDelete: ReferentialAction.Cascade);
        }
    }
}
