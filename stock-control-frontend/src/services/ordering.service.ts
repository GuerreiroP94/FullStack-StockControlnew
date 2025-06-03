// Serviço para gerenciar ordenação de componentes
class OrderingService {
  /**
   * Reordena um array baseado em drag and drop
   */
  reorderByDragDrop<T>(
    array: T[],
    dragIndex: number,
    dropIndex: number
  ): T[] {
    const newArray = [...array];
    const draggedItem = newArray[dragIndex];
    newArray.splice(dragIndex, 1);
    newArray.splice(dropIndex, 0, draggedItem);
    return newArray;
  }

  /**
   * Cria objeto de inputs de ordem baseado em array
   */
  createOrderInputsFromArray(array: number[]): { [key: number]: number } {
    const inputs: { [key: number]: number } = {};
    array.forEach((id, index) => {
      inputs[id] = index + 1;
    });
    return inputs;
  }

  /**
   * Ordena array baseado em inputs manuais
   */
  sortByOrderInputs(
    currentOrder: number[],
    orderInputs: { [key: number]: number }
  ): number[] {
    const itemsWithOrder = currentOrder.map(id => ({
      id,
      order: orderInputs[id] || 999
    }));

    itemsWithOrder.sort((a, b) => a.order - b.order);
    
    return itemsWithOrder.map(item => item.id);
  }

  /**
   * Gerencia estado completo de ordenação para modal
   */
  handleDragReorder(
    currentOrder: number[],
    dragIndex: number,
    dropIndex: number
  ): {
    newOrder: number[];
    newInputs: { [key: number]: number };
  } {
    const newOrder = this.reorderByDragDrop(currentOrder, dragIndex, dropIndex);
    const newInputs = this.createOrderInputsFromArray(newOrder);
    
    return { newOrder, newInputs };
  }
}

export default new OrderingService();