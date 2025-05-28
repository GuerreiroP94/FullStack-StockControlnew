// User Types
export interface User {
  id: number;
  name: string;
  email: string;
  role: 'admin' | 'operator';
  createdAt: string;
}

export interface UserLogin {
  email: string;
  password: string;
}

export interface UserCreate {
  name: string;
  email: string;
  password: string;
  role: 'admin' | 'operator';
}

export interface UserUpdate {
  name: string;
  email: string;
  password?: string;
}

// Component Types
export interface Component {
  id: number;
  name: string;
  description?: string;
  group: string;
  quantityInStock: number;
  minimumQuantity: number;
}

export interface ComponentCreate {
  name: string;
  description?: string;
  group: string;
  quantityInStock: number;
  minimumQuantity: number;
}

// Product Types
export interface Product {
  id: number;
  name: string;
  description?: string;
  createdAt: string;
  createdBy?: string;
  components: ProductComponent[];
}

export interface ProductComponent {
  componentId: number;
  componentName: string;
  group: string;
  quantity: number;
}

export interface ProductCreate {
  name: string;
  description?: string;
  createdBy?: string;
  components: ProductComponentCreate[];
}

export interface ProductComponentCreate {
  componentId: number;
  quantity: number;
}

// Stock Movement Types
export interface StockMovement {
  id: number;
  componentId: number;
  movementType: 'Entrada' | 'Saida';
  quantity: number;
  movementDate: string;
  performedBy: string;
  userId?: number;
  userName?: string;
}

export interface StockMovementCreate {
  componentId: number;
  movementType: 'Entrada' | 'Saida';
  quantity: number;
  performedBy: string;
}

// Stock Alert Types
export interface StockAlert {
  id: number;
  componentId: number;
  message: string;
  createdAt: string;
}

// Filter Types
export interface ComponentFilter {
  name?: string;
  group?: string;
  pageNumber: number;
  pageSize: number;
}

export interface ProductQueryParameters {
  pageNumber: number;
  pageSize: number;
  name?: string;
}

export interface StockMovementQueryParameters {
  componentId?: number;
  movementType?: string;
  startDate?: string;
  endDate?: string;
  page: number;
  pageSize: number;
}

export interface StockAlertQueryParameters {
  page: number;
  pageSize: number;
  componentId?: number;
  fromDate?: string;
  toDate?: string;
}

// Auth Types
export interface AuthResponse {
  token: string;
}

export interface AuthContextType {
  user: User | null;
  token: string | null;
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
  updateCurrentUser: (user: User) => void;
  isAuthenticated: boolean;
  isAdmin: boolean;
}