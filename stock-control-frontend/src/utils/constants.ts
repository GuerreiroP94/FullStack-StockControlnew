export const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:5123/api';

export const ROUTES = {
  LOGIN: '/login',
  FORGOT_PASSWORD: '/forgot-password',
  DASHBOARD: '/dashboard',
  COMPONENTS: '/components',
  PRODUCTS: '/products',
  MOVEMENTS: '/movements',
  ALERTS: '/alerts',
  USERS: '/users',
  SETTINGS: '/settings',
};

export const COMPONENT_GROUPS = [
  'Semicondutor',
  'Resistor',
  'Capacitor',
  'Indutor',
  'Conector',
  'CI',
  'Diodo',
  'Transistor',
  'LED',
  'Outros'
];

export const COMPONENT_ENVIRONMENTS = {
  STOCK: 'estoque',
  LAB: 'laboratorio'
} as const;

export const MOVEMENT_TYPES = {
  ENTRADA: 'Entrada',
  SAIDA: 'Saida'
} as const;

export const USER_ROLES = {
  ADMIN: 'admin',
  OPERATOR: 'operator'
} as const;

export const PAGINATION = {
  DEFAULT_PAGE_SIZE: 10,
  PAGE_SIZE_OPTIONS: [10, 20, 50, 100]
};

export const MESSAGES = {
  LOGIN_SUCCESS: 'Login realizado com sucesso!',
  LOGIN_ERROR: 'Erro ao fazer login. Verifique suas credenciais.',
  LOGOUT_SUCCESS: 'Logout realizado com sucesso!',
  
  COMPONENT_CREATED: 'Componente criado com sucesso!',
  COMPONENT_UPDATED: 'Componente atualizado com sucesso!',
  COMPONENT_DELETED: 'Componente excluído com sucesso!',
  
  PRODUCT_CREATED: 'Produto criado com sucesso!',
  PRODUCT_UPDATED: 'Produto atualizado com sucesso!',
  PRODUCT_DELETED: 'Produto excluído com sucesso!',
  
  MOVEMENT_CREATED: 'Movimentação registrada com sucesso!',
  
  USER_CREATED: 'Usuário criado com sucesso!',
  USER_UPDATED: 'Usuário atualizado com sucesso!',
  USER_DELETED: 'Usuário excluído com sucesso!',
  
  ERROR_GENERIC: 'Ocorreu um erro. Tente novamente.',
  ERROR_NETWORK: 'Erro de conexão. Verifique sua internet.',
  ERROR_UNAUTHORIZED: 'Você não tem permissão para realizar esta ação.',
  ERROR_NOT_FOUND: 'Registro não encontrado.'
};