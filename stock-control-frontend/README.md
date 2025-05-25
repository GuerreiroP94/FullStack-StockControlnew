# Sistema de Controle de Estoque - Frontend

Frontend React com TypeScript para o sistema de controle de estoque de componentes eletrônicos.

## 🚀 Tecnologias

- React 18
- TypeScript
- Tailwind CSS
- React Router DOM v6
- Axios
- Lucide React (ícones)

## 📋 Pré-requisitos

- Node.js v16+
- NPM ou Yarn
- Backend API rodando em http://localhost:5123

## 🔧 Instalação

1. Clone o repositório
```bash
git clone [url-do-repositorio]
cd stock-control-frontend
```

2. Instale as dependências
```bash
npm install
```

3. Configure as variáveis de ambiente
```bash
# Copie o arquivo .env.example para .env
cp .env.example .env
```

4. Inicie o servidor de desenvolvimento
```bash
npm start
```

O aplicativo estará disponível em http://localhost:3000

## 🏗️ Estrutura do Projeto

```
src/
├── components/      # Componentes reutilizáveis
├── pages/          # Páginas da aplicação
├── services/       # Serviços de API
├── contexts/       # Contextos React
├── types/          # Definições TypeScript
└── utils/          # Funções utilitárias
```

## 🔑 Funcionalidades

- Autenticação JWT
- Gestão de componentes
- Gestão de produtos
- Movimentações de estoque
- Alertas de estoque baixo
- Gestão de usuários (Admin)

## 📱 Páginas

- Login
- Dashboard
- Componentes (CRUD)
- Produtos (CRUD)
- Movimentações
- Alertas
- Usuários (Admin)

## 🛠️ Scripts Disponíveis

- `npm start` - Inicia o servidor de desenvolvimento
- `npm build` - Gera a build de produção
- `npm test` - Executa os testes