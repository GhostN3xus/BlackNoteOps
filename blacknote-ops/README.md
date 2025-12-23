# BLACKNOTE OPS – Vault Edition
**Subtítulo:** Irreversible Secure Notebook for Offensive Security

## Visão Geral
O **BLACKNOTE OPS** é um cofre digital projetado para operações de Red Team e Pentest. Diferente de notas comuns, ele foca em **segurança irreversível**: se a identidade do usuário ou do dispositivo não for confirmada, os dados são matematicamente irrecuperáveis.

### Recursos Chave
- **Criptografia Irreversível:** AES-256-GCM + Argon2id.
- **Device Binding:** O cofre só abre no dispositivo onde foi criado.
- **Integridade de Aplicação:** Verificação de hash do executável (conceitual).
- **Playbooks & Host Intelligence:** Ferramentas nativas para pentesters.
- **Stack:** Electron, Node.js, SQLite (Encrypted blobs).

## Instalação e Build

### Pré-requisitos
- Node.js v16+
- Python (para build de módulos nativos como argon2)
- Visual Studio Build Tools (Windows) ou `build-essential` (Linux)

### Desenvolvimento
```bash
npm install
npm start
```

### Build do Executável (Windows)
```bash
npm run dist
```
O artefato `.exe` será gerado na pasta `dist/`.

## Estrutura do Projeto
- `src/main`: Processo principal do Electron (Backend local).
- `src/main/security`: Motores criptográficos e validação de integridade.
- `src/main/database`: Gerenciamento do SQLite.
- `src/renderer`: Interface do usuário (React/Vanilla).
