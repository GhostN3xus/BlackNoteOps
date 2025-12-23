# Arquitetura de Segurança – BLACKNOTE OPS

## 1. Modelo de Ameaça e Defesa

| Ameaça | Defesa |
| :--- | :--- |
| **Roubo de arquivo .db** | O banco contém apenas blobs criptografados (AES-256-GCM). Sem a chave mestre (que reside na RAM), é lixo aleatório. |
| **Roubo de Notebook** | A chave mestre é derivada da senha + Fingerprint do Hardware. Se o atacante clonar o disco para outra máquina, a Fingerprint muda e a chave derivada será incorreta. |
| **Engenharia Reversa** | Ofuscação de código (na build final) e verificação de integridade do executável. |
| **Dumps de Memória** | Zeroização de buffers (overwrite) após o uso. Chaves sensíveis são mantidas pelo menor tempo possível. |

## 2. Fluxo Criptográfico (The "Vault Logic")

### A. Derivação da Chave Mestre (Master Key Derivation)
A chave que descriptografa o banco **nunca** é salva em disco. Ela é reconstruída em tempo de execução.

1.  **Entradas:**
    *   `UserPassword` (Digitada no login).
    *   `DeviceFingerprint` (Coletada do OS: CPU ID, MAC Address, Machine GUID).
    *   `Salt` (Aleatório, armazenado no cabeçalho do banco).

2.  **Processo:**
    *   `DeviceKey` = HMAC-SHA256(`DeviceFingerprint`, `StaticAppSecret`)
    *   `EntropyPool` = `UserPassword` + `DeviceKey`
    *   **MasterKey** = Argon2id(`EntropyPool`, `Salt`, TimeCost=High, Memory=High)

3.  **Resultado:**
    *   Se o usuário errar a senha -> `MasterKey` incorreta -> Falha no Auth Tag do AES (MAC mismatch).
    *   Se trocar de PC -> `DeviceFingerprint` muda -> `DeviceKey` muda -> `MasterKey` incorreta -> Dados ilegíveis.

### B. Criptografia de Dados (Data at Rest)
*   Algoritmo: **AES-256-GCM** (Galois/Counter Mode).
*   Garante Confidencialidade e Integridade (detecta tampered data).
*   Cada registro (nota/playbook) tem seu próprio **IV (Initialization Vector)**.

## 3. Estrutura do Banco de Dados
O SQLite atua como um "Key-Value Store" glorificado e seguro. Não usamos a criptografia nativa do SQLCipher apenas, fazemos a criptografia na camada de aplicação para garantir o controle sobre a lógica de derivação.

Tabela `vault_store`:
- `id`: UUID
- `type`: 'note' | 'playbook' | 'host'
- `iv`: Hex string (único por linha)
- `data`: Blob criptografado (JSON stringified do objeto real)
- `auth_tag`: Tag GCM para validação

## 4. Proteção de Memória
*   Ao fechar o app ou bloquear:
    *   `MasterKey` é sobrescrita com zeros.
    *   O Garbage Collector do JS é forçado (se possível) ou buffers são manualmente limpos.
