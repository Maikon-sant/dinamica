# Análise de código — problemas e segurança

> **Nota:** o arquivo analisado aqui é o endpoint de atualização de perfil (e-mail/senha),
> o mesmo de [../cenarioA/atualizar_perfil.php](../cenarioA/atualizar_perfil.php).
> Ele não implementa o download de documentos descrito no Cenário B
> (tabela `documentos`, PDFs de faturas).

## Código analisado

```php
<?php
declare(strict_types=1);

/**
 * Atualiza e-mail e/ou senha do usuário logado.
 * Veja o README.md para o contrato da API.
 */

session_start();
header('Content-Type: application/json; charset=utf-8');

function responder(int $status, array $dados): never
{
    http_response_code($status);
    exit(json_encode($dados, JSON_UNESCAPED_UNICODE));
}

function conectar(): PDO
{
    // MySQL: 'mysql:host=localhost;dbname=app;charset=utf8mb4', 'usuario', 'senha'
    return new PDO('sqlite:' . __DIR__ . '/app.db', options: [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    ]);
}

function validar(string $senhaAtual, ?string $email, ?string $novaSenha): array
{
    $erros = [];

    if ($senhaAtual === '') {
        $erros['senha_atual'] = 'Informe a senha atual.';
    }
    if ($email === null && $novaSenha === null) {
        $erros['geral'] = 'Informe e-mail e/ou nova senha.';
    }
    if ($email !== null && (mb_strlen($email) > 120 || !filter_var($email, FILTER_VALIDATE_EMAIL))) {
        $erros['email'] = 'E-mail inválido.';
    }
    if ($novaSenha !== null) {
        $erros['nova_senha'] = match (true) {
            mb_strlen($novaSenha) < 8      => 'Mínimo de 8 caracteres.',
            strlen($novaSenha) > 72        => 'Máximo de 72 bytes.',
            $novaSenha === $senhaAtual     => 'Deve ser diferente da senha atual.',
            default                        => null,
        };
        $erros = array_filter($erros);
    }

    return $erros;
}

// --- Requisição -----------------------------------------------------------

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    responder(405, ['erro' => 'Método não permitido.']);
}

$usuarioId = filter_var($_SESSION['usuario_id'] ?? null, FILTER_VALIDATE_INT);
if ($usuarioId === false) {
    responder(401, ['erro' => 'Não autenticado.']);
}

$entrada = str_contains($_SERVER['CONTENT_TYPE'] ?? '', 'application/json')
    ? json_decode(file_get_contents('php://input'), true)
    : $_POST;
if (!is_array($entrada)) {
    responder(400, ['erro' => 'JSON inválido.']);
}

$token = (string) ($entrada['csrf_token'] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '');
if (!hash_equals($_SESSION['csrf_token'] ?? '', $token)) {
    responder(403, ['erro' => 'Token CSRF inválido.']);
}

$senhaAtual = (string) ($entrada['senha_atual'] ?? '');
$email      = isset($entrada['email']) ? mb_strtolower(trim((string) $entrada['email'])) : null;
$novaSenha  = isset($entrada['nova_senha']) ? (string) $entrada['nova_senha'] : null;

if ($erros = validar($senhaAtual, $email, $novaSenha)) {
    responder(422, ['erro' => 'Dados inválidos.', 'campos' => $erros]);
}

// --- Persistência ---------------------------------------------------------

try {
    $pdo  = conectar();
    $stmt = $pdo->prepare('SELECT email, senha_hash FROM usuarios WHERE id = ?');
    $stmt->execute([$usuarioId]);
    $usuario = $stmt->fetch();

    if (!$usuario) {
        session_destroy();
        responder(401, ['erro' => 'Usuário não encontrado.']);
    }
    if (!password_verify($senhaAtual, $usuario['senha_hash'])) {
        responder(403, ['erro' => 'Senha atual incorreta.']);
    }

    // Apenas colunas que realmente mudaram (nomes fixos, sem input no SQL).
    $campos = array_filter([
        'email'      => $email !== null && $email !== mb_strtolower($usuario['email']) ? $email : null,
        'senha_hash' => $novaSenha !== null ? password_hash($novaSenha, PASSWORD_DEFAULT) : null,
    ]);

    if (!$campos) {
        responder(200, ['mensagem' => 'Nenhuma alteração necessária.']);
    }

    $set = implode(', ', array_map(fn(string $c) => "$c = :$c", array_keys($campos)));
    $pdo->prepare("UPDATE usuarios SET $set WHERE id = :id")
        ->execute($campos + ['id' => $usuarioId]);

    if ($novaSenha !== null) {
        session_regenerate_id(true);
    }

    responder(200, ['mensagem' => 'Cadastro atualizado com sucesso.']);
} catch (PDOException $e) {
    if ($e->getCode() === '23000') { // violação de UNIQUE (email)
        responder(409, ['erro' => 'Este e-mail já está em uso.']);
    }
    error_log('[atualizar_perfil] ' . $e->getMessage());
    responder(500, ['erro' => 'Erro interno. Tente novamente mais tarde.']);
}
```

## Pontos positivos

| Prática                                   | Onde                                   |
|-------------------------------------------|----------------------------------------|
| Identidade vinda da sessão (sem IDOR)     | `$_SESSION['usuario_id']`              |
| Prepared statements                       | `SELECT` e `UPDATE`                    |
| Nomes de coluna fixos no `UPDATE`         | array `$campos`                        |
| Hash de senha moderno + `password_verify` | `password_hash` / `password_verify`    |
| Exige a senha atual para alterar          | antes do `UPDATE`                      |
| Sessão renovada após trocar a senha       | `session_regenerate_id(true)`          |
| Erros internos não vazam ao cliente       | `error_log` + mensagem genérica        |

## Problemas encontrados

### 1. Bypass de CSRF quando a sessão não tem token — **alta**

**Linha:** `hash_equals($_SESSION['csrf_token'] ?? '', $token)`

Se a sessão não tiver `csrf_token` e a requisição também não enviar um, os dois lados
viram `''` e `hash_equals('', '')` retorna `true`. A proteção é ignorada.

**Correção:** rejeitar quando o token da sessão estiver vazio.

```php
$esperado = $_SESSION['csrf_token'] ?? '';
if ($esperado === '' || !hash_equals($esperado, $token)) {
    responder(403, ['erro' => 'Token CSRF inválido.']);
}
```

### 2. Banco SQLite dentro do diretório do script — **média**

**Linha:** `new PDO('sqlite:' . __DIR__ . '/app.db')`

Se a pasta estiver no diretório público do servidor, `app.db` (com hashes de senha) pode
ser baixado direto pela URL.

**Correção:** guardar o arquivo fora do diretório público, ou usar MySQL com usuário de
privilégios mínimos.

### 3. Sem limite de tentativas na senha atual — **média**

Quem controla uma sessão (por exemplo, um computador desbloqueado) pode testar senhas
indefinidamente.

**Correção:** limitar tentativas por usuário/IP (contador na sessão ou no banco, ou na
borda com proxy/WAF) e registrar falhas.

### 4. Cookie de sessão sem configuração segura — **média**

`session_start()` é chamado com os padrões. Sem `HttpOnly`, `Secure` e `SameSite`, o
cookie fica mais exposto, e o CSRF depende da sessão.

**Correção:**

```php
session_set_cookie_params([
    'httponly' => true,
    'secure'   => true,
    'samesite' => 'Lax',
]);
session_start();
```

### 5. Troca de e-mail sem confirmação — **média**

O novo e-mail é gravado na hora. Quem tem a sessão e a senha pode trocar o e-mail e
assumir a conta por "esqueci minha senha".

**Correção:** enviar link de confirmação ao novo e-mail e avisar o antigo da mudança.

### 6. Outras sessões continuam válidas após trocar a senha — **baixa**

`session_regenerate_id` só renova a sessão atual. Sessões abertas em outros dispositivos
continuam ativas.

**Correção:** guardar uma versão da credencial (ou `senha_alterada_em`) e invalidar
sessões mais antigas.

### 7. Todo erro de integridade vira "e-mail já em uso" — **baixa**

`getCode() === '23000'` cobre qualquer violação de integridade. Hoje só o `UNIQUE` do
e-mail pode causar isso, mas é uma suposição frágil se a tabela ganhar outras restrições.

**Correção:** conferir também a mensagem/coluna do erro ou consultar o e-mail antes (sem
abrir mão do `UNIQUE`, que continua sendo a garantia final).

### 8. `UNIQUE` diferencia maiúsculas de minúsculas no SQLite — **baixa**

Só e-mails novos são normalizados com `mb_strtolower`. Contas antigas com caixa
diferente podem colidir ou duplicar.

**Correção:** normalizar os dados existentes e usar `COLLATE NOCASE` na coluna.

### 9. `session_destroy()` não apaga o cookie — **baixa**

O cookie continua no navegador, apontando para uma sessão inexistente.

**Correção:** limpar também o cookie (`setcookie` com expiração no passado).

### 10. Sem log de auditoria — **baixa**

Trocas de e-mail e senha não são registradas, o que dificulta investigar incidentes.

**Correção:** registrar usuário, data, IP e o campo alterado (nunca os valores).

## Resumo

| # | Problema                                  | Severidade |
|---|-------------------------------------------|------------|
| 1 | Bypass de CSRF com token vazio            | Alta       |
| 2 | `app.db` no diretório do script           | Média      |
| 3 | Sem limite de tentativas                  | Média      |
| 4 | Cookie de sessão sem flags                | Média      |
| 5 | E-mail trocado sem confirmação            | Média      |
| 6 | Outras sessões não invalidadas            | Baixa      |
| 7 | Erro `23000` genérico → 409               | Baixa      |
| 8 | `UNIQUE` sensível a caixa                 | Baixa      |
| 9 | Cookie não apagado no `session_destroy`   | Baixa      |
| 10| Sem auditoria                             | Baixa      |
