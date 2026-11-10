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
