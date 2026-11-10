# Atualização de Perfil (Cenário A)

Endpoint PHP que permite ao usuário logado alterar o **e-mail** e/ou a **senha**.

- Arquivo: [atualizar_perfil.php](atualizar_perfil.php)
- Requisitos: PHP 8.1+, extensão PDO (SQLite ou MySQL)

## Tabela utilizada

```sql
CREATE TABLE usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT, -- ou INT AUTO_INCREMENT
    nome VARCHAR(100) NOT NULL,
    email VARCHAR(120) NOT NULL UNIQUE,
    senha_hash VARCHAR(255) NOT NULL,
    tipo_usuario VARCHAR(20) DEFAULT 'cliente' -- 'cliente' ou 'admin'
);
```

## Pré-requisitos na aplicação

O endpoint assume que o login já preencheu a sessão:

```php
$_SESSION['usuario_id'] = $usuario['id'];
$_SESSION['csrf_token'] = bin2hex(random_bytes(32)); // exponha ao front-end
```

## Contrato da API

`POST /atualizar_perfil.php` — corpo em JSON (`Content-Type: application/json`) ou formulário.

| Campo         | Obrigatório | Descrição                                              |
|---------------|-------------|--------------------------------------------------------|
| `csrf_token`  | sim         | Token da sessão (ou header `X-CSRF-Token`)             |
| `senha_atual` | sim         | Senha atual, para confirmar a identidade               |
| `email`       | não         | Novo e-mail (válido, até 120 caracteres)               |
| `nova_senha`  | não         | 8 a 72 bytes, diferente da senha atual                 |

É obrigatório enviar `email`, `nova_senha` ou ambos.

### Exemplo

```bash
curl -X POST http://localhost/atualizar_perfil.php \
  -H "Content-Type: application/json" \
  -H "Cookie: PHPSESSID=<sessao>" \
  -d '{"csrf_token":"<token>","senha_atual":"antiga123","email":"novo@exemplo.com","nova_senha":"novaSenha456"}'
```

### Respostas

| Status | Quando                                         | Corpo                                        |
|--------|------------------------------------------------|----------------------------------------------|
| 200    | Atualizado (ou nada a alterar)                 | `{"mensagem": "..."}`                        |
| 400    | JSON malformado                                | `{"erro": "..."}`                            |
| 401    | Sem sessão ou usuário inexistente              | `{"erro": "..."}`                            |
| 403    | CSRF inválido ou senha atual incorreta         | `{"erro": "..."}`                            |
| 405    | Método diferente de POST                       | `{"erro": "..."}`                            |
| 409    | E-mail já usado por outra conta                | `{"erro": "..."}`                            |
| 422    | Validação falhou                               | `{"erro": "...", "campos": {"email": "..."}}`|
| 500    | Erro interno (detalhe só no log do servidor)   | `{"erro": "..."}`                            |

## Como funciona

1. Valida método, sessão e token CSRF.
2. Valida e normaliza os campos (função `validar()`).
3. Busca o usuário **pelo id da sessão** e confere `senha_atual` com `password_verify`.
4. Monta o `UPDATE` somente com os campos que mudaram.
5. Salva a nova senha com `password_hash` e renova o id da sessão.

## Decisões de segurança

| Risco                     | Mitigação                                                         |
|---------------------------|-------------------------------------------------------------------|
| Alterar conta de outro    | O id vem da sessão, nunca da requisição                           |
| Sequestro de sessão       | Exige a senha atual; `session_regenerate_id` após trocar a senha  |
| CSRF                      | Token comparado com `hash_equals`                                 |
| SQL injection             | Prepared statements; nomes de coluna fixos no código              |
| Senha vazada no banco     | `password_hash` (algoritmo padrão do PHP, atualizável)            |
| E-mail duplicado (corrida)| Constraint `UNIQUE` do banco, erro `23000` convertido em 409      |
| Vazamento de erros        | Detalhes vão para `error_log`; o cliente recebe mensagem genérica |

## Configuração

Edite `conectar()` em [atualizar_perfil.php](atualizar_perfil.php) para usar seu banco. Para MySQL, troque o DSN pelo exemplo comentado na função.

## Limitações conhecidas

- Não há limite de tentativas (rate limiting) para `senha_atual`; recomenda-se adicioná-lo na borda (proxy/WAF) ou na aplicação.
- Trocar o e-mail não exige confirmação por link; em produção, considere verificá-lo antes de efetivar.
- Outras sessões ativas do mesmo usuário não são encerradas após a troca de senha.
