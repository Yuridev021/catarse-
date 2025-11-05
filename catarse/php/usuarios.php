<?php
require_once 'config/Database.php';

try {
    // Criar conexão com o banco
    $database = new Database();
    $pdo = $database->getConnection();

    if(!$pdo) {
        throw new Exception("Erro ao conectar ao banco de dados");
    }

    // Receber dados do formulário
$nome = htmlspecialchars(trim($_POST['nome'] ?? ''));
$login = htmlspecialchars(trim($_POST['login'] ?? ''));
$senha = $_POST['senha'] ?? '';
$celular = htmlspecialchars(trim($_POST['celular'] ?? ''));
$cpf = htmlspecialchars(trim($_POST['cpf'] ?? ''));
$cep = htmlspecialchars(trim($_POST['cep'] ?? ''));
$endereco = htmlspecialchars(trim($_POST['endereco'] ?? ''));
$bairro = htmlspecialchars(trim($_POST['bairro'] ?? ''));
$cidade = htmlspecialchars(trim($_POST['cidade'] ?? ''));
$uf = htmlspecialchars(trim($_POST['uf'] ?? ''));

    // Validações
    if (strlen($login) != 6 || !ctype_alpha($login)) {
        throw new Exception("Login deve conter exatamente 6 letras");
    }

    if (!preg_match('/^[0-9]{6,12}$/', $senha)) {
        throw new Exception("Senha deve conter entre 6 e 12 números");
    }

    // Remove caracteres especiais do CPF
    $cpf = preg_replace('/[^0-9]/', '', $cpf);
    if (strlen($cpf) != 11) {
        throw new Exception("CPF inválido");
    }

    // Verificar se login já existe
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM usuarios WHERE login = ?");
    $stmt->execute([$login]);
    if ($stmt->fetchColumn() > 0) {
        throw new Exception("Login já está em uso");
    }

    // Verificar se CPF já existe
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM usuarios WHERE cpf = ?");
    $stmt->execute([$cpf]);
    if ($stmt->fetchColumn() > 0) {
        throw new Exception("CPF já cadastrado");
    }

    // Hash da senha
    $senha_hash = password_hash($senha, PASSWORD_DEFAULT);

    // Preparar e executar a query SQL
    $sql = "INSERT INTO usuarios (nome, login, senha, celular, cpf, cep, endereco, bairro, cidade, uf) 
            VALUES (:nome, :login, :senha, :celular, :cpf, :cep, :endereco, :bairro, :cidade, :uf)";
    
    $stmt = $pdo->prepare($sql);
    
    $stmt->execute([
        ':nome' => $nome,
        ':login' => $login,
        ':senha' => $senha_hash,
        ':celular' => $celular,
        ':cpf' => $cpf,
        ':cep' => $cep,
        ':endereco' => $endereco,
        ':bairro' => $bairro,
        ':cidade' => $cidade,
        ':uf' => $uf
    ]);

    // Cadastro bem sucedido
    header("Location: login.html");
    exit();

} catch (PDOException $e) {
    // Erro de banco de dados
    header('Content-Type: application/json');
    echo json_encode(['erro' => 'Erro no banco de dados: ' . $e->getMessage()]);
    exit();
    
} catch (Exception $e) {
    // Outros erros (validações)
    header('Content-Type: application/json');
    echo json_encode(['erro' => $e->getMessage()]);
    exit();
}
?>