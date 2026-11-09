<?php
declare(strict_types=1);

session_start();

const DB_HOST = '127.0.0.1';
const DB_NAME = 'lms_sman9_wajo';
const DB_USER = 'root';
const DB_PASS = '';
const UPLOAD_DIR = __DIR__ . DIRECTORY_SEPARATOR . 'uploads';
const MAX_UPLOAD_SIZE = 10 * 1024 * 1024;

$pdo = new PDO(
    'mysql:host=' . DB_HOST . ';dbname=' . DB_NAME . ';charset=utf8mb4',
    DB_USER,
    DB_PASS,
    [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]
);

function e(?string $value): string
{
    return htmlspecialchars($value ?? '', ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function csrf_token(): string
{
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function csrf_field(): string
{
    return '<input type="hidden" name="csrf_token" value="' . e(csrf_token()) . '">';
}

function redirect(string $url = 'index.php'): never
{
    header('Location: ' . $url);
    exit;
}

function flash(string $message, string $type = 'success'): void
{
    $_SESSION['flash'] = ['message' => $message, 'type' => $type];
}

function require_role(string ...$roles): array
{
    $user = $_SESSION['user'] ?? null;
    if (!$user || !in_array($user['role'], $roles, true)) {
        http_response_code(403);
        exit('Anda tidak memiliki izin untuk mengakses halaman ini.');
    }
    return $user;
}

function require_login(): array
{
    if (empty($_SESSION['user'])) {
        redirect('index.php');
    }
    return $_SESSION['user'];
}

function save_upload(string $field): ?string
{
    if (!isset($_FILES[$field]) || $_FILES[$field]['error'] === UPLOAD_ERR_NO_FILE) {
        return null;
    }
    $file = $_FILES[$field];
    if ($file['error'] !== UPLOAD_ERR_OK) {
        throw new RuntimeException('Upload gagal. Periksa ukuran file dan coba lagi.');
    }
    if ($file['size'] > MAX_UPLOAD_SIZE) {
        throw new RuntimeException('Ukuran file maksimal 10 MB.');
    }

    $allowed = [
        'pdf' => ['application/pdf'],
        'doc' => ['application/msword', 'application/octet-stream'],
        'docx' => ['application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'application/zip'],
        'xls' => ['application/vnd.ms-excel', 'application/octet-stream'],
        'xlsx' => ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', 'application/zip'],
        'ppt' => ['application/vnd.ms-powerpoint', 'application/octet-stream'],
        'pptx' => ['application/vnd.openxmlformats-officedocument.presentationml.presentation', 'application/zip'],
        'jpg' => ['image/jpeg'],
        'jpeg' => ['image/jpeg'],
        'png' => ['image/png'],
    ];
    $extension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    $mime = (new finfo(FILEINFO_MIME_TYPE))->file($file['tmp_name']);
    if (!isset($allowed[$extension]) || !in_array($mime, $allowed[$extension], true)) {
        throw new RuntimeException('Format file tidak didukung. Gunakan PDF, Office, JPG, atau PNG.');
    }

    if (!is_dir(UPLOAD_DIR) && !mkdir(UPLOAD_DIR, 0755, true) && !is_dir(UPLOAD_DIR)) {
        throw new RuntimeException('Folder penyimpanan file tidak dapat dibuat.');
    }
    $filename = bin2hex(random_bytes(16)) . '.' . $extension;
    if (!move_uploaded_file($file['tmp_name'], UPLOAD_DIR . DIRECTORY_SEPARATOR . $filename)) {
        throw new RuntimeException('File gagal disimpan.');
    }
    return $filename;
}

function user_subjects(PDO $pdo, array $user): array
{
    if ($user['role'] === 'admin') {
        return $pdo->query(
            'SELECT s.*, c.name AS class_name, u.full_name AS teacher_name
             FROM subjects s JOIN classes c ON c.id = s.class_id
             JOIN users u ON u.id = s.teacher_id ORDER BY c.name, s.name'
        )->fetchAll();
    }
    $statement = $pdo->prepare(
        'SELECT s.*, c.name AS class_name, u.full_name AS teacher_name
         FROM subjects s JOIN classes c ON c.id = s.class_id
         JOIN users u ON u.id = s.teacher_id
         WHERE ' . ($user['role'] === 'guru' ? 's.teacher_id' : 's.class_id') . ' = ?
         ORDER BY s.name'
    );
    $statement->execute([$user[$user['role'] === 'guru' ? 'id' : 'class_id']]);
    return $statement->fetchAll();
}

function ensure_demo_accounts(PDO $pdo): void
{
    $class = $pdo->query("SELECT id FROM classes WHERE name = 'X MIPA 1' LIMIT 1")->fetch();
    if (!$class) {
        $pdo->exec("INSERT INTO classes (name) VALUES ('X MIPA 1')");
        $classId = (int)$pdo->lastInsertId();
    } else {
        $classId = (int)$class['id'];
    }

    $accounts = [
        ['admin', 'admin', 'Administrator LMS', 'admin', null],
        ['guru', 'guru', 'Guru Demo', 'guru', $classId],
        ['siswa', 'siswa', 'Siswa Demo', 'siswa', $classId],
    ];
    $find = $pdo->prepare('SELECT id FROM users WHERE username = ?');
    $insert = $pdo->prepare(
        'INSERT INTO users (username, password_hash, full_name, role, class_id) VALUES (?, ?, ?, ?, ?)'
    );
    foreach ($accounts as [$username, $password, $fullName, $role, $accountClass]) {
        $find->execute([$username]);
        if (!$find->fetch()) {
            $insert->execute([$username, password_hash($password, PASSWORD_DEFAULT), $fullName, $role, $accountClass]);
        }
    }

    $teacher = $pdo->query("SELECT id FROM users WHERE username = 'guru'")->fetch();
    $subject = $pdo->prepare('SELECT id FROM subjects WHERE class_id = ? AND name = ?');
    $subject->execute([$classId, 'Matematika']);
    if (!$subject->fetch()) {
        $insertSubject = $pdo->prepare('INSERT INTO subjects (name, class_id, teacher_id) VALUES (?, ?, ?)');
        $insertSubject->execute(['Matematika', $classId, (int)$teacher['id']]);
    }
}

ensure_demo_accounts($pdo);

if (isset($_SESSION['user'])) {
    $active = $pdo->prepare('SELECT id, username, full_name, role, class_id, active FROM users WHERE id = ?');
    $active->execute([$_SESSION['user']['id']]);
    $currentUser = $active->fetch();
    if (!$currentUser || !(int)$currentUser['active']) {
        $_SESSION = [];
        session_destroy();
    } else {
        $_SESSION['user'] = $currentUser;
    }
}
