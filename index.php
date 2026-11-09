<?php
declare(strict_types=1);
require __DIR__ . '/bootstrap.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!hash_equals(csrf_token(), (string)($_POST['csrf_token'] ?? ''))) {
        http_response_code(400);
        exit('Permintaan tidak valid. Muat ulang halaman dan coba kembali.');
    }

    $action = (string)($_POST['action'] ?? '');
    if ($action === 'login') {
        $statement = $pdo->prepare('SELECT id, username, password_hash, full_name, role, class_id, active FROM users WHERE username = ?');
        $statement->execute([trim((string)($_POST['username'] ?? ''))]);
        $user = $statement->fetch();
        if ($user && (int)$user['active'] === 1 && password_verify((string)($_POST['password'] ?? ''), $user['password_hash'])) {
            session_regenerate_id(true);
            unset($user['password_hash'], $user['active']);
            $_SESSION['user'] = $user;
            flash('Selamat datang, ' . $user['full_name'] . '!');
            redirect();
        }
        flash('Username atau password salah.', 'error');
        redirect();
    }

    $user = require_login();
    try {
        switch ($action) {
            case 'logout':
                $_SESSION = [];
                session_destroy();
                redirect();

            case 'create_class':
                require_role('admin');
                $name = trim((string)($_POST['name'] ?? ''));
                if ($name === '') {
                    throw new RuntimeException('Nama kelas wajib diisi.');
                }
                $statement = $pdo->prepare('INSERT INTO classes (name) VALUES (?)');
                $statement->execute([$name]);
                flash('Kelas berhasil ditambahkan.');
                break;

            case 'update_profile':
                $fullName = trim((string)($_POST['full_name'] ?? ''));
                $username = trim((string)($_POST['username'] ?? ''));
                $currentPassword = (string)($_POST['current_password'] ?? '');
                $newPassword = (string)($_POST['new_password'] ?? '');
                $passwordCheck = $pdo->prepare('SELECT password_hash FROM users WHERE id = ?');
                $passwordCheck->execute([$user['id']]);
                $account = $passwordCheck->fetch();
                if ($fullName === '' || $username === '' || !$account || !password_verify($currentPassword, $account['password_hash'])) {
                    throw new RuntimeException('Nama dan username wajib diisi; masukkan password saat ini dengan benar.');
                }
                if ($newPassword !== '' && strlen($newPassword) < 6) {
                    throw new RuntimeException('Password baru minimal 6 karakter.');
                }
                if ($newPassword === '') {
                    $statement = $pdo->prepare('UPDATE users SET full_name = ?, username = ? WHERE id = ?');
                    $statement->execute([$fullName, $username, $user['id']]);
                } else {
                    $statement = $pdo->prepare('UPDATE users SET full_name = ?, username = ?, password_hash = ? WHERE id = ?');
                    $statement->execute([$fullName, $username, password_hash($newPassword, PASSWORD_DEFAULT), $user['id']]);
                }
                $_SESSION['user']['full_name'] = $fullName;
                $_SESSION['user']['username'] = $username;
                flash('Identitas akun berhasil diperbarui.');
                break;

            case 'update_class':
                require_role('admin');
                $classId = (int)($_POST['class_id'] ?? 0);
                $name = trim((string)($_POST['name'] ?? ''));
                if ($classId < 1 || $name === '') {
                    throw new RuntimeException('Pilih kelas dan isi nama kelas.');
                }
                $statement = $pdo->prepare('UPDATE classes SET name = ? WHERE id = ?');
                $statement->execute([$name, $classId]);
                if (!$statement->rowCount()) {
                    $exists = $pdo->prepare('SELECT id FROM classes WHERE id = ?');
                    $exists->execute([$classId]);
                    if (!$exists->fetch()) {
                        throw new RuntimeException('Kelas tidak ditemukan.');
                    }
                }
                flash('Nama kelas berhasil diperbarui.');
                break;

            case 'delete_class':
                require_role('admin');
                $classId = (int)($_POST['class_id'] ?? 0);
                $usage = $pdo->prepare(
                    'SELECT (SELECT COUNT(*) FROM users WHERE class_id = ?) +
                            (SELECT COUNT(*) FROM subjects WHERE class_id = ?) AS total'
                );
                $usage->execute([$classId, $classId]);
                if ((int)$usage->fetchColumn() > 0) {
                    throw new RuntimeException('Kelas belum dapat dihapus. Pindahkan penggunanya dan hapus/pindahkan mata pelajarannya terlebih dahulu.');
                }
                $statement = $pdo->prepare('DELETE FROM classes WHERE id = ?');
                $statement->execute([$classId]);
                if (!$statement->rowCount()) {
                    throw new RuntimeException('Kelas tidak ditemukan.');
                }
                flash('Kelas berhasil dihapus.');
                break;

            case 'create_user':
                require_role('admin');
                $username = trim((string)($_POST['username'] ?? ''));
                $fullName = trim((string)($_POST['full_name'] ?? ''));
                $password = (string)($_POST['password'] ?? '');
                $role = (string)($_POST['role'] ?? '');
                $classValue = (string)($_POST['class_id'] ?? '');
                $classId = $classValue !== '' ? (int)$classValue : null;
                if ($username === '' || $fullName === '' || strlen($password) < 6 || !in_array($role, ['admin', 'guru', 'siswa'], true)) {
                    throw new RuntimeException('Lengkapi data akun. Password minimal 6 karakter.');
                }
                if ($role === 'siswa' && !$classId) {
                    throw new RuntimeException('Siswa harus ditempatkan pada sebuah kelas.');
                }
                $statement = $pdo->prepare('INSERT INTO users (username, password_hash, full_name, role, class_id) VALUES (?, ?, ?, ?, ?)');
                $statement->execute([$username, password_hash($password, PASSWORD_DEFAULT), $fullName, $role, $classId]);
                flash('Akun berhasil dibuat.');
                break;

            case 'update_user':
                require_role('admin');
                $targetId = (int)($_POST['user_id'] ?? 0);
                $username = trim((string)($_POST['username'] ?? ''));
                $fullName = trim((string)($_POST['full_name'] ?? ''));
                $role = (string)($_POST['role'] ?? '');
                $classValue = (string)($_POST['class_id'] ?? '');
                $classId = $classValue !== '' ? (int)$classValue : null;
                $password = (string)($_POST['password'] ?? '');
                $targetCheck = $pdo->prepare('SELECT role FROM users WHERE id = ?');
                $targetCheck->execute([$targetId]);
                $target = $targetCheck->fetch();
                if (!$target || $username === '' || $fullName === '' || !in_array($role, ['admin', 'guru', 'siswa'], true)) {
                    throw new RuntimeException('Data pengguna tidak valid.');
                }
                if ($targetId === (int)$user['id'] && $role !== $user['role']) {
                    throw new RuntimeException('Peran akun admin yang sedang digunakan tidak dapat diubah.');
                }
                if ($role === 'siswa' && !$classId) {
                    throw new RuntimeException('Siswa harus ditempatkan pada sebuah kelas.');
                }
                if ($password !== '' && strlen($password) < 6) {
                    throw new RuntimeException('Password baru minimal 6 karakter.');
                }
                if ($password === '') {
                    $statement = $pdo->prepare('UPDATE users SET username = ?, full_name = ?, role = ?, class_id = ? WHERE id = ?');
                    $statement->execute([$username, $fullName, $role, $classId, $targetId]);
                } else {
                    $statement = $pdo->prepare('UPDATE users SET username = ?, full_name = ?, role = ?, class_id = ?, password_hash = ? WHERE id = ?');
                    $statement->execute([$username, $fullName, $role, $classId, password_hash($password, PASSWORD_DEFAULT), $targetId]);
                }
                flash('Data pengguna berhasil diperbarui.');
                break;

            case 'toggle_user':
                require_role('admin');
                $targetId = (int)($_POST['user_id'] ?? 0);
                if ($targetId === (int)$user['id']) {
                    throw new RuntimeException('Akun admin yang sedang digunakan tidak dapat dinonaktifkan.');
                }
                $statement = $pdo->prepare('UPDATE users SET active = IF(active = 1, 0, 1) WHERE id = ?');
                $statement->execute([$targetId]);
                flash('Status akun diperbarui.');
                break;

            case 'create_subject':
                require_role('admin');
                $name = trim((string)($_POST['name'] ?? ''));
                $classId = (int)($_POST['class_id'] ?? 0);
                $teacherId = (int)($_POST['teacher_id'] ?? 0);
                $teacherCheck = $pdo->prepare("SELECT id FROM users WHERE id = ? AND role = 'guru' AND active = 1");
                $teacherCheck->execute([$teacherId]);
                if ($name === '' || !$teacherCheck->fetch()) {
                    throw new RuntimeException('Nama mata pelajaran atau guru pengampu tidak valid.');
                }
                $statement = $pdo->prepare('INSERT INTO subjects (name, class_id, teacher_id) VALUES (?, ?, ?)');
                $statement->execute([$name, $classId, $teacherId]);
                flash('Mata pelajaran berhasil ditambahkan.');
                break;

            case 'update_subject':
                require_role('admin');
                $subjectId = (int)($_POST['subject_id'] ?? 0);
                $name = trim((string)($_POST['name'] ?? ''));
                $classId = (int)($_POST['class_id'] ?? 0);
                $teacherId = (int)($_POST['teacher_id'] ?? 0);
                $teacherCheck = $pdo->prepare("SELECT id FROM users WHERE id = ? AND role = 'guru' AND active = 1");
                $teacherCheck->execute([$teacherId]);
                if ($subjectId < 1 || $name === '' || !$teacherCheck->fetch()) {
                    throw new RuntimeException('Data mata pelajaran atau guru pengampu tidak valid.');
                }
                $statement = $pdo->prepare('UPDATE subjects SET name = ?, class_id = ?, teacher_id = ? WHERE id = ?');
                $statement->execute([$name, $classId, $teacherId, $subjectId]);
                flash('Data mata pelajaran berhasil diperbarui.');
                break;

            case 'create_material':
                require_role('guru');
                $subjectId = (int)($_POST['subject_id'] ?? 0);
                $title = trim((string)($_POST['title'] ?? ''));
                $content = trim((string)($_POST['content'] ?? ''));
                $check = $pdo->prepare('SELECT id FROM subjects WHERE id = ? AND teacher_id = ?');
                $check->execute([$subjectId, $user['id']]);
                if ($title === '' || !$check->fetch()) {
                    throw new RuntimeException('Pilih mata pelajaran yang Anda ampu dan isi judul materi.');
                }
                $fileName = save_upload('attachment');
                $statement = $pdo->prepare('INSERT INTO materials (subject_id, title, content, file_name) VALUES (?, ?, ?, ?)');
                $statement->execute([$subjectId, $title, $content, $fileName]);
                flash('Materi berhasil diterbitkan.');
                break;

            case 'update_material':
                require_role('guru');
                $materialId = (int)($_POST['material_id'] ?? 0);
                $title = trim((string)($_POST['title'] ?? ''));
                $content = trim((string)($_POST['content'] ?? ''));
                $check = $pdo->prepare(
                    'SELECT m.file_name FROM materials m JOIN subjects s ON s.id = m.subject_id
                     WHERE m.id = ? AND s.teacher_id = ?'
                );
                $check->execute([$materialId, $user['id']]);
                $existing = $check->fetch();
                if (!$existing || $title === '') {
                    throw new RuntimeException('Materi tidak ditemukan atau judul belum diisi.');
                }
                $newFile = save_upload('attachment');
                $statement = $pdo->prepare('UPDATE materials SET title = ?, content = ?, file_name = ? WHERE id = ?');
                $statement->execute([$title, $content, $newFile ?? $existing['file_name'], $materialId]);
                if ($newFile && $existing['file_name']) {
                    $oldPath = UPLOAD_DIR . DIRECTORY_SEPARATOR . basename($existing['file_name']);
                    if (is_file($oldPath)) unlink($oldPath);
                }
                flash('Materi berhasil diperbarui.');
                break;

            case 'create_assignment':
                require_role('guru');
                $subjectId = (int)($_POST['subject_id'] ?? 0);
                $title = trim((string)($_POST['title'] ?? ''));
                $description = trim((string)($_POST['description'] ?? ''));
                $dueAt = trim((string)($_POST['due_at'] ?? ''));
                $check = $pdo->prepare('SELECT id FROM subjects WHERE id = ? AND teacher_id = ?');
                $check->execute([$subjectId, $user['id']]);
                if ($title === '' || !$check->fetch()) {
                    throw new RuntimeException('Pilih mata pelajaran yang Anda ampu dan isi judul tugas.');
                }
                $fileName = save_upload('attachment');
                $statement = $pdo->prepare('INSERT INTO assignments (subject_id, title, description, due_at, file_name) VALUES (?, ?, ?, ?, ?)');
                $statement->execute([$subjectId, $title, $description, $dueAt !== '' ? str_replace('T', ' ', $dueAt) : null, $fileName]);
                flash('Tugas berhasil diterbitkan.');
                break;

            case 'update_assignment':
                require_role('guru');
                $assignmentId = (int)($_POST['assignment_id'] ?? 0);
                $title = trim((string)($_POST['title'] ?? ''));
                $description = trim((string)($_POST['description'] ?? ''));
                $dueAt = trim((string)($_POST['due_at'] ?? ''));
                $check = $pdo->prepare(
                    'SELECT a.file_name FROM assignments a JOIN subjects s ON s.id = a.subject_id
                     WHERE a.id = ? AND s.teacher_id = ?'
                );
                $check->execute([$assignmentId, $user['id']]);
                $existing = $check->fetch();
                if (!$existing || $title === '') {
                    throw new RuntimeException('Tugas tidak ditemukan atau judul belum diisi.');
                }
                $newFile = save_upload('attachment');
                $statement = $pdo->prepare(
                    'UPDATE assignments SET title = ?, description = ?, due_at = ?, file_name = ? WHERE id = ?'
                );
                $statement->execute([
                    $title,
                    $description,
                    $dueAt !== '' ? str_replace('T', ' ', $dueAt) : null,
                    $newFile ?? $existing['file_name'],
                    $assignmentId,
                ]);
                if ($newFile && $existing['file_name']) {
                    $oldPath = UPLOAD_DIR . DIRECTORY_SEPARATOR . basename($existing['file_name']);
                    if (is_file($oldPath)) unlink($oldPath);
                }
                flash('Tugas berhasil diperbarui.');
                break;

            case 'submit_assignment':
                require_role('siswa');
                $assignmentId = (int)($_POST['assignment_id'] ?? 0);
                $check = $pdo->prepare(
                    'SELECT a.id FROM assignments a JOIN subjects s ON s.id = a.subject_id
                     WHERE a.id = ? AND s.class_id = ?'
                );
                $check->execute([$assignmentId, $user['class_id']]);
                if (!$check->fetch()) {
                    throw new RuntimeException('Tugas tidak ditemukan untuk kelas Anda.');
                }
                $fileName = save_upload('submission');
                if (!$fileName) {
                    throw new RuntimeException('Pilih file jawaban terlebih dahulu.');
                }
                $statement = $pdo->prepare(
                    'INSERT INTO submissions (assignment_id, student_id, file_name, note, grade, feedback)
                     VALUES (?, ?, ?, ?, NULL, NULL)
                     ON DUPLICATE KEY UPDATE file_name = VALUES(file_name), note = VALUES(note),
                       submitted_at = CURRENT_TIMESTAMP, grade = NULL, feedback = NULL'
                );
                $statement->execute([$assignmentId, $user['id'], $fileName, trim((string)($_POST['note'] ?? ''))]);
                flash('Tugas berhasil dikumpulkan. Pengumpulan baru menggantikan file sebelumnya.');
                break;

            case 'grade_submission':
                require_role('guru');
                $submissionId = (int)($_POST['submission_id'] ?? 0);
                $grade = filter_var($_POST['grade'] ?? null, FILTER_VALIDATE_FLOAT);
                $feedback = trim((string)($_POST['feedback'] ?? ''));
                if ($grade === false || $grade < 0 || $grade > 100) {
                    throw new RuntimeException('Nilai harus berupa angka antara 0 sampai 100.');
                }
                $check = $pdo->prepare(
                    'SELECT sub.id FROM submissions sub JOIN assignments a ON a.id = sub.assignment_id
                     JOIN subjects s ON s.id = a.subject_id
                     WHERE sub.id = ? AND s.teacher_id = ?'
                );
                $check->execute([$submissionId, $user['id']]);
                if (!$check->fetch()) {
                    throw new RuntimeException('Pengumpulan tidak ditemukan atau bukan mata pelajaran Anda.');
                }
                $statement = $pdo->prepare(
                    'UPDATE submissions sub JOIN assignments a ON a.id = sub.assignment_id
                     JOIN subjects s ON s.id = a.subject_id
                     SET sub.grade = ?, sub.feedback = ?
                     WHERE sub.id = ? AND s.teacher_id = ?'
                );
                $statement->execute([$grade, $feedback, $submissionId, $user['id']]);
                flash('Nilai dan umpan balik berhasil disimpan.');
                break;

            default:
                throw new RuntimeException('Aksi tidak dikenali.');
        }
    } catch (RuntimeException $error) {
        flash($error->getMessage(), 'error');
    } catch (PDOException $error) {
        if ($error->getCode() === '23000') {
            flash('Data tidak dapat disimpan karena nama sudah digunakan atau masih terkait dengan data lain.', 'error');
        } else {
            throw $error;
        }
    }
    redirect('index.php?page=' . urlencode((string)($_GET['page'] ?? 'dashboard')));
}

if (isset($_GET['download'])) {
    $user = require_login();
    $type = (string)($_GET['type'] ?? '');
    $id = (int)$_GET['download'];
    $fileName = null;
    if ($type === 'material') {
        $statement = $pdo->prepare(
            "SELECT m.file_name FROM materials m JOIN subjects s ON s.id = m.subject_id
             WHERE m.id = ? AND (? = 'admin' OR (? = 'guru' AND s.teacher_id = ?) OR (? = 'siswa' AND s.class_id = ?))"
        );
        $statement->execute([$id, $user['role'], $user['role'], $user['id'], $user['role'], $user['class_id']]);
    } elseif ($type === 'assignment') {
        $statement = $pdo->prepare(
            "SELECT a.file_name FROM assignments a JOIN subjects s ON s.id = a.subject_id
             WHERE a.id = ? AND (? = 'admin' OR (? = 'guru' AND s.teacher_id = ?) OR (? = 'siswa' AND s.class_id = ?))"
        );
        $statement->execute([$id, $user['role'], $user['role'], $user['id'], $user['role'], $user['class_id']]);
    } elseif ($type === 'submission') {
        $statement = $pdo->prepare(
            "SELECT sub.file_name FROM submissions sub JOIN assignments a ON a.id = sub.assignment_id
             JOIN subjects s ON s.id = a.subject_id
             WHERE sub.id = ? AND (? = 'admin' OR (? = 'guru' AND s.teacher_id = ?) OR (? = 'siswa' AND sub.student_id = ?))"
        );
        $statement->execute([$id, $user['role'], $user['role'], $user['id'], $user['role'], $user['id']]);
    } else {
        http_response_code(404);
        exit('File tidak ditemukan.');
    }
    $result = $statement->fetch();
    $fileName = $result['file_name'] ?? null;
    $path = $fileName ? UPLOAD_DIR . DIRECTORY_SEPARATOR . basename($fileName) : '';
    if (!$fileName || !is_file($path)) {
        http_response_code(404);
        exit('File tidak ditemukan.');
    }
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . basename($fileName) . '"');
    header('Content-Length: ' . filesize($path));
    readfile($path);
    exit;
}

if (empty($_SESSION['user'])) {
    $notice = $_SESSION['flash'] ?? null;
    unset($_SESSION['flash']);
    ?><!doctype html>
    <html lang="id"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Masuk · LMS SMAN 9 Wajo</title><link rel="stylesheet" href="style.css"></head>
    <body class="login-page"><main class="login-card">
      <div class="brand-mark">9</div><p class="eyebrow">LEARNING MANAGEMENT SYSTEM</p>
      <h1>Selamat datang</h1><p class="muted">Masuk ke LMS SMAN 9 Wajo</p>
      <?php if ($notice): ?><div class="alert <?= e($notice['type']) ?>"><?= e($notice['message']) ?></div><?php endif; ?>
      <form method="post" class="stack">
        <?= csrf_field() ?><input type="hidden" name="action" value="login">
        <label>Username<input name="username" autocomplete="username" required autofocus></label>
        <label>Password<input type="password" name="password" autocomplete="current-password" required></label>
        <button class="button primary full" type="submit">Masuk ke aplikasi</button>
      </form>
      <p class="login-hint">Akun demo: admin.admin · guru.guru · siswa.siswa</p>
    </main></body></html><?php
    exit;
}

$user = require_login();
$page = (string)($_GET['page'] ?? 'dashboard');
$allowedPages = ['dashboard', 'admin', 'materials', 'assignments', 'grades', 'profile'];
if (!in_array($page, $allowedPages, true)) {
    $page = 'dashboard';
}
$subjects = user_subjects($pdo, $user);
$classes = $user['role'] === 'admin' ? $pdo->query('SELECT * FROM classes ORDER BY name')->fetchAll() : [];
$notice = $_SESSION['flash'] ?? null;
unset($_SESSION['flash']);
?><!doctype html>
<html lang="id"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>LMS SMAN 9 Wajo</title><link rel="stylesheet" href="style.css"></head>
<body>
<div class="app-shell">
  <aside class="sidebar">
    <a class="brand" href="index.php"><span class="brand-mark small">9</span><span><strong>SMAN 9 Wajo</strong><small>Learning portal</small></span></a>
    <nav>
      <a class="<?= $page === 'dashboard' ? 'active' : '' ?>" href="?page=dashboard"><span>⌂</span> Beranda</a>
      <?php if ($user['role'] === 'admin'): ?><a class="<?= $page === 'admin' ? 'active' : '' ?>" href="?page=admin"><span>⚙</span> Kelola LMS</a><?php endif; ?>
      <a class="<?= $page === 'materials' ? 'active' : '' ?>" href="?page=materials"><span>▤</span> Materi</a>
      <a class="<?= $page === 'assignments' ? 'active' : '' ?>" href="?page=assignments"><span>✓</span> Tugas</a>
      <?php if ($user['role'] === 'siswa'): ?><a class="<?= $page === 'grades' ? 'active' : '' ?>" href="?page=grades"><span>▥</span> Nilai saya</a><?php endif; ?>
      <a class="<?= $page === 'profile' ? 'active' : '' ?>" href="?page=profile"><span>◉</span> Profil saya</a>
    </nav>
    <div class="sidebar-bottom"><div class="user-chip"><span class="avatar"><?= e(strtoupper(substr($user['full_name'], 0, 1))) ?></span><span><strong><?= e($user['full_name']) ?></strong><small><?= e(ucfirst($user['role'])) ?></small></span></div>
      <form method="post"><?= csrf_field() ?><input type="hidden" name="action" value="logout"><button class="logout" type="submit">Keluar <span>↗</span></button></form>
    </div>
  </aside>
  <main class="main">
    <header class="topbar"><div><p class="eyebrow">SMAN 9 WAJO · <?= e(strtoupper($user['role'])) ?></p><h1><?= ['admin' => 'Kelola LMS', 'materials' => 'Materi pembelajaran', 'assignments' => 'Tugas', 'grades' => 'Nilai saya', 'profile' => 'Profil saya'][$page] ?? 'Beranda' ?></h1></div>
      <div class="topbar-date"><?= date('d M Y') ?></div></header>
    <?php if ($notice): ?><div class="alert <?= e($notice['type']) ?>"><?= e($notice['message']) ?></div><?php endif; ?>

    <?php if ($page === 'dashboard'):
      $materialQuery = $pdo->prepare(
        'SELECT COUNT(*) FROM materials m JOIN subjects s ON s.id = m.subject_id WHERE ' .
        ($user['role'] === 'admin' ? '1=1' : ($user['role'] === 'guru' ? 's.teacher_id = ?' : 's.class_id = ?'))
      );
      $materialQuery->execute($user['role'] === 'admin' ? [] : [$user['role'] === 'guru' ? $user['id'] : $user['class_id']]);
      $materialCount = (int)$materialQuery->fetchColumn();
      $taskQuery = $pdo->prepare(
        'SELECT COUNT(*) FROM assignments a JOIN subjects s ON s.id = a.subject_id WHERE ' .
        ($user['role'] === 'admin' ? '1=1' : ($user['role'] === 'guru' ? 's.teacher_id = ?' : 's.class_id = ?'))
      );
      $taskQuery->execute($user['role'] === 'admin' ? [] : [$user['role'] === 'guru' ? $user['id'] : $user['class_id']]);
      $taskCount = (int)$taskQuery->fetchColumn();
      if ($user['role'] === 'admin') {
        $stats = [['Pengguna aktif', (int)$pdo->query('SELECT COUNT(*) FROM users WHERE active = 1')->fetchColumn(), '👥'], ['Mata pelajaran', count($subjects), '▤'], ['Kelas', count($classes), '⌂']];
      } elseif ($user['role'] === 'guru') {
        $stats = [['Mata pelajaran', count($subjects), '▤'], ['Materi diterbitkan', $materialCount, '📖'], ['Tugas dibuat', $taskCount, '✓']];
      } else {
        $gradedQuery = $pdo->prepare('SELECT COUNT(*) FROM submissions WHERE student_id = ? AND grade IS NOT NULL');
        $gradedQuery->execute([$user['id']]);
        $stats = [['Mata pelajaran', count($subjects), '▤'], ['Tugas tersedia', $taskCount, '✓'], ['Tugas dinilai', (int)$gradedQuery->fetchColumn(), '★']];
      }
      ?>
      <section class="welcome"><div><p class="eyebrow">PORTAL PEMBELAJARAN</p><h2>Halo, <?= e($user['full_name']) ?> 👋</h2><p>Semua aktivitas belajar Anda, dalam satu tempat.</p></div><div class="welcome-art">✦</div></section>
      <section class="stats"><?php foreach ($stats as [$label, $value, $icon]): ?><article class="stat-card"><span class="stat-icon"><?= $icon ?></span><div><p><?= e($label) ?></p><strong><?= $value ?></strong></div></article><?php endforeach; ?></section>
      <section class="section"><div class="section-heading"><div><p class="eyebrow">KELAS ANDA</p><h2>Mata pelajaran</h2></div></div>
        <?php if (!$subjects): ?><div class="empty-state">Belum ada mata pelajaran yang tersedia.</div><?php else: ?><div class="subject-grid"><?php foreach ($subjects as $subject): ?><article class="subject-card"><span class="subject-icon">▤</span><h3><?= e($subject['name']) ?></h3><p><?= e($subject['class_name']) ?> · <?= e($subject['teacher_name']) ?></p><div class="subject-links"><a href="?page=materials">Lihat materi →</a><a href="?page=assignments">Lihat tugas →</a></div></article><?php endforeach; ?></div><?php endif; ?>
      </section>

    <?php elseif ($page === 'admin' && $user['role'] === 'admin'):
      $allUsers = $pdo->query('SELECT u.*, c.name AS class_name FROM users u LEFT JOIN classes c ON c.id = u.class_id ORDER BY u.role, u.full_name')->fetchAll();
      $teachers = $pdo->query("SELECT id, full_name FROM users WHERE role = 'guru' AND active = 1 ORDER BY full_name")->fetchAll();
      ?>
      <section class="admin-grid">
        <article class="panel"><div class="panel-heading"><div><p class="eyebrow">STRUKTUR SEKOLAH</p><h2>Tambah kelas</h2></div></div>
          <form method="post" class="inline-form"><?= csrf_field() ?><input type="hidden" name="action" value="create_class"><input name="name" placeholder="Contoh: XI IPA 1" required><button class="button primary" type="submit">Tambah kelas</button></form>
          <div class="table-wrap class-list"><table><thead><tr><th>Nama kelas</th><th>Pengguna / mapel</th><th>Aksi</th></tr></thead><tbody>
          <?php foreach ($classes as $class):
            $usageCheck = $pdo->prepare(
                'SELECT (SELECT COUNT(*) FROM users WHERE class_id = ?) +
                        (SELECT COUNT(*) FROM subjects WHERE class_id = ?) AS total'
            );
            $usageCheck->execute([$class['id'], $class['id']]);
            $classUsage = (int)$usageCheck->fetchColumn();
          ?><tr><td colspan="3"><div class="class-edit-row">
            <form method="post" class="inline-form compact-form"><?= csrf_field() ?><input type="hidden" name="action" value="update_class"><input type="hidden" name="class_id" value="<?= (int)$class['id'] ?>"><input name="name" value="<?= e($class['name']) ?>" required><button class="button light small" type="submit">Simpan</button></form>
            <span class="count-label"><?= $classUsage ?> terkait</span>
            <?php if ($classUsage === 0): ?><form method="post" onsubmit="return confirm('Hapus kelas ini? Tindakan ini tidak dapat dibatalkan.')"><?= csrf_field() ?><input type="hidden" name="action" value="delete_class"><input type="hidden" name="class_id" value="<?= (int)$class['id'] ?>"><button class="text-button danger" type="submit">Hapus kelas</button></form><?php else: ?><span class="muted small-note">Kosongkan kelas sebelum menghapus</span><?php endif; ?>
          </div></td></tr><?php endforeach; ?>
          </tbody></table></div>
          <p class="muted small-note">Kelas hanya dapat dihapus setelah semua pengguna dan mata pelajaran dipindahkan atau dihapus.</p>
        </article>
        <article class="panel"><div class="panel-heading"><div><p class="eyebrow">AKUN PENGGUNA</p><h2>Buat akun</h2></div></div>
          <form method="post" class="form-grid"><?= csrf_field() ?><input type="hidden" name="action" value="create_user">
            <label>Nama lengkap<input name="full_name" required></label><label>Username<input name="username" required></label>
            <label>Password (min. 6 karakter)<input type="password" name="password" minlength="6" required></label>
            <label>Peran<select name="role"><option value="siswa">Siswa</option><option value="guru">Guru</option><option value="admin">Admin</option></select></label>
            <label>Kelas (wajib untuk siswa)<select name="class_id"><option value="">Tidak ada / pilih nanti</option><?php foreach ($classes as $class): ?><option value="<?= (int)$class['id'] ?>"><?= e($class['name']) ?></option><?php endforeach; ?></select></label>
            <div class="form-end"><button class="button primary" type="submit">Buat akun</button></div>
          </form>
        </article>
        <article class="panel"><div class="panel-heading"><div><p class="eyebrow">KURIKULUM</p><h2>Tambah mata pelajaran</h2></div></div>
          <form method="post" class="form-grid"><?= csrf_field() ?><input type="hidden" name="action" value="create_subject">
            <label>Nama mata pelajaran<input name="name" required></label><label>Kelas<select name="class_id" required><?php foreach ($classes as $class): ?><option value="<?= (int)$class['id'] ?>"><?= e($class['name']) ?></option><?php endforeach; ?></select></label>
            <label>Guru pengampu<select name="teacher_id" required><?php foreach ($teachers as $teacher): ?><option value="<?= (int)$teacher['id'] ?>"><?= e($teacher['full_name']) ?></option><?php endforeach; ?></select></label>
            <div class="form-end"><button class="button primary" type="submit">Tambah mapel</button></div>
          </form>
        </article>
      </section>
      <section class="panel section"><div class="panel-heading"><div><p class="eyebrow">PENGELOLAAN AKUN</p><h2>Pengguna</h2></div></div><div class="table-wrap"><table><thead><tr><th>Nama / username</th><th>Peran</th><th>Kelas</th><th>Status</th><th>Aksi</th></tr></thead><tbody>
      <?php foreach ($allUsers as $account): ?><tr><td><strong><?= e($account['full_name']) ?></strong><br><span class="muted"><?= e($account['username']) ?></span></td><td><span class="role-badge"><?= e(ucfirst($account['role'])) ?></span></td><td><?= e($account['class_name'] ?? '—') ?></td><td><span class="status <?= $account['active'] ? 'on' : 'off' ?>"><?= $account['active'] ? 'Aktif' : 'Nonaktif' ?></span></td><td><details class="edit-details"><summary>Edit data</summary><form method="post" class="form-grid edit-form"><?= csrf_field() ?><input type="hidden" name="action" value="update_user"><input type="hidden" name="user_id" value="<?= (int)$account['id'] ?>">
        <label>Nama lengkap<input name="full_name" value="<?= e($account['full_name']) ?>" required></label><label>Username<input name="username" value="<?= e($account['username']) ?>" required></label>
        <label>Peran<select name="role"><?php foreach (['admin' => 'Admin', 'guru' => 'Guru', 'siswa' => 'Siswa'] as $roleValue => $roleLabel): ?><option value="<?= $roleValue ?>" <?= $account['role'] === $roleValue ? 'selected' : '' ?>><?= $roleLabel ?></option><?php endforeach; ?></select></label>
        <label>Kelas<select name="class_id"><option value="">Tidak ada</option><?php foreach ($classes as $class): ?><option value="<?= (int)$class['id'] ?>" <?= (int)$account['class_id'] === (int)$class['id'] ? 'selected' : '' ?>><?= e($class['name']) ?></option><?php endforeach; ?></select></label>
        <label class="span-2">Password baru (kosongkan jika tidak diganti)<input type="password" name="password" minlength="6"></label><button class="button primary small" type="submit">Simpan perubahan</button></form></details>
        <?php if ((int)$account['id'] !== (int)$user['id']): ?><form method="post" class="status-action"><?= csrf_field() ?><input type="hidden" name="action" value="toggle_user"><input type="hidden" name="user_id" value="<?= (int)$account['id'] ?>"><button class="text-button" type="submit"><?= $account['active'] ? 'Nonaktifkan' : 'Aktifkan' ?></button></form><?php endif; ?></td></tr><?php endforeach; ?>
      </tbody></table></div></section>

      <section class="panel section"><div class="panel-heading"><div><p class="eyebrow">KURIKULUM</p><h2>Edit mata pelajaran</h2></div></div><div class="table-wrap"><table><thead><tr><th>Mata pelajaran</th><th>Kelas</th><th>Guru</th><th>Edit</th></tr></thead><tbody>
      <?php foreach ($subjects as $subject): ?><tr><td><?= e($subject['name']) ?></td><td><?= e($subject['class_name']) ?></td><td><?= e($subject['teacher_name']) ?></td><td><details class="edit-details"><summary>Edit data</summary><form method="post" class="form-grid edit-form"><?= csrf_field() ?><input type="hidden" name="action" value="update_subject"><input type="hidden" name="subject_id" value="<?= (int)$subject['id'] ?>">
        <label>Nama mata pelajaran<input name="name" value="<?= e($subject['name']) ?>" required></label>
        <label>Kelas<select name="class_id" required><?php foreach ($classes as $class): ?><option value="<?= (int)$class['id'] ?>" <?= (int)$subject['class_id'] === (int)$class['id'] ? 'selected' : '' ?>><?= e($class['name']) ?></option><?php endforeach; ?></select></label>
        <label class="span-2">Guru pengampu<select name="teacher_id" required><?php foreach ($teachers as $teacher): ?><option value="<?= (int)$teacher['id'] ?>" <?= (int)$subject['teacher_id'] === (int)$teacher['id'] ? 'selected' : '' ?>><?= e($teacher['full_name']) ?></option><?php endforeach; ?></select></label>
        <button class="button primary small" type="submit">Simpan perubahan</button></form></details></td></tr><?php endforeach; ?>
      </tbody></table></div></section>

    <?php elseif ($page === 'materials'):
      if ($user['role'] === 'guru'): ?>
        <section class="panel section"><div class="panel-heading"><div><p class="eyebrow">KONTEN BARU</p><h2>Terbitkan materi</h2></div></div>
          <?php if (!$subjects): ?><p class="muted">Admin perlu menambahkan mata pelajaran untuk Anda terlebih dahulu.</p><?php else: ?>
          <form method="post" enctype="multipart/form-data" class="form-grid"><?= csrf_field() ?><input type="hidden" name="action" value="create_material">
            <label>Mata pelajaran<select name="subject_id" required><?php foreach ($subjects as $subject): ?><option value="<?= (int)$subject['id'] ?>"><?= e($subject['name'] . ' · ' . $subject['class_name']) ?></option><?php endforeach; ?></select></label>
            <label>Judul materi<input name="title" required></label><label class="span-2">Deskripsi / isi materi<textarea name="content" rows="3"></textarea></label>
            <label>Lampiran (opsional, maks. 10 MB)<input type="file" name="attachment" accept=".pdf,.doc,.docx,.xls,.xlsx,.ppt,.pptx,.jpg,.jpeg,.png"></label>
            <div class="form-end"><button class="button primary" type="submit">Terbitkan materi</button></div>
          </form><?php endif; ?>
        </section>
      <?php endif;
      $query = $pdo->prepare(
        'SELECT m.*, s.name AS subject_name, c.name AS class_name, u.full_name AS teacher_name
         FROM materials m JOIN subjects s ON s.id = m.subject_id JOIN classes c ON c.id = s.class_id
         JOIN users u ON u.id = s.teacher_id WHERE ' .
        ($user['role'] === 'admin' ? '1=1' : ($user['role'] === 'guru' ? 's.teacher_id = ?' : 's.class_id = ?')) .
        ' ORDER BY m.created_at DESC'
      );
      $query->execute($user['role'] === 'admin' ? [] : [$user['role'] === 'guru' ? $user['id'] : $user['class_id']]);
      $materials = $query->fetchAll(); ?>
      <section class="section"><div class="section-heading"><div><p class="eyebrow">PERPUSTAKAAN KELAS</p><h2>Semua materi</h2></div><span class="count-label"><?= count($materials) ?> materi</span></div>
      <?php if (!$materials): ?><div class="empty-state">Belum ada materi yang diterbitkan.</div><?php else: ?><div class="content-grid"><?php foreach ($materials as $material): ?><article class="content-card"><div class="content-meta"><?= e($material['subject_name']) ?> <span>·</span> <?= e($material['class_name']) ?></div><h3><?= e($material['title']) ?></h3><p><?= nl2br(e($material['content'])) ?></p><div class="card-footer"><span><?= e($material['teacher_name']) ?> · <?= date('d M Y', strtotime($material['created_at'])) ?></span><?php if ($material['file_name']): ?><a class="button light small" href="?download=<?= (int)$material['id'] ?>&type=material">Unduh lampiran ↓</a><?php endif; ?></div>
        <?php if ($user['role'] === 'guru'): ?><details class="edit-details"><summary>Edit materi</summary><form method="post" enctype="multipart/form-data" class="form-grid edit-form"><?= csrf_field() ?><input type="hidden" name="action" value="update_material"><input type="hidden" name="material_id" value="<?= (int)$material['id'] ?>">
          <label>Judul materi<input name="title" value="<?= e($material['title']) ?>" required></label><label class="span-2">Deskripsi / isi materi<textarea name="content" rows="3"><?= e($material['content']) ?></textarea></label>
          <label>Ganti lampiran (opsional)<input type="file" name="attachment" accept=".pdf,.doc,.docx,.xls,.xlsx,.ppt,.pptx,.jpg,.jpeg,.png"></label><button class="button primary small" type="submit">Simpan perubahan</button>
        </form></details><?php endif; ?></article><?php endforeach; ?></div><?php endif; ?></section>

    <?php elseif ($page === 'assignments'):
      if ($user['role'] === 'guru'): ?>
        <section class="panel section"><div class="panel-heading"><div><p class="eyebrow">TUGAS BARU</p><h2>Berikan tugas</h2></div></div>
          <?php if (!$subjects): ?><p class="muted">Admin perlu menambahkan mata pelajaran untuk Anda terlebih dahulu.</p><?php else: ?>
          <form method="post" enctype="multipart/form-data" class="form-grid"><?= csrf_field() ?><input type="hidden" name="action" value="create_assignment">
            <label>Mata pelajaran<select name="subject_id" required><?php foreach ($subjects as $subject): ?><option value="<?= (int)$subject['id'] ?>"><?= e($subject['name'] . ' · ' . $subject['class_name']) ?></option><?php endforeach; ?></select></label>
            <label>Judul tugas<input name="title" required></label><label class="span-2">Petunjuk<textarea name="description" rows="3"></textarea></label>
            <label>Batas pengumpulan<input type="datetime-local" name="due_at"></label><label>Lampiran soal (opsional)<input type="file" name="attachment" accept=".pdf,.doc,.docx,.xls,.xlsx,.ppt,.pptx,.jpg,.jpeg,.png"></label>
            <div class="form-end"><button class="button primary" type="submit">Terbitkan tugas</button></div>
          </form><?php endif; ?>
        </section>
      <?php endif;
      $query = $pdo->prepare(
        'SELECT a.*, s.name AS subject_name, s.class_id, c.name AS class_name, u.full_name AS teacher_name
         FROM assignments a JOIN subjects s ON s.id = a.subject_id JOIN classes c ON c.id = s.class_id
         JOIN users u ON u.id = s.teacher_id WHERE ' .
        ($user['role'] === 'admin' ? '1=1' : ($user['role'] === 'guru' ? 's.teacher_id = ?' : 's.class_id = ?')) .
        ' ORDER BY a.created_at DESC'
      );
      $query->execute($user['role'] === 'admin' ? [] : [$user['role'] === 'guru' ? $user['id'] : $user['class_id']]);
      $assignments = $query->fetchAll(); ?>
      <section class="section"><div class="section-heading"><div><p class="eyebrow">RUANG TUGAS</p><h2><?= $user['role'] === 'siswa' ? 'Tugas untuk kelas Anda' : 'Daftar tugas' ?></h2></div><span class="count-label"><?= count($assignments) ?> tugas</span></div>
      <?php if (!$assignments): ?><div class="empty-state">Belum ada tugas yang diterbitkan.</div><?php else: ?><div class="content-grid"><?php foreach ($assignments as $assignment):
        $submission = null;
        if ($user['role'] === 'siswa') {
          $check = $pdo->prepare('SELECT * FROM submissions WHERE assignment_id = ? AND student_id = ?');
          $check->execute([$assignment['id'], $user['id']]);
          $submission = $check->fetch();
        }
        ?><article class="content-card"><div class="content-meta"><?= e($assignment['subject_name']) ?> <span>·</span> <?= e($assignment['class_name']) ?></div><h3><?= e($assignment['title']) ?></h3><p><?= nl2br(e($assignment['description'])) ?></p>
        <?php if ($assignment['due_at']): ?><p class="deadline">Batas: <?= date('d M Y, H:i', strtotime($assignment['due_at'])) ?></p><?php endif; ?>
        <?php if ($assignment['file_name']): ?><a class="inline-link" href="?download=<?= (int)$assignment['id'] ?>&type=assignment">Unduh lampiran soal ↓</a><?php endif; ?>
        <?php if ($user['role'] === 'siswa'): ?>
          <?php if ($submission): ?><div class="submission-status <?= $submission['grade'] !== null ? 'graded' : '' ?>"><?= $submission['grade'] !== null ? 'Nilai: ' . e((string)$submission['grade']) : 'Sudah dikumpulkan' ?> · <?= date('d M Y H:i', strtotime($submission['submitted_at'])) ?><?php if ($submission['grade'] !== null && $submission['feedback']): ?><br><span>Umpan balik: <?= e($submission['feedback']) ?></span><?php endif; ?></div><?php endif; ?>
          <form method="post" enctype="multipart/form-data" class="submit-form"><?= csrf_field() ?><input type="hidden" name="action" value="submit_assignment"><input type="hidden" name="assignment_id" value="<?= (int)$assignment['id'] ?>">
            <label><?= $submission ? 'Ganti file jawaban' : 'Unggah jawaban' ?><input type="file" name="submission" accept=".pdf,.doc,.docx,.xls,.xlsx,.ppt,.pptx,.jpg,.jpeg,.png" required></label>
            <input name="note" placeholder="Catatan untuk guru (opsional)"><button class="button primary small" type="submit"><?= $submission ? 'Kirim ulang' : 'Kumpulkan tugas' ?></button>
          </form>
        <?php elseif ($user['role'] === 'guru'):
          $submitted = $pdo->prepare('SELECT sub.*, u.full_name FROM submissions sub JOIN users u ON u.id = sub.student_id WHERE sub.assignment_id = ? ORDER BY sub.submitted_at DESC');
          $submitted->execute([$assignment['id']]);
          $submissions = $submitted->fetchAll();
          ?><details class="grading"><summary><?= count($submissions) ?> pengumpulan · Lihat / nilai</summary>
            <?php foreach ($submissions as $answer): ?><form method="post" class="grade-row"><?= csrf_field() ?><input type="hidden" name="action" value="grade_submission"><input type="hidden" name="submission_id" value="<?= (int)$answer['id'] ?>">
              <div><strong><?= e($answer['full_name']) ?></strong><small><?= date('d M Y H:i', strtotime($answer['submitted_at'])) ?> · <a href="?download=<?= (int)$answer['id'] ?>&type=submission">Unduh jawaban</a></small><?php if ($answer['note']): ?><small><?= e($answer['note']) ?></small><?php endif; ?></div>
              <input name="grade" type="number" min="0" max="100" step="0.01" value="<?= e($answer['grade'] === null ? '' : (string)$answer['grade']) ?>" placeholder="Nilai" required>
              <input name="feedback" value="<?= e($answer['feedback']) ?>" placeholder="Umpan balik">
              <button class="button light small" type="submit">Simpan</button>
            </form><?php endforeach; ?>
            <?php if (!$submissions): ?><p class="muted">Belum ada siswa yang mengumpulkan tugas.</p><?php endif; ?>
          </details>
          <details class="edit-details"><summary>Edit tugas</summary><form method="post" enctype="multipart/form-data" class="form-grid edit-form"><?= csrf_field() ?><input type="hidden" name="action" value="update_assignment"><input type="hidden" name="assignment_id" value="<?= (int)$assignment['id'] ?>">
            <label>Judul tugas<input name="title" value="<?= e($assignment['title']) ?>" required></label>
            <label>Batas pengumpulan<input type="datetime-local" name="due_at" value="<?= $assignment['due_at'] ? date('Y-m-d\TH:i', strtotime($assignment['due_at'])) : '' ?>"></label>
            <label class="span-2">Petunjuk<textarea name="description" rows="3"><?= e($assignment['description']) ?></textarea></label>
            <label>Ganti lampiran (opsional)<input type="file" name="attachment" accept=".pdf,.doc,.docx,.xls,.xlsx,.ppt,.pptx,.jpg,.jpeg,.png"></label>
            <button class="button primary small" type="submit">Simpan perubahan</button>
          </form></details>
        <?php endif; ?>
        <div class="card-footer"><span><?= e($assignment['teacher_name']) ?></span></div></article><?php endforeach; ?></div><?php endif; ?></section>

    <?php elseif ($page === 'grades' && $user['role'] === 'siswa'):
      $grades = $pdo->prepare(
        'SELECT sub.*, a.title, s.name AS subject_name FROM submissions sub
         JOIN assignments a ON a.id = sub.assignment_id JOIN subjects s ON s.id = a.subject_id
         WHERE sub.student_id = ? ORDER BY sub.submitted_at DESC'
      );
      $grades->execute([$user['id']]);
      $gradeRows = $grades->fetchAll(); ?>
      <section class="section"><div class="section-heading"><div><p class="eyebrow">HASIL BELAJAR</p><h2>Nilai dan umpan balik</h2></div></div>
      <?php if (!$gradeRows): ?><div class="empty-state">Belum ada tugas yang dikumpulkan.</div><?php else: ?><div class="panel table-wrap"><table><thead><tr><th>Mata pelajaran</th><th>Tugas</th><th>Dikumpulkan</th><th>Nilai</th><th>Umpan balik</th></tr></thead><tbody>
      <?php foreach ($gradeRows as $row): ?><tr><td><?= e($row['subject_name']) ?></td><td><?= e($row['title']) ?></td><td><?= date('d M Y H:i', strtotime($row['submitted_at'])) ?></td><td><strong class="<?= $row['grade'] !== null ? 'grade-value' : '' ?>"><?= $row['grade'] === null ? 'Belum dinilai' : e((string)$row['grade']) ?></strong></td><td><?= e($row['feedback'] ?: '—') ?></td></tr><?php endforeach; ?>
      </tbody></table></div><?php endif; ?></section>
    <?php elseif ($page === 'profile'): ?>
      <section class="panel profile-panel"><div class="panel-heading"><div><p class="eyebrow">PENGATURAN AKUN</p><h2>Edit identitas</h2></div></div>
        <p class="muted">Perbarui nama dan username Anda. Masukkan password saat ini untuk mengonfirmasi perubahan.</p>
        <form method="post" class="form-grid profile-form"><?= csrf_field() ?><input type="hidden" name="action" value="update_profile">
          <label>Nama lengkap<input name="full_name" value="<?= e($user['full_name']) ?>" required></label>
          <label>Username<input name="username" value="<?= e($user['username']) ?>" required></label>
          <label>Password saat ini<input type="password" name="current_password" autocomplete="current-password" required></label>
          <label>Password baru (opsional, minimal 6 karakter)<input type="password" name="new_password" minlength="6" autocomplete="new-password"></label>
          <div class="form-end"><button class="button primary" type="submit">Simpan identitas</button></div>
        </form>
      </section>
    <?php endif; ?>
    <footer class="footer">© <?= date('Y') ?> SMAN 9 Wajo · Learning Management System</footer>
  </main>
</div>
</body></html>
