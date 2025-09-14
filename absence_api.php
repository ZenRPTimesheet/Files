<?php
// NHS Security Headers
header('Content-Type: application/json');
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Content-Security-Policy: default-src \'self\'; script-src \'self\' \'unsafe-inline\'; style-src \'self\' \'unsafe-inline\';');
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Headers: Content-Type");
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE');

// NHS Session Management
session_start();
session_regenerate_id(true);

// NHS Audit Logger
class NHSAuditLogger {
    private $pdo;
    
    public function __construct($database_connection) {
        $this->pdo = $database_connection;
        $this->createAuditTable();
    }
    
    private function createAuditTable() {
        try {
            $this->pdo->exec("
                CREATE TABLE IF NOT EXISTS audit_log (
                    id SERIAL PRIMARY KEY,
                    user_id VARCHAR(50),
                    user_role VARCHAR(20),
                    action VARCHAR(100),
                    target_employee_id VARCHAR(50),
                    data_type VARCHAR(50),
                    details JSON,
                    ip_address VARCHAR(45),
                    user_agent TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ");
        } catch (PDOException $e) {
            error_log("Audit table creation failed: " . $e->getMessage());
        }
    }
    
    public function logDataAccess($userId, $userRole, $action, $targetEmployeeId = null, $dataType = null, $details = []) {
        try {
            $stmt = $this->pdo->prepare("
                INSERT INTO audit_log (user_id, user_role, action, target_employee_id, data_type, details, ip_address, user_agent)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ");
            $stmt->execute([
                $userId,
                $userRole,
                $action,
                $targetEmployeeId,
                $dataType,
                json_encode($details),
                $_SERVER['REMOTE_ADDR'] ?? 'unknown',
                $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
            ]);
        } catch (PDOException $e) {
            error_log("Audit logging failed: " . $e->getMessage());
        }
    }
}

// NHS Session Security Manager
class NHSSessionManager {
    private $timeout_minutes;
    private $audit_logger;
    
    public function __construct($timeout_minutes = 30, $audit_logger = null) {
        $this->timeout_minutes = $timeout_minutes;
        $this->audit_logger = $audit_logger;
    }
    
    public function checkSessionTimeout() {
        if (isset($_SESSION['last_activity'])) {
            $inactive_time = time() - $_SESSION['last_activity'];
            if ($inactive_time > ($this->timeout_minutes * 60)) {
                $this->destroySession('session_timeout');
                return false;
            }
        }
        $_SESSION['last_activity'] = time();
        return true;
    }
    
    public function requireAuthentication() {
        if (!$this->checkSessionTimeout()) {
            http_response_code(401);
            echo json_encode(['error' => 'Session expired. Please login again.']);
            exit;
        }
        
        if (!isset($_SESSION['user_id']) || !isset($_SESSION['user_role'])) {
            http_response_code(401);
            echo json_encode(['error' => 'Authentication required']);
            exit;
        }
    }
    
    public function requireRole($allowedRoles) {
        $this->requireAuthentication();
        if (!in_array($_SESSION['user_role'], $allowedRoles)) {
            if ($this->audit_logger) {
                $this->audit_logger->logDataAccess(
                    $_SESSION['user_id'] ?? 'unknown',
                    $_SESSION['user_role'] ?? 'unknown',
                    'unauthorized_access_attempt',
                    null,
                    'absence_portal',
                    ['required_roles' => $allowedRoles]
                );
            }
            http_response_code(403);
            echo json_encode(['error' => 'Insufficient permissions']);
            exit;
        }
    }
    
    public function destroySession($reason = 'logout') {
        if ($this->audit_logger && isset($_SESSION['user_id'])) {
            $this->audit_logger->logDataAccess(
                $_SESSION['user_id'],
                $_SESSION['user_role'] ?? 'unknown',
                'session_destroyed',
                null,
                'authentication',
                ['reason' => $reason]
            );
        }
        session_destroy();
    }
}

// NHS Email Service
class NHSEmailService {
    private $smtp_host;
    private $smtp_port;
    private $smtp_username;
    private $smtp_password;
    private $from_email;
    private $from_name;
    
    public function __construct() {
        $this->smtp_host = getenv('SMTP_HOST') ?: 'localhost';
        $this->smtp_port = getenv('SMTP_PORT') ?: 587;
        $this->smtp_username = getenv('SMTP_USERNAME') ?: '';
        $this->smtp_password = getenv('SMTP_PASSWORD') ?: '';
        $this->from_email = getenv('FROM_EMAIL') ?: 'noreply@nhs.uk';
        $this->from_name = getenv('FROM_NAME') ?: 'NHS Portal System';
    }
    
    public function sendPasswordReset($to_email, $reset_token, $user_name) {
        $reset_link = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http') . 
                     '://' . $_SERVER['HTTP_HOST'] . 
                     dirname($_SERVER['REQUEST_URI']) . 
                     '/reset_password.php?token=' . urlencode($reset_token);
        
        $subject = 'NHS Portal - Password Reset Request';
        $message = $this->getPasswordResetEmailTemplate($user_name, $reset_link);
        
        $headers = [
            'MIME-Version: 1.0',
            'Content-type: text/html; charset=UTF-8',
            'From: ' . $this->from_name . ' <' . $this->from_email . '>',
            'Reply-To: ' . $this->from_email,
            'X-Mailer: NHS Portal System'
        ];
        
        return mail($to_email, $subject, $message, implode("\r\n", $headers));
    }
    
    private function getPasswordResetEmailTemplate($user_name, $reset_link) {
        return "
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset='UTF-8'>
            <meta name='viewport' content='width=device-width, initial-scale=1.0'>
            <title>Password Reset</title>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 20px; background-color: #f4f4f4; }
                .container { max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
                .header { background: linear-gradient(135deg, #2c3e50 0%, #3498db 100%); color: white; padding: 20px; border-radius: 8px; margin-bottom: 30px; text-align: center; }
                .content { margin-bottom: 30px; }
                .button { display: inline-block; background: #007bff; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; margin: 20px 0; }
                .footer { font-size: 12px; color: #666; border-top: 1px solid #eee; padding-top: 20px; margin-top: 30px; }
                .warning { background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 20px 0; }
            </style>
        </head>
        <body>
            <div class='container'>
                <div class='header'>
                    <h1>NHS Portal</h1>
                    <h2>Password Reset Request</h2>
                </div>
                
                <div class='content'>
                    <p>Dear " . htmlspecialchars($user_name) . ",</p>
                    
                    <p>We received a request to reset your NHS Portal password. If you made this request, please click the button below to reset your password:</p>
                    
                    <div style='text-align: center; margin: 30px 0;'>
                        <a href='" . htmlspecialchars($reset_link) . "' class='button'>Reset My Password</a>
                    </div>
                    
                    <p>Alternatively, you can copy and paste this link into your browser:</p>
                    <p style='word-break: break-all; background: #f8f9fa; padding: 10px; border-radius: 5px; font-family: monospace;'>
                        " . htmlspecialchars($reset_link) . "
                    </p>
                    
                    <div class='warning'>
                        <strong>Security Notice:</strong>
                        <ul>
                            <li>This link will expire in 1 hour for security reasons</li>
                            <li>If you didn't request this reset, please ignore this email</li>
                            <li>Never share this link with anyone else</li>
                            <li>Contact IT support if you have concerns</li>
                        </ul>
                    </div>
                </div>
                
                <div class='footer'>
                    <p><strong>NHS Portal System</strong></p>
                    <p>This is an automated message. Please do not reply to this email.</p>
                    <p>If you need assistance, contact your IT support team.</p>
                </div>
            </div>
        </body>
        </html>
        ";
    }
}

class DatabaseConfig {
    private static $host = null;
    private static $port = '5432';
    private static $dbname = null;
    private static $username = null;
    private static $password = null;
    
    public static function getConnection() {
        self::$host = getenv('DB_HOST');
        self::$dbname = getenv('DB_NAME');
        self::$username = getenv('DB_USER');
        self::$password = getenv('DB_PASS');
        
        try {
            $dsn = "pgsql:host=" . self::$host . ";port=" . self::$port . ";dbname=" . self::$dbname;
            $pdo = new PDO($dsn, self::$username, self::$password);
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            return $pdo;
        } catch (PDOException $e) {
            http_response_code(500);
            echo json_encode(['error' => 'Database connection failed']);
            exit;
        }
    }
}

try {
    $pdo = DatabaseConfig::getConnection();
    $audit = new NHSAuditLogger($pdo);
    $session = new NHSSessionManager(30, $audit);
    $emailService = new NHSEmailService();
    
    $input = json_decode(file_get_contents("php://input"), true);
    $action = $input['action'] ?? '';

    if ($action === 'login') {
        $username = filter_var($input['username'] ?? '', FILTER_SANITIZE_STRING);
        $password = $input['password'] ?? '';

        $stmt = $pdo->prepare("SELECT id, username, first_name, last_name, role, password, approval_level, email 
                               FROM users 
                               WHERE username = ? AND role IN ('manager', 'hr', 'admin')");
        $stmt->execute([$username]);
        $user = $stmt->fetch();

        if ($user && password_verify($password, $user['password'])) {
            session_regenerate_id(true);
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['user_role'] = $user['role'];
            $_SESSION['approval_level'] = $user['approval_level'];
            $_SESSION['last_activity'] = time();
            
            $audit->logDataAccess($user['id'], $user['role'], 'login_success', null, 'authentication');
            
            echo json_encode([
                "success" => true,
                "user" => [
                    "id" => $user['id'],
                    "username" => $user['username'],
                    "firstName" => $user['first_name'] ?? '',
                    "lastName" => $user['last_name'] ?? '',
                    "role" => $user['role'],
                    "approval_level" => $user['approval_level']
                ]
            ]);
        } else {
            $audit->logDataAccess($username, 'unknown', 'login_failed', null, 'authentication');
            echo json_encode(["success" => false, "error" => "Invalid login credentials"]);
        }
        exit;
    }

    if ($action === 'reset_password') {
        $email = filter_var($input['email'] ?? '', FILTER_SANITIZE_EMAIL);
        
        if (!$email || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            echo json_encode(["success" => false, "error" => "Valid email address required"]);
            exit;
        }
        
        try {
            // Create password_resets table if it doesn't exist
            $pdo->exec("
                CREATE TABLE IF NOT EXISTS password_resets (
                    id SERIAL PRIMARY KEY,
                    user_id VARCHAR(50) NOT NULL,
                    email VARCHAR(255) NOT NULL,
                    token VARCHAR(255) NOT NULL,
                    expires_at TIMESTAMP NOT NULL,
                    used BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ");
            
            // Check if user exists with manager/hr/admin role
            $stmt = $pdo->prepare("SELECT id, username, first_name, last_name, email 
                                   FROM users 
                                   WHERE email = ? AND role IN ('manager', 'hr', 'admin')");
            $stmt->execute([$email]);
            $user = $stmt->fetch();
            
            if ($user) {
                // Generate secure token
                $token = bin2hex(random_bytes(32));
                $expires_at = date('Y-m-d H:i:s', time() + 3600); // 1 hour
                
                // Store reset token
                $stmt = $pdo->prepare("INSERT INTO password_resets (user_id, email, token, expires_at) VALUES (?, ?, ?, ?)");
                $stmt->execute([$user['id'], $email, hash('sha256', $token), $expires_at]);
                
                // Send email
                $full_name = trim(($user['first_name'] ?? '') . ' ' . ($user['last_name'] ?? '')) ?: $user['username'];
                $emailSent = $emailService->sendPasswordReset($email, $token, $full_name);
                
                $audit->logDataAccess($user['id'], 'system', 'password_reset_requested', null, 'authentication', ['email' => $email]);
                
                if ($emailSent) {
                    echo json_encode(["success" => true, "message" => "Password reset instructions sent to your email"]);
                } else {
                    echo json_encode(["success" => false, "error" => "Failed to send email. Please contact IT support."]);
                }
            } else {
                // Don't reveal whether email exists or not - security measure
                $audit->logDataAccess('unknown', 'system', 'password_reset_attempted_invalid_email', null, 'authentication', ['email' => $email]);
                echo json_encode(["success" => true, "message" => "If this email is registered, you will receive reset instructions"]);
            }
        } catch (Exception $e) {
            error_log("Password reset error: " . $e->getMessage());
            echo json_encode(["success" => false, "error" => "System error. Please try again later."]);
        }
        exit;
    }

    // All other actions require authentication
    $session->requireRole(['manager', 'hr', 'admin']);

    if ($action === 'get_departments_teams') {
        try {
            $audit->logDataAccess($_SESSION['user_id'], $_SESSION['user_role'], 'view_departments_teams', null, 'organizational_data');
            
            $deptStmt = $pdo->query("SELECT DISTINCT department FROM employees WHERE department IS NOT NULL ORDER BY department");
            $departments = $deptStmt->fetchAll(PDO::FETCH_COLUMN);
            
            $teamStmt = $pdo->query("SELECT DISTINCT department, team FROM employees WHERE department IS NOT NULL AND team IS NOT NULL ORDER BY department, team");
            $teamData = $teamStmt->fetchAll(PDO::FETCH_ASSOC);
            
            $teamsByDept = [];
            foreach ($teamData as $row) {
                $teamsByDept[$row['department']][] = $row['team'];
            }
            
            echo json_encode([
                "success" => true,
                "departments" => $departments,
                "teams_by_department" => $teamsByDept
            ]);
        } catch (Exception $e) {
            echo json_encode(["success" => false, "error" => "Failed to load departments/teams"]);
        }
        exit;
    }

    if ($action === 'get_absences') {
        $department = filter_var($input['department'] ?? '', FILTER_SANITIZE_STRING);
        $team = filter_var($input['team'] ?? '', FILTER_SANITIZE_STRING);
        $absenceType = filter_var($input['absence_type'] ?? '', FILTER_SANITIZE_STRING);
        $dateFrom = filter_var($input['date_from'] ?? '', FILTER_SANITIZE_STRING);
        $dateTo = filter_var($input['date_to'] ?? '', FILTER_SANITIZE_STRING);
        $manager_id = $_SESSION['user_id'];
        
        $stmt = $pdo->prepare("SELECT approval_level FROM users WHERE id = ?");
        $stmt->execute([$manager_id]);
        $manager = $stmt->fetch(PDO::FETCH_ASSOC);
        $manager_approval_level = $manager['approval_level'] ?? null;
        
        if (!$manager_approval_level) {
            echo json_encode(["success" => false, "error" => "Manager approval level not found"]);
            exit;
        }
        
        $audit->logDataAccess($manager_id, $_SESSION['user_role'], 'view_absence_data', null, 'absence_records', [
            'department' => $department,
            'team' => $team,
            'date_range' => "$dateFrom to $dateTo"
        ]);
        
        try {
            $whereClauses = [
                "pt.absence_type IS NOT NULL", 
                "pt.absence_type != ''", 
                "pt.absence_type != 'Annual Leave'", 
                "pt.absence_hours > '00:00:00'",
                "CAST(e.pay_grade AS INTEGER) < ?"
            ];
            $params = [$manager_approval_level];
            
            if (!empty($department)) {
                $whereClauses[] = "e.department = ?";
                $params[] = $department;
            }
            
            if (!empty($team)) {
                $whereClauses[] = "e.team = ?";
                $params[] = $team;
            }
            
            if (!empty($absenceType)) {
                $whereClauses[] = "pt.absence_type = ?";
                $params[] = $absenceType;
            }
            
            if (!empty($dateFrom)) {
                $whereClauses[] = "pt.sched_date >= ?";
                $params[] = $dateFrom;
            }
            
            if (!empty($dateTo)) {
                $whereClauses[] = "pt.sched_date <= ?";
                $params[] = $dateTo;
            }
            
            $whereSQL = implode(' AND ', $whereClauses);
            
            $stmt = $pdo->prepare("
                SELECT e.employee_id, e.employee_name, pt.sched_date, pt.absence_type, pt.absence_hours, 
                       e.department, e.team, e.job_title, e.site, e.pay_grade
                FROM employees e
                INNER JOIN processed_timesheet pt ON e.employee_id = pt.employee_id
                WHERE $whereSQL
                ORDER BY pt.sched_date DESC, e.employee_id
                LIMIT 100
            ");
            $stmt->execute($params);
            $absenceData = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            // Log each employee's data accessed
            $employeeIds = array_unique(array_column($absenceData, 'employee_id'));
            foreach ($employeeIds as $empId) {
                $audit->logDataAccess($manager_id, $_SESSION['user_role'], 'view_employee_absence', $empId, 'personal_data');
            }
            
            $summaryStmt = $pdo->prepare("
                SELECT 
                    COUNT(CASE WHEN LOWER(pt.absence_type) LIKE '%sick%' THEN 1 END) as sick_count,
                    COUNT(CASE WHEN LOWER(pt.absence_type) LIKE '%maternity%' OR LOWER(pt.absence_type) LIKE '%paternity%' THEN 1 END) as maternity_count,
                    COUNT(CASE WHEN LOWER(pt.absence_type) LIKE '%bereavement%' THEN 1 END) as bereavement_count,
                    COUNT(CASE WHEN LOWER(pt.absence_type) LIKE '%study%' THEN 1 END) as study_count,
                    COUNT(CASE WHEN LOWER(pt.absence_type) LIKE '%unpaid%' THEN 1 END) as unpaid_count,
                    SUM(EXTRACT(EPOCH FROM pt.absence_hours)/3600) as total_hours
                FROM employees e
                INNER JOIN processed_timesheet pt ON e.employee_id = pt.employee_id
                WHERE $whereSQL
            ");
            $summaryStmt->execute($params);
            $summary = $summaryStmt->fetch(PDO::FETCH_ASSOC);
            
            echo json_encode([
                "success" => true,
                "data" => $absenceData,
                "summary" => [
                    "sick_count" => (int)($summary['sick_count'] ?? 0),
                    "maternity_count" => (int)($summary['maternity_count'] ?? 0),
                    "bereavement_count" => (int)($summary['bereavement_count'] ?? 0),
                    "study_count" => (int)($summary['study_count'] ?? 0),
                    "unpaid_count" => (int)($summary['unpaid_count'] ?? 0),
                    "total_hours" => round($summary['total_hours'] ?? 0, 1)
                ]
            ]);
            
        } catch (Exception $e) {
            echo json_encode(["success" => false, "error" => "Failed to load absence data"]);
        }
        exit;
    }

    if ($action === 'get_current_absences') {
        $manager_id = $_SESSION['user_id'];
        
        $stmt = $pdo->prepare("SELECT approval_level FROM users WHERE id = ?");
        $stmt->execute([$manager_id]);
        $manager = $stmt->fetch(PDO::FETCH_ASSOC);
        $manager_approval_level = $manager['approval_level'] ?? null;
        
        if (!$manager_approval_level) {
            echo json_encode(["success" => false, "error" => "Manager approval level not found"]);
            exit;
        }
        
        $audit->logDataAccess($manager_id, $_SESSION['user_role'], 'view_current_absences', null, 'absence_records');
        
        try {
            $stmt = $pdo->prepare("
                WITH recent_absences AS (
                    SELECT 
                        e.employee_id, 
                        e.employee_name, 
                        pt.absence_type,
                        e.department,
                        e.team,
                        MIN(pt.sched_date) as start_date,
                        MAX(pt.sched_date) as end_date,
                        COUNT(*) as total_days,
                        SUM(EXTRACT(EPOCH FROM pt.absence_hours)/3600) as total_hours
                    FROM employees e
                    INNER JOIN processed_timesheet pt ON e.employee_id = pt.employee_id
                    WHERE pt.absence_type IS NOT NULL 
                    AND pt.absence_type != '' 
                    AND pt.absence_type != 'Annual Leave'
                    AND pt.absence_hours > '00:00:00'
                    AND pt.sched_date >= CURRENT_DATE - INTERVAL '30 days'
                    AND CAST(e.pay_grade AS INTEGER) < ?
                    GROUP BY e.employee_id, e.employee_name, pt.absence_type, e.department, e.team
                )
                SELECT 
                    employee_id, 
                    employee_name, 
                    absence_type,
                    start_date,
                    end_date,
                    total_days,
                    ROUND(total_hours, 1) as total_hours,
                    department,
                    team
                FROM recent_absences
                WHERE end_date >= CURRENT_DATE - INTERVAL '7 days'
                ORDER BY start_date DESC
            ");
            $stmt->execute([$manager_approval_level]);
            $currentAbsences = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            // Log each employee's data accessed
            $employeeIds = array_unique(array_column($currentAbsences, 'employee_id'));
            foreach ($employeeIds as $empId) {
                $audit->logDataAccess($manager_id, $_SESSION['user_role'], 'view_employee_current_absence', $empId, 'personal_data');
            }
            
            echo json_encode([
                "success" => true,
                "data" => $currentAbsences
            ]);
            
        } catch (Exception $e) {
            echo json_encode(["success" => false, "error" => "Failed to load current absences"]);
        }
        exit;
    }

    if ($action === 'logout') {
        $session->destroySession('user_logout');
        echo json_encode(["success" => true, "message" => "Logged out successfully"]);
        exit;
    }

    echo json_encode(["success" => false, "error" => "Unknown action: $action"]);

} catch (Exception $e) {
    if (isset($audit) && isset($_SESSION['user_id'])) {
        $audit->logDataAccess($_SESSION['user_id'], $_SESSION['user_role'] ?? 'unknown', 'system_error', null, 'api_error', ['error' => $e->getMessage()]);
    }
    echo json_encode(["success" => false, "error" => "API Error"]);
}
?>