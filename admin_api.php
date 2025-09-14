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

if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
    http_response_code(200);
    exit();
}

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
                    'admin_portal',
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

class DatabaseConfig {
    private static $host = null;
    private static $port = '5432';
    private static $dbname = null;
    private static $username = null;
    private static $password = null;
    
    public static function getConnection() {
        // Get credentials from environment variables
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
            error_log("NHS Admin API: Database connection failed: " . $e->getMessage());
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
    
    $input = json_decode(file_get_contents("php://input"), true);
    $action = $input['action'] ?? '';

    // --- ADMIN LOGIN (admin role only) ---
    if ($action === 'admin_login') {
        $username = filter_var($input['username'] ?? '', FILTER_SANITIZE_STRING);
        $password = $input['password'] ?? '';

        $stmt = $pdo->prepare("SELECT id, username, first_name, last_name, role, password, approval_level 
                               FROM users 
                               WHERE username = ? AND role = 'admin'");
        $stmt->execute([$username]);
        $user = $stmt->fetch();

        if ($user && password_verify($password, $user['password'])) {
            session_regenerate_id(true);
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['user_role'] = $user['role'];
            $_SESSION['approval_level'] = $user['approval_level'];
            $_SESSION['last_activity'] = time();
            
            $audit->logDataAccess($user['id'], $user['role'], 'admin_login_success', null, 'authentication');
            
            echo json_encode([
                "success" => true,
                "user" => [
                    "id" => $user['id'],
                    "username" => $user['username'],
                    "firstName" => $user['first_name'] ?? '',
                    "lastName" => $user['last_name'] ?? '',
                    "role" => $user['role'],
                    "approvalLevel" => $user['approval_level']
                ]
            ]);
        } else {
            $audit->logDataAccess($username, 'unknown', 'admin_login_failed', null, 'authentication');
            echo json_encode(["success" => false, "error" => "Invalid admin credentials"]);
        }
        exit;
    }

    // All other actions require admin authentication
    $session->requireRole(['admin']);

    // --- GET USER STATISTICS ---
    if ($action === 'get_user_stats') {
        try {
            $audit->logDataAccess($_SESSION['user_id'], $_SESSION['user_role'], 'view_user_statistics', null, 'system_data');
            
            $stmt = $pdo->query("
                SELECT 
                    COUNT(*) as total,
                    COUNT(CASE WHEN approval_level >= 3 THEN 1 END) as managers,
                    COUNT(CASE WHEN approval_level = 2 THEN 1 END) as supervisors,
                    COUNT(CASE WHEN approval_level = 1 THEN 1 END) as employees
                FROM users
            ");
            $stats = $stmt->fetch(PDO::FETCH_ASSOC);
            
            echo json_encode([
                "success" => true,
                "stats" => $stats
            ]);
        } catch (Exception $e) {
            echo json_encode(["success" => false, "error" => "Failed to get statistics: " . $e->getMessage()]);
        }
        exit;
    }

    // --- GET ALL USERS ---
    if ($action === 'get_all_users') {
        try {
            $audit->logDataAccess($_SESSION['user_id'], $_SESSION['user_role'], 'view_all_users', null, 'user_data');
            
            $stmt = $pdo->query("
                SELECT id, username, first_name, last_name, role, approval_level, 
                       created_date, last_login_date
                FROM users 
                ORDER BY approval_level DESC, last_name ASC, first_name ASC
            ");
            $users = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            // Log access to each user's data
            foreach ($users as $user) {
                $audit->logDataAccess($_SESSION['user_id'], $_SESSION['user_role'], 'view_user_details', $user['id'], 'personal_data');
            }
            
            echo json_encode([
                "success" => true,
                "users" => $users
            ]);
        } catch (Exception $e) {
            echo json_encode(["success" => false, "error" => "Failed to get users: " . $e->getMessage()]);
        }
        exit;
    }

    // --- ADD NEW USER ---
    if ($action === 'add_user') {
        $username = filter_var($input['username'] ?? '', FILTER_SANITIZE_STRING);
        $password = $input['password'] ?? '';
        $firstName = filter_var($input['firstName'] ?? '', FILTER_SANITIZE_STRING);
        $lastName = filter_var($input['lastName'] ?? '', FILTER_SANITIZE_STRING);
        $role = filter_var($input['role'] ?? '', FILTER_SANITIZE_STRING);
        $approvalLevel = filter_var($input['approvalLevel'] ?? 1, FILTER_VALIDATE_INT);

        $audit->logDataAccess($_SESSION['user_id'], $_SESSION['user_role'], 'create_user_attempt', null, 'user_management', [
            'username' => $username,
            'role' => $role,
            'approval_level' => $approvalLevel
        ]);

        if (empty($username) || empty($password) || empty($role)) {
            echo json_encode(["success" => false, "error" => "Username, password, and role are required"]);
            exit;
        }

        // Validate password strength
        if (strlen($password) < 12) {
            echo json_encode(["success" => false, "error" => "Password must be at least 12 characters long"]);
            exit;
        }

        try {
            // Check if username already exists
            $stmt = $pdo->prepare("SELECT id FROM users WHERE username = ?");
            $stmt->execute([$username]);
            if ($stmt->fetch()) {
                echo json_encode(["success" => false, "error" => "Username already exists"]);
                exit;
            }

            // Hash password before storing
            $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

            // Insert new user
            $stmt = $pdo->prepare("
                INSERT INTO users (username, password, first_name, last_name, role, approval_level, created_date)
                VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                RETURNING id
            ");
            $stmt->execute([$username, $hashedPassword, $firstName, $lastName, $role, $approvalLevel]);
            $newUserId = $stmt->fetch(PDO::FETCH_ASSOC)['id'];

            $audit->logDataAccess($_SESSION['user_id'], $_SESSION['user_role'], 'user_created', $newUserId, 'user_management', [
                'username' => $username,
                'role' => $role
            ]);

            echo json_encode([
                "success" => true,
                "message" => "User created successfully",
                "user_id" => $newUserId
            ]);
        } catch (Exception $e) {
            echo json_encode(["success" => false, "error" => "Failed to create user: " . $e->getMessage()]);
        }
        exit;
    }

    // --- UPDATE USER ---
    if ($action === 'update_user') {
        $userId = filter_var($input['userId'] ?? '', FILTER_VALIDATE_INT);
        $firstName = filter_var($input['firstName'] ?? '', FILTER_SANITIZE_STRING);
        $lastName = filter_var($input['lastName'] ?? '', FILTER_SANITIZE_STRING);
        $role = filter_var($input['role'] ?? '', FILTER_SANITIZE_STRING);
        $approvalLevel = filter_var($input['approvalLevel'] ?? 1, FILTER_VALIDATE_INT);
        $password = $input['password'] ?? null;

        if (empty($userId)) {
            echo json_encode(["success" => false, "error" => "User ID is required"]);
            exit;
        }

        $audit->logDataAccess($_SESSION['user_id'], $_SESSION['user_role'], 'update_user_attempt', $userId, 'user_management', [
            'target_user_id' => $userId,
            'new_role' => $role,
            'new_approval_level' => $approvalLevel
        ]);

        try {
            if ($password) {
                // Validate password strength if provided
                if (strlen($password) < 12) {
                    echo json_encode(["success" => false, "error" => "Password must be at least 12 characters long"]);
                    exit;
                }
                
                // Hash password before storing
                $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
                
                // Update with new password
                $stmt = $pdo->prepare("
                    UPDATE users 
                    SET first_name = ?, last_name = ?, role = ?, approval_level = ?, password = ?
                    WHERE id = ?
                ");
                $stmt->execute([$firstName, $lastName, $role, $approvalLevel, $hashedPassword, $userId]);
            } else {
                // Update without changing password
                $stmt = $pdo->prepare("
                    UPDATE users 
                    SET first_name = ?, last_name = ?, role = ?, approval_level = ?
                    WHERE id = ?
                ");
                $stmt->execute([$firstName, $lastName, $role, $approvalLevel, $userId]);
            }

            if ($stmt->rowCount() > 0) {
                $audit->logDataAccess($_SESSION['user_id'], $_SESSION['user_role'], 'user_updated', $userId, 'user_management', [
                    'password_changed' => !empty($password)
                ]);
                echo json_encode(["success" => true, "message" => "User updated successfully"]);
            } else {
                echo json_encode(["success" => false, "error" => "User not found or no changes made"]);
            }
        } catch (Exception $e) {
            echo json_encode(["success" => false, "error" => "Failed to update user: " . $e->getMessage()]);
        }
        exit;
    }

    // --- DELETE USER ---
    if ($action === 'delete_user') {
        $userId = filter_var($input['userId'] ?? '', FILTER_VALIDATE_INT);

        if (empty($userId)) {
            echo json_encode(["success" => false, "error" => "User ID is required"]);
            exit;
        }

        $audit->logDataAccess($_SESSION['user_id'], $_SESSION['user_role'], 'delete_user_attempt', $userId, 'user_management');

        try {
            $stmt = $pdo->prepare("DELETE FROM users WHERE id = ?");
            $stmt->execute([$userId]);

            if ($stmt->rowCount() > 0) {
                $audit->logDataAccess($_SESSION['user_id'], $_SESSION['user_role'], 'user_deleted', $userId, 'user_management');
                echo json_encode(["success" => true, "message" => "User deleted successfully"]);
            } else {
                echo json_encode(["success" => false, "error" => "User not found"]);
            }
        } catch (Exception $e) {
            echo json_encode(["success" => false, "error" => "Failed to delete user: " . $e->getMessage()]);
        }
        exit;
    }

    // --- GET HIERARCHY STATISTICS ---
    if ($action === 'get_hierarchy_stats') {
        try {
            $audit->logDataAccess($_SESSION['user_id'], $_SESSION['user_role'], 'view_hierarchy_stats', null, 'system_data');
            
            // Get count by level
            $stmt = $pdo->query("
                SELECT approval_level, COUNT(*) as count 
                FROM users 
                GROUP BY approval_level 
                ORDER BY approval_level DESC
            ");
            $levelData = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            $levels = [];
            foreach ($levelData as $row) {
                $levels[$row['approval_level']] = $row['count'];
            }

            // Get all users for hierarchy table
            $stmt = $pdo->query("
                SELECT id, username, first_name, last_name, role, approval_level
                FROM users 
                ORDER BY approval_level DESC, last_name ASC
            ");
            $users = $stmt->fetchAll(PDO::FETCH_ASSOC);

            echo json_encode([
                "success" => true,
                "levels" => $levels,
                "users" => $users
            ]);
        } catch (Exception $e) {
            echo json_encode(["success" => false, "error" => "Failed to get hierarchy stats: " . $e->getMessage()]);
        }
        exit;
    }

    // --- CHANGE APPROVAL LEVEL ---
    if ($action === 'change_approval_level') {
        $userId = filter_var($input['userId'] ?? '', FILTER_VALIDATE_INT);
        $newLevel = filter_var($input['newLevel'] ?? '', FILTER_VALIDATE_INT);

        if (empty($userId) || empty($newLevel)) {
            echo json_encode(["success" => false, "error" => "User ID and new level are required"]);
            exit;
        }

        if ($newLevel < 1 || $newLevel > 4) {
            echo json_encode(["success" => false, "error" => "Approval level must be between 1 and 4"]);
            exit;
        }

        $audit->logDataAccess($_SESSION['user_id'], $_SESSION['user_role'], 'change_approval_level', $userId, 'user_management', [
            'new_level' => $newLevel
        ]);

        try {
            $stmt = $pdo->prepare("UPDATE users SET approval_level = ? WHERE id = ?");
            $stmt->execute([$newLevel, $userId]);

            if ($stmt->rowCount() > 0) {
                echo json_encode(["success" => true, "message" => "Approval level updated successfully"]);
            } else {
                echo json_encode(["success" => false, "error" => "User not found"]);
            }
        } catch (Exception $e) {
            echo json_encode(["success" => false, "error" => "Failed to update approval level: " . $e->getMessage()]);
        }
        exit;
    }

    // --- GENERATE REPORT ---
    if ($action === 'generate_report') {
        $reportType = filter_var($input['reportType'] ?? '', FILTER_SANITIZE_STRING);
        $dateRange = filter_var($input['dateRange'] ?? 30, FILTER_VALIDATE_INT);

        $audit->logDataAccess($_SESSION['user_id'], $_SESSION['user_role'], 'generate_report', null, 'reporting', [
            'report_type' => $reportType,
            'date_range' => $dateRange
        ]);

        try {
            switch ($reportType) {
                case 'approval-history':
                    $stmt = $pdo->prepare("
                        SELECT 
                            COUNT(*) as total_approvals,
                            COUNT(CASE WHEN status = 'approved' THEN 1 END) as approved_count,
                            COUNT(CASE WHEN status = 'rejected' THEN 1 END) as rejected_count,
                            ROUND(AVG(EXTRACT(EPOCH FROM (approval_date - submission_date))/3600.0), 2) as avg_processing_hours,
                            COUNT(DISTINCT approved_by) as unique_approvers,
                            COUNT(DISTINCT employee_id) as unique_employees
                        FROM timesheet_submissions 
                        WHERE submission_date >= (CURRENT_DATE - INTERVAL '$dateRange days')
                        AND status IN ('approved', 'rejected')
                    ");
                    $stmt->execute();
                    $report = $stmt->fetch(PDO::FETCH_ASSOC);
                    
                    // Get top approvers
                    $stmt = $pdo->prepare("
                        SELECT approved_by, COUNT(*) as approval_count
                        FROM timesheet_submissions 
                        WHERE approval_date >= (CURRENT_DATE - INTERVAL '$dateRange days')
                        AND status = 'approved'
                        GROUP BY approved_by 
                        ORDER BY approval_count DESC 
                        LIMIT 5
                    ");
                    $stmt->execute();
                    $report['top_approvers'] = $stmt->fetchAll(PDO::FETCH_ASSOC);
                    break;

                case 'user-activity':
                    $stmt = $pdo->prepare("
                        SELECT 
                            COUNT(DISTINCT u.id) as total_active_users,
                            COUNT(CASE WHEN u.last_login_date >= (CURRENT_DATE - INTERVAL '7 days') THEN 1 END) as recent_logins,
                            COUNT(CASE WHEN u.role = 'manager' THEN 1 END) as manager_count,
                            COUNT(CASE WHEN u.role = 'admin' THEN 1 END) as admin_count
                        FROM users u
                        WHERE u.status = 'Active' OR u.status IS NULL
                    ");
                    $stmt->execute();
                    $report = $stmt->fetch(PDO::FETCH_ASSOC);
                    break;

                case 'manager-workload':
                    $stmt = $pdo->prepare("
                        SELECT 
                            ts.approved_by as manager_name,
                            COUNT(*) as timesheets_approved,
                            COUNT(DISTINCT ts.employee_id) as unique_employees,
                            ROUND(AVG(EXTRACT(EPOCH FROM (ts.approval_date - ts.submission_date))/3600.0), 2) as avg_approval_time_hours,
                            COUNT(CASE WHEN ts.status = 'rejected' THEN 1 END) as rejections
                        FROM timesheet_submissions ts
                        WHERE ts.approval_date >= (CURRENT_DATE - INTERVAL '$dateRange days')
                        AND ts.approved_by IS NOT NULL
                        GROUP BY ts.approved_by
                        ORDER BY timesheets_approved DESC
                    ");
                    $stmt->execute();
                    $report = $stmt->fetchAll(PDO::FETCH_ASSOC);
                    break;

                case 'system-usage':
                    $stmt = $pdo->prepare("
                        SELECT 
                            DATE_TRUNC('day', submission_date) as submission_day,
                            COUNT(*) as daily_submissions,
                            COUNT(DISTINCT employee_id) as unique_users
                        FROM timesheet_submissions 
                        WHERE submission_date >= (CURRENT_DATE - INTERVAL '$dateRange days')
                        GROUP BY DATE_TRUNC('day', submission_date)
                        ORDER BY submission_day DESC
                        LIMIT 10
                    ");
                    $stmt->execute();
                    $usage_data = $stmt->fetchAll(PDO::FETCH_ASSOC);
                    
                    $stmt = $pdo->prepare("
                        SELECT 
                            COUNT(*) as total_submissions,
                            COUNT(DISTINCT employee_id) as total_users,
                            COUNT(CASE WHEN status = 'draft' THEN 1 END) as draft_count,
                            COUNT(CASE WHEN status = 'submitted' THEN 1 END) as pending_count,
                            COUNT(CASE WHEN status = 'approved' THEN 1 END) as approved_count
                        FROM timesheet_submissions 
                        WHERE submission_date >= (CURRENT_DATE - INTERVAL '$dateRange days')
                    ");
                    $stmt->execute();
                    $summary = $stmt->fetch(PDO::FETCH_ASSOC);
                    
                    $report = [
                        'summary' => $summary,
                        'daily_usage' => $usage_data
                    ];
                    break;

                case 'compliance-audit':
                    $stmt = $pdo->prepare("
                        SELECT 
                            tm.original_record_employee_id as employee_id,
                            tm.field_name,
                            tm.original_value,
                            tm.modified_value,
                            tm.modified_by,
                            tm.modified_by_role,
                            tm.modification_date,
                            tm.status as mod_status,
                            tm.manager_override
                        FROM timesheet_modifications tm
                        WHERE tm.modification_date >= (CURRENT_DATE - INTERVAL '$dateRange days')
                        AND tm.manager_override = true
                        ORDER BY tm.modification_date DESC
                        LIMIT 50
                    ");
                    $stmt->execute();
                    $modifications = $stmt->fetchAll(PDO::FETCH_ASSOC);
                    
                    $stmt = $pdo->prepare("
                        SELECT 
                            COUNT(*) as total_modifications,
                            COUNT(CASE WHEN manager_override = true THEN 1 END) as manager_overrides,
                            COUNT(DISTINCT original_record_employee_id) as employees_modified,
                            COUNT(DISTINCT modified_by) as modifiers
                        FROM timesheet_modifications 
                        WHERE modification_date >= (CURRENT_DATE - INTERVAL '$dateRange days')
                    ");
                    $stmt->execute();
                    $summary = $stmt->fetch(PDO::FETCH_ASSOC);
                    
                    $report = [
                        'summary' => $summary,
                        'recent_modifications' => $modifications
                    ];
                    break;

                case 'audit-trail':
                    // NHS Audit Trail Report
                    $stmt = $pdo->prepare("
                        SELECT 
                            user_id,
                            user_role,
                            action,
                            target_employee_id,
                            data_type,
                            details,
                            ip_address,
                            timestamp
                        FROM audit_log 
                        WHERE timestamp >= (CURRENT_DATE - INTERVAL '$dateRange days')
                        ORDER BY timestamp DESC
                        LIMIT 100
                    ");
                    $stmt->execute();
                    $auditData = $stmt->fetchAll(PDO::FETCH_ASSOC);
                    
                    $stmt = $pdo->prepare("
                        SELECT 
                            COUNT(*) as total_events,
                            COUNT(DISTINCT user_id) as unique_users,
                            COUNT(CASE WHEN action LIKE '%login%' THEN 1 END) as login_events,
                            COUNT(CASE WHEN action LIKE '%view%' THEN 1 END) as data_access_events,
                            COUNT(CASE WHEN action LIKE '%unauthorized%' THEN 1 END) as security_violations
                        FROM audit_log 
                        WHERE timestamp >= (CURRENT_DATE - INTERVAL '$dateRange days')
                    ");
                    $stmt->execute();
                    $auditSummary = $stmt->fetch(PDO::FETCH_ASSOC);
                    
                    $report = [
                        'summary' => $auditSummary,
                        'recent_events' => $auditData
                    ];
                    break;

                default:
                    $report = ["error" => "Unknown report type"];
            }

            echo json_encode([
                "success" => true,
                "report" => $report
            ]);
        } catch (Exception $e) {
            echo json_encode(["success" => false, "error" => "Failed to generate report: " . $e->getMessage()]);
        }
        exit;
    }

    // --- SYNC EMPLOYEES FROM TIMESHEETS ---
    if ($action === 'sync_employees') {
        $audit->logDataAccess($_SESSION['user_id'], $_SESSION['user_role'], 'sync_employees', null, 'data_management');
        
        try {
            $stmt = $pdo->prepare("
                INSERT INTO employees (
                    employee_id, employee_name, department, job_title, site, hpw, 
                    muid, team, approval_level, employment_status
                )
                SELECT DISTINCT
                    tv_id::text as employee_id,
                    agent_name as employee_name,
                    MUID as department,
                    job_title,
                    site,
                    hpw,
                    MUID as muid,
                    Team as team,
                    1 as approval_level,
                    'Active' as employment_status
                FROM timesheets
                WHERE tv_id IS NOT NULL 
                AND agent_name IS NOT NULL
                ON CONFLICT (employee_id) 
                DO UPDATE SET
                    employee_name = EXCLUDED.employee_name,
                    department = EXCLUDED.department,
                    job_title = EXCLUDED.job_title,
                    site = EXCLUDED.site,
                    hpw = EXCLUDED.hpw,
                    muid = EXCLUDED.muid,
                    team = EXCLUDED.team,
                    employment_status = 'Active'
            ");
            $stmt->execute();
            $syncedCount = $stmt->rowCount();

            // Mark inactive employees
            $stmt = $pdo->prepare("
                UPDATE employees 
                SET employment_status = 'Inactive'
                WHERE employee_id NOT IN (
                    SELECT DISTINCT tv_id::text 
                    FROM timesheets 
                    WHERE exc_date >= CURRENT_DATE - INTERVAL '30 days'
                )
                AND employment_status = 'Active'
            ");
            $stmt->execute();
            $inactiveCount = $stmt->rowCount();

            echo json_encode([
                "success" => true,
                "message" => "Employee sync completed",
                "synced_count" => $syncedCount,
                "inactive_count" => $inactiveCount
            ]);
        } catch (Exception $e) {
            echo json_encode(["success" => false, "error" => "Failed to sync employees: " . $e->getMessage()]);
        }
        exit;
    }

    // --- DATA RETENTION CLEANUP ---
    if ($action === 'cleanup_audit_logs') {
        $retentionDays = filter_var($input['retention_days'] ?? 2555, FILTER_VALIDATE_INT); // Default 7 years
        
        $audit->logDataAccess($_SESSION['user_id'], $_SESSION['user_role'], 'audit_log_cleanup', null, 'data_retention', [
            'retention_days' => $retentionDays
        ]);
        
        try {
            $stmt = $pdo->prepare("
                DELETE FROM audit_log 
                WHERE timestamp < CURRENT_DATE - INTERVAL '$retentionDays days'
            ");
            $stmt->execute();
            $deletedCount = $stmt->rowCount();
            
            echo json_encode([
                "success" => true,
                "message" => "Audit log cleanup completed",
                "deleted_records" => $deletedCount
            ]);
        } catch (Exception $e) {
            echo json_encode(["success" => false, "error" => "Failed to cleanup audit logs: " . $e->getMessage()]);
        }
        exit;
    }

    if ($action === 'logout') {
        $session->destroySession('admin_logout');
        echo json_encode(["success" => true, "message" => "Logged out successfully"]);
        exit;
    }

    // Default if unknown action
    echo json_encode(["success" => false, "error" => "Unknown action: $action"]);

} catch (Exception $e) {
    if (isset($pdo) && $pdo->inTransaction()) {
        $pdo->rollback();
    }
    if (isset($audit) && isset($_SESSION['user_id'])) {
        $audit->logDataAccess($_SESSION['user_id'], $_SESSION['user_role'] ?? 'unknown', 'system_error', null, 'api_error', ['error' => $e->getMessage()]);
    }
    error_log("NHS Admin API Error: " . $e->getMessage());
    echo json_encode(["success" => false, "error" => "System error occurred"]);
}
?>