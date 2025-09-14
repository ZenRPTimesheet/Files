<?php
// NHS Security Implementation for Timesheet API
error_log("=== NHS SECURED TIMESHEET API STARTED ===");

// NHS Security Headers
header('Content-Type: application/json');
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Content-Security-Policy: default-src \'self\'; script-src \'self\' \'unsafe-inline\'; style-src \'self\' \'unsafe-inline\';');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE');
header('Access-Control-Allow-Headers: Content-Type');

// Start session for NHS compliance
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
    
    public function requireEmployeeAccess($employeeId) {
        if (!$this->checkSessionTimeout()) {
            http_response_code(401);
            echo json_encode(['error' => 'Session expired. Please login again.']);
            exit;
        }
        
        // For employee portal, they can only access their own data
        if (!isset($_SESSION['employee_id']) || $_SESSION['employee_id'] !== $employeeId) {
            if ($this->audit_logger) {
                $this->audit_logger->logDataAccess(
                    $_SESSION['employee_id'] ?? 'unknown',
                    'employee',
                    'unauthorized_data_access_attempt',
                    $employeeId,
                    'personal_data',
                    ['attempted_employee_id' => $employeeId]
                );
            }
            http_response_code(403);
            echo json_encode(['error' => 'Access denied - you can only view your own timesheet data']);
            exit;
        }
    }
    
    public function destroySession($reason = 'logout') {
        if ($this->audit_logger && isset($_SESSION['employee_id'])) {
            $this->audit_logger->logDataAccess(
                $_SESSION['employee_id'],
                'employee',
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
            error_log("NHS Timesheet API: Database connection successful");
            return $pdo;
        } catch (PDOException $e) {
            error_log("NHS Timesheet API: Database connection failed: " . $e->getMessage());
            http_response_code(500);
            echo json_encode(['error' => 'Database connection failed']);
            exit;
        }
    }
}

// Security functions
function generateCSRFToken() {
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function validateCSRFToken($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

function sanitizeInput($input, $type = 'string') {
    $input = trim($input);
    
    switch($type) {
        case 'employee_id':
            return preg_replace('/[^a-zA-Z0-9_-]/', '', $input);
        case 'email':
            return filter_var($input, FILTER_SANITIZE_EMAIL);
        case 'token':
            return preg_replace('/[^a-f0-9]/', '', $input);
        default:
            return htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
    }
}

function checkAccountLockout($pdo, $employeeId, $audit) {
    try {
        $stmt = $pdo->prepare("
            SELECT COUNT(*) FROM audit_log 
            WHERE user_id = ? 
            AND action = 'login_failed' 
            AND timestamp > NOW() - INTERVAL '15 minutes'
        ");
        $stmt->execute([$employeeId]);
        $failedAttempts = $stmt->fetchColumn();
        
        if ($failedAttempts >= 5) {
            $audit->logDataAccess($employeeId, 'employee', 'account_locked', null, 'security', ['failed_attempts' => $failedAttempts]);
            return true;
        }
        return false;
    } catch (PDOException $e) {
        error_log("Account lockout check error: " . $e->getMessage());
        return false;
    }
}

function checkPasswordHistory($pdo, $employeeId, $newPassword) {
    try {
        $stmt = $pdo->prepare("
            SELECT password FROM password_history 
            WHERE employee_id = ? 
            ORDER BY created_at DESC 
            LIMIT 5
        ");
        $stmt->execute([$employeeId]);
        $oldPasswords = $stmt->fetchAll(PDO::FETCH_COLUMN);
        
        foreach ($oldPasswords as $oldHash) {
            if (password_verify($newPassword, $oldHash)) {
                return false; // Password already used
            }
        }
        return true;
    } catch (PDOException $e) {
        error_log("Password history check error: " . $e->getMessage());
        return true; // Allow if table doesn't exist yet
    }
}

function validateStrongPassword($password, $employeeId = '') {
    if (strlen($password) < 12) {
        return 'Password must be at least 12 characters long';
    }
    
    if (!preg_match('/[A-Z]/', $password)) {
        return 'Password must contain at least one uppercase letter';
    }
    
    if (!preg_match('/[a-z]/', $password)) {
        return 'Password must contain at least one lowercase letter';
    }
    
    if (!preg_match('/[0-9]/', $password)) {
        return 'Password must contain at least one number';
    }
    
    if (!preg_match('/[!@#$%^&*(),.?":{}|<>]/', $password)) {
        return 'Password must contain at least one special character';
    }
    
    if (!empty($employeeId) && stripos($password, $employeeId) !== false) {
        return 'Password cannot contain your employee ID';
    }
    
    return null; // Password is valid
}

function checkResetRateLimit($pdo, $employeeId) {
    try {
        $stmt = $pdo->prepare("
            SELECT COUNT(*) FROM password_reset_tokens 
            WHERE (employee_id = ? OR ip_address = ?) 
            AND created_at > NOW() - INTERVAL '1 hour'
        ");
        $stmt->execute([$employeeId, $_SERVER['REMOTE_ADDR']]);
        return $stmt->fetchColumn() >= 3;
    } catch (PDOException $e) {
        error_log("Rate limit check error: " . $e->getMessage());
        return false;
    }
}

function maskEmail($email) {
    $parts = explode('@', $email);
    if (count($parts) !== 2) return $email;
    
    $username = $parts[0];
    $domain = $parts[1];
    
    if (strlen($username) <= 2) {
        return $username . '@' . $domain;
    }
    
    return substr($username, 0, 2) . '***@' . $domain;
}

function sendPasswordResetEmail($email, $token, $employeeId) {
    require_once '/var/www/html/PHPMailer/PHPMailer.php';
    require_once '/var/www/html/PHPMailer/SMTP.php';
    require_once '/var/www/html/PHPMailer/Exception.php';
    
    $mail = new PHPMailer\PHPMailer\PHPMailer();
    
    try {
        // SES SMTP configuration from environment variables
        $mail->isSMTP();
        $mail->Host = getenv('SES_SMTP_HOST');
        $mail->SMTPAuth = true;
        $mail->Username = getenv('SES_SMTP_USERNAME');
        $mail->Password = getenv('SES_SMTP_PASSWORD');
        $mail->SMTPSecure = 'tls';
        $mail->Port = 587;
        
        // Email content
        $mail->setFrom(getenv('SES_FROM_EMAIL'), 'NHS Timesheet System');
        $mail->addAddress($email);
        $mail->Subject = 'NHS Timesheet System - Password Reset Request';
        
        $resetLink = "https://zentimesheets.com/reset-password.html?token=" . urlencode($token);
        $mail->Body = "A password reset was requested for employee ID: $employeeId

Click the link below to reset your password (expires in 30 minutes):
$resetLink

If you did not request this reset, please ignore this email or contact IT support.

NHS Timesheet System";
        
        return $mail->send();
        
    } catch (Exception $e) {
        error_log("Email send error: " . $e->getMessage());
        return false;
    }
}

// Password reset functions
function handlePasswordResetRequest($pdo, $audit) {
    $input = json_decode(file_get_contents('php://input'), true);
    $employeeId = sanitizeInput($input['employee_id'] ?? '', 'employee_id');
    
    if (empty($employeeId)) {
        echo json_encode(['success' => false, 'error' => 'Employee ID required']);
        return;
    }
    
    // Rate limiting check
    if (checkResetRateLimit($pdo, $employeeId)) {
        $audit->logDataAccess($employeeId, 'employee', 'password_reset_rate_limited', null, 'security', ['reason' => 'Too many attempts']);
        echo json_encode(['success' => false, 'error' => 'Too many reset attempts. Try again in 1 hour.']);
        return;
    }
    
    // Log the attempt
    $audit->logDataAccess($employeeId, 'employee', 'password_reset_request', null, 'authentication');
    
    try {
        // Check if employee exists and get email
        $stmt = $pdo->prepare("SELECT employee_id, email FROM employees WHERE employee_id = ?");
        $stmt->execute([$employeeId]);
        $employee = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($employee && !empty($employee['email'])) {
            // Generate secure token
            $token = bin2hex(random_bytes(32));
            $expires = date('Y-m-d H:i:s', strtotime('+30 minutes'));
            
            // Invalidate any existing tokens for this employee
            $stmt = $pdo->prepare("UPDATE password_reset_tokens SET used = TRUE WHERE employee_id = ? AND used = FALSE");
            $stmt->execute([$employeeId]);
            
            // Store new token
            $stmt = $pdo->prepare("INSERT INTO password_reset_tokens (token, employee_id, email, expires_at, ip_address) VALUES (?, ?, ?, ?, ?)");
            $stmt->execute([$token, $employeeId, $employee['email'], $expires, $_SERVER['REMOTE_ADDR']]);
            
            // Send email
            if (sendPasswordResetEmail($employee['email'], $token, $employeeId)) {
                $audit->logDataAccess($employeeId, 'employee', 'password_reset_email_sent', null, 'authentication', ['email' => maskEmail($employee['email'])]);
            } else {
                $audit->logDataAccess($employeeId, 'employee', 'password_reset_email_failed', null, 'authentication');
            }
        }
        
        // Always return success to prevent enumeration
        echo json_encode(['success' => true, 'message' => 'If the employee ID exists, a password reset email has been sent to the registered email address.']);
        
    } catch (PDOException $e) {
        error_log("Password reset request error: " . $e->getMessage());
        echo json_encode(['success' => false, 'error' => 'System error. Please try again later.']);
    }
}

function handlePasswordResetConfirm($pdo, $audit) {
    $input = json_decode(file_get_contents('php://input'), true);
    $token = sanitizeInput($input['token'] ?? '', 'token');
    $newPassword = $input['new_password'] ?? '';
    $confirmPassword = $input['confirm_password'] ?? '';
    
    if (empty($token) || empty($newPassword) || empty($confirmPassword)) {
        echo json_encode(['success' => false, 'error' => 'All fields required']);
        return;
    }
    
    if ($newPassword !== $confirmPassword) {
        echo json_encode(['success' => false, 'error' => 'Passwords do not match']);
        return;
    }
    
    try {
        // Verify token
        $stmt = $pdo->prepare("
            SELECT employee_id, email, expires_at 
            FROM password_reset_tokens 
            WHERE token = ? AND used = FALSE AND expires_at > NOW()
        ");
        $stmt->execute([$token]);
        $resetToken = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$resetToken) {
            $audit->logDataAccess('unknown', 'employee', 'password_reset_invalid_token', null, 'security', ['token_prefix' => substr($token, 0, 8)]);
            echo json_encode(['success' => false, 'error' => 'Invalid or expired reset token']);
            return;
        }
        
        // Validate password strength
        $passwordError = validateStrongPassword($newPassword, $resetToken['employee_id']);
        if ($passwordError) {
            echo json_encode(['success' => false, 'error' => $passwordError]);
            return;
        }
        
        // Check password history
        if (!checkPasswordHistory($pdo, $resetToken['employee_id'], $newPassword)) {
            echo json_encode(['success' => false, 'error' => 'Cannot reuse recent passwords']);
            return;
        }
        
        // Get current password for history
        $stmt = $pdo->prepare("SELECT password FROM employees WHERE employee_id = ?");
        $stmt->execute([$resetToken['employee_id']]);
        $currentPassword = $stmt->fetchColumn();
        
        // Save current password to history
        if ($currentPassword) {
            try {
                $stmt = $pdo->prepare("INSERT INTO password_history (employee_id, password) VALUES (?, ?)");
                $stmt->execute([$resetToken['employee_id'], $currentPassword]);
            } catch (PDOException $e) {
                error_log("Password history save error: " . $e->getMessage());
            }
        }
        
        // Update password
        $hashedPassword = password_hash($newPassword, PASSWORD_DEFAULT);
        $stmt = $pdo->prepare("UPDATE employees SET password = ? WHERE employee_id = ?");
        $stmt->execute([$hashedPassword, $resetToken['employee_id']]);
        
        // Mark token as used
        $stmt = $pdo->prepare("UPDATE password_reset_tokens SET used = TRUE WHERE token = ?");
        $stmt->execute([$token]);
        
        // Log successful reset
        $audit->logDataAccess($resetToken['employee_id'], 'employee', 'password_reset_completed', null, 'authentication');
        
        echo json_encode(['success' => true, 'message' => 'Password reset successfully']);
        
    } catch (PDOException $e) {
        error_log("Password reset confirm error: " . $e->getMessage());
        echo json_encode(['success' => false, 'error' => 'Database error']);
    }
}

// Test endpoint
if ($_SERVER['REQUEST_METHOD'] === 'GET' && strpos($_SERVER['REQUEST_URI'], '/test') !== false) {
    try {
        $pdo = DatabaseConfig::getConnection();
        echo json_encode([
            'status' => 'success',
            'message' => 'NHS Secured API Connected successfully!',
            'timestamp' => date('Y-m-d H:i:s'),
            'security_status' => 'NHS compliance enabled'
        ]);
    } catch (Exception $e) {
        echo json_encode(['status' => 'error', 'error' => $e->getMessage()]);
    }
    exit;
}

$method = $_SERVER['REQUEST_METHOD'];
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
if (isset($_GET['path'])) $path = $_GET['path'];

error_log("NHS Timesheet API - Method: $method, Path: $path");

try {
    $pdo = DatabaseConfig::getConnection();
    $audit = new NHSAuditLogger($pdo);
    $session = new NHSSessionManager(30, $audit);
    
    switch ($method) {
        case 'POST':
            if (strpos($path, '/login') !== false) {
                handleLogin($pdo, $audit, $session);
            } elseif (strpos($path, '/request-password-reset') !== false) {
                handlePasswordResetRequest($pdo, $audit);
            } elseif (strpos($path, '/confirm-password-reset') !== false) {
                handlePasswordResetConfirm($pdo, $audit);
            } elseif (strpos($path, '/save-draft') !== false) {
                handleSaveDraft($pdo, $audit, $session);
            } elseif (strpos($path, '/submit-timesheet') !== false) {
                handleSubmitTimesheet($pdo, $audit, $session);
            }
            break;
            
        case 'GET':
            if (strpos($path, '/available-months/') !== false) {
                $pathParts = explode('/', trim($path, '/'));
                $employeeId = end($pathParts);
                handleGetAvailableMonths($pdo, $employeeId, $audit, $session);
            } elseif (strpos($path, '/timesheet/') !== false) {
                $pathParts = explode('/', trim($path, '/'));
                if (count($pathParts) >= 4) {
                    $employeeId = $pathParts[count($pathParts) - 3];
                    $year = $pathParts[count($pathParts) - 2];
                    $month = $pathParts[count($pathParts) - 1];
                    handleGetTimesheetByMonth($pdo, $employeeId, $year, $month, $audit, $session);
                }
            }
            break;
    }
} catch (Exception $e) {
    error_log("NHS Timesheet API ERROR: " . $e->getMessage());
    if (isset($audit) && isset($_SESSION['employee_id'])) {
        $audit->logDataAccess($_SESSION['employee_id'], 'employee', 'system_error', null, 'api_error', ['error' => $e->getMessage()]);
    }
    http_response_code(500);
    echo json_encode(['error' => 'System error occurred']);
}

function handleLogin($pdo, $audit, $session) {
    $input = json_decode(file_get_contents('php://input'), true);
    $employeeId = sanitizeInput($input['employee_id'] ?? '', 'employee_id');
    $password = $input['password'] ?? '';
    
    // Check account lockout
    if (checkAccountLockout($pdo, $employeeId, $audit)) {
        echo json_encode(['success' => false, 'error' => 'Account temporarily locked. Try again in 15 minutes.']);
        return;
    }
    
    try {
        // Get employee with password from employees table
        $stmt = $pdo->prepare("
            SELECT employee_id, employee_name, site, job_title, hpw, password
            FROM employees 
            WHERE employee_id = :employee_id LIMIT 1
        ");
        $stmt->execute(['employee_id' => $employeeId]);
        $employee = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($employee && password_verify($password, $employee['password'])) {
            session_regenerate_id(true);
            $_SESSION['employee_id'] = $employee['employee_id'];
            $_SESSION['employee_name'] = $employee['employee_name'];
            $_SESSION['last_activity'] = time();
            
            $audit->logDataAccess($employeeId, 'employee', 'login_success', $employeeId, 'authentication');
            error_log("NHS Login successful for: $employeeId");
            
            echo json_encode([
                'success' => true,
                'employee' => [
                    'id' => $employee['employee_id'],
                    'name' => $employee['employee_name'],
                    'site' => $employee['site'],
                    'jobTitle' => $employee['job_title'],
                    'hpw' => $employee['hpw']
                ]
            ]);
        } else {
            $audit->logDataAccess($employeeId, 'employee', 'login_failed', $employeeId, 'authentication');
            echo json_encode(['success' => false, 'error' => 'Invalid employee ID or password']);
        }
    } catch (PDOException $e) {
        error_log("NHS Login error: " . $e->getMessage());
        echo json_encode(['success' => false, 'error' => 'Database error']);
    }
}

function handleGetAvailableMonths($pdo, $employeeId, $audit, $session) {
    $session->requireEmployeeAccess($employeeId);
    
    $audit->logDataAccess($employeeId, 'employee', 'view_available_months', $employeeId, 'timesheet_data');
    
    try {
        $stmt = $pdo->prepare("
            SELECT DISTINCT 
                EXTRACT(YEAR FROM sched_date) as year,
                EXTRACT(MONTH FROM sched_date) as month,
                TO_CHAR(sched_date, 'Month YYYY') as display_name,
                TO_CHAR(sched_date, 'YYYY-MM') as value
            FROM processed_timesheet 
            WHERE employee_id = :employee_id 
            ORDER BY year DESC, month DESC
        ");
        $stmt->execute(['employee_id' => $employeeId]);
        $months = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        echo json_encode(['success' => true, 'months' => $months]);
    } catch (PDOException $e) {
        error_log("Get months error: " . $e->getMessage());
        echo json_encode(['success' => false, 'error' => 'Database error']);
    }
}

function handleGetTimesheetByMonth($pdo, $employeeId, $year, $month, $audit, $session) {
    $session->requireEmployeeAccess($employeeId);
    
    error_log("NHS Loading timesheet: Employee=$employeeId, Year=$year, Month=$month");
    
    $audit->logDataAccess($employeeId, 'employee', 'view_timesheet', $employeeId, 'personal_data', [
        'year' => $year,
        'month' => $month
    ]);
    
    try {
        // Get base data from processed_timesheet - Updated with new columns
        $stmt = $pdo->prepare("
            SELECT 
                sched_date, earliest_start, latest_stop, paid_hours, unpaid_breaks, 
                absence_type, absence_hours, sat_enhancement, sun_enhancement, 
                nights_enhancement, bank_holiday_enhancement, extra_hours,
                weekday_overtime, saturday_overtime, sunday_overtime, bank_holiday_overtime,
                total_worked_hours, total_overtime_hours, employee_normal_paid_hours
            FROM processed_timesheet 
            WHERE employee_id = :employee_id 
            AND EXTRACT(YEAR FROM sched_date) = :year
            AND EXTRACT(MONTH FROM sched_date) = :month
            ORDER BY sched_date ASC
        ");
        $stmt->execute(['employee_id' => $employeeId, 'year' => (int)$year, 'month' => (int)$month]);
        $timesheetRows = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        if (empty($timesheetRows)) {
            echo json_encode(['success' => false, 'error' => "No data found for $year-$month"]);
            return;
        }
        
        // Get modifications (pending, submitted, AND approved) - manager changes override employee changes
        $stmt = $pdo->prepare("
            SELECT original_record_date, field_name, modified_value, manager_override, status
            FROM timesheet_modifications 
            WHERE original_record_employee_id = :employee_id 
            AND EXTRACT(YEAR FROM original_record_date) = :year
            AND EXTRACT(MONTH FROM original_record_date) = :month
            AND status IN ('pending', 'submitted', 'approved')
            ORDER BY manager_override DESC, modification_date DESC
        ");
        $stmt->execute(['employee_id' => $employeeId, 'year' => (int)$year, 'month' => (int)$month]);
        $modifications = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        // Check submission status and lock state
        $yearMonth = $year . '-' . str_pad($month, 2, '0', STR_PAD_LEFT);
        $stmt = $pdo->prepare("
            SELECT status, manager_comments FROM timesheet_submissions 
            WHERE employee_id = :employee_id AND year_month = :year_month
        ");
        $stmt->execute([
            'employee_id' => $employeeId, 
            'year_month' => $yearMonth
        ]);
        $submission = $stmt->fetch(PDO::FETCH_ASSOC);

        $isLocked = false;
        $submissionStatus = 'draft';
        if ($submission) {
            $submissionStatus = $submission['status'];
            $isLocked = in_array($submission['status'], ['submitted', 'approved']);
        }

        // If approved, employee sees final version but can't edit
        $showingApprovedVersion = ($submissionStatus === 'approved');
        
        // Group modifications by date, manager changes override employee changes
        $modsByDate = [];
        foreach ($modifications as $mod) {
            $dateKey = $mod['original_record_date'];
            $fieldKey = $mod['field_name'];
            
            // If no existing value OR manager override, use this value
            if (!isset($modsByDate[$dateKey][$fieldKey]) || $mod['manager_override']) {
                $modsByDate[$dateKey][$fieldKey] = $mod['modified_value'];
            }
        }
        
        // Build response data with all fields (WITH modifications applied)
        $timesheetData = [];
        foreach ($timesheetRows as $row) {
            $dateKey = $row['sched_date'];
            $dayMods = $modsByDate[$dateKey] ?? [];
            
            $timesheetData[] = [
                'date' => date('d/m/Y', strtotime($row['sched_date'])),
                'startTime' => $dayMods['startTime'] ?? formatTime($row['earliest_start']),
                'stopTime' => $dayMods['stopTime'] ?? formatTime($row['latest_stop']),
                'unpaidBreaks' => formatTime($row['unpaid_breaks']),
                'totalHours' => formatTime($row['paid_hours']), // Keep for compatibility
                'normalPaidHours' => formatTime($row['total_worked_hours']), // Renamed: Total Worked Hours (read-only)
                'normalPaidHoursInput' => $dayMods['normalPaidHours'] ?? formatTime($row['employee_normal_paid_hours']), // Employee input field
                'overtimeHours' => formatTime($row['total_overtime_hours']),
                'absenceType' => $row['absence_type'] ?? 'None',
                'absenceHours' => formatTime($row['absence_hours']),
                'satEnhancement' => $dayMods['satEnhancement'] ?? formatTime($row['sat_enhancement']),
                'sunEnhancement' => $dayMods['sunEnhancement'] ?? formatTime($row['sun_enhancement']),
                'nightsEnhancement' => $dayMods['nightsEnhancement'] ?? formatTime($row['nights_enhancement']),
                'bankHolidayEnhancement' => $dayMods['bankHolidayEnhancement'] ?? formatTime($row['bank_holiday_enhancement']),
                'extraHours' => $dayMods['extraHours'] ?? formatTime($row['extra_hours']),
                'weekdayOvertime' => $dayMods['weekdayOvertime'] ?? formatTime($row['weekday_overtime']),
                'satOvertime' => $dayMods['satOvertime'] ?? formatTime($row['saturday_overtime']),
                'sunOvertime' => $dayMods['sunOvertime'] ?? formatTime($row['sunday_overtime']),
                'bankHolidayOvertime' => $dayMods['bankHolidayOvertime'] ?? formatTime($row['bank_holiday_overtime']),
                'comments' => $dayMods['comments'] ?? ''
            ];
        }
        
        // Build original data (WITHOUT modifications) for comparison
        $originalTimesheetData = [];
        foreach ($timesheetRows as $row) {
            $originalTimesheetData[] = [
                'date' => date('d/m/Y', strtotime($row['sched_date'])),
                'startTime' => formatTime($row['earliest_start']),
                'stopTime' => formatTime($row['latest_stop']),
                'unpaidBreaks' => formatTime($row['unpaid_breaks']),
                'totalHours' => formatTime($row['paid_hours']),
                'normalPaidHours' => formatTime($row['total_worked_hours']), // Total Worked Hours (original)
                'normalPaidHoursInput' => formatTime($row['employee_normal_paid_hours']), // Employee input (original)
                'overtimeHours' => formatTime($row['total_overtime_hours']),
                'absenceType' => $row['absence_type'] ?? 'None',
                'absenceHours' => formatTime($row['absence_hours']),
                'satEnhancement' => formatTime($row['sat_enhancement']),
                'sunEnhancement' => formatTime($row['sun_enhancement']),
                'nightsEnhancement' => formatTime($row['nights_enhancement']),
                'bankHolidayEnhancement' => formatTime($row['bank_holiday_enhancement']),
                'extraHours' => formatTime($row['extra_hours']),
                'weekdayOvertime' => formatTime($row['weekday_overtime']),
                'satOvertime' => formatTime($row['saturday_overtime']),
                'sunOvertime' => formatTime($row['sunday_overtime']),
                'bankHolidayOvertime' => formatTime($row['bank_holiday_overtime']),
                'comments' => ''
            ];
        }
        
        echo json_encode([
            'success' => true,
            'timesheetData' => $timesheetData,
            'originalTimesheetData' => $originalTimesheetData,  // Original data for comparison
            'submission_status' => $submissionStatus,
            'is_locked' => $isLocked,
            'modifications_count' => count($modifications),
            'manager_comments' => $submission['manager_comments'] ?? '',
            'showing_approved_version' => $showingApprovedVersion
        ]);
        
    } catch (PDOException $e) {
        error_log("Timesheet load error: " . $e->getMessage());
        echo json_encode(['success' => false, 'error' => 'Database error loading timesheet']);
    }
}

function handleSaveDraft($pdo, $audit, $session) {
    error_log("=== NHS SAVE DRAFT STARTED ===");
    
    $input = json_decode(file_get_contents('php://input'), true);
    $employeeId = sanitizeInput($input['employee_id'] ?? '', 'employee_id');
    $yearMonth = $input['year_month'] ?? '';
    $timesheetData = $input['timesheet_data'] ?? [];
    
    $session->requireEmployeeAccess($employeeId);
    
    // NORMALIZE YEAR_MONTH FORMAT
    $yearMonthParts = explode('-', $yearMonth);
    $year = (int)$yearMonthParts[0];
    $month = (int)$yearMonthParts[1];
    $yearMonth = $year . '-' . str_pad($month, 2, '0', STR_PAD_LEFT);
    
    $audit->logDataAccess($employeeId, 'employee', 'save_draft', $employeeId, 'timesheet_modification', [
        'year_month' => $yearMonth,
        'rows_modified' => count($timesheetData)
    ]);
    
    error_log("NHS Saving for Employee: $employeeId, Month: $yearMonth, Rows: " . count($timesheetData));
    
    if (empty($employeeId) || empty($yearMonth) || empty($timesheetData)) {
        echo json_encode(['success' => false, 'error' => 'Missing data']);
        return;
    }
    
    try {
        $pdo->beginTransaction();
        
        // Get or create submission record for this month
        $stmt = $pdo->prepare("
            SELECT id FROM timesheet_submissions 
            WHERE employee_id = ? AND year_month = ?
        ");
        $stmt->execute([$employeeId, $yearMonth]);
        $submission = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$submission) {
            // Create new submission record
            $stmt = $pdo->prepare("
                INSERT INTO timesheet_submissions (employee_id, year_month, status, submission_date)
                VALUES (?, ?, 'draft', CURRENT_TIMESTAMP)
                RETURNING id
            ");
            $stmt->execute([$employeeId, $yearMonth]);
            $submissionId = $stmt->fetch(PDO::FETCH_ASSOC)['id'];
            error_log("Created new submission record with ID: $submissionId");
        } else {
            $submissionId = $submission['id'];
            error_log("Using existing submission ID: $submissionId");
        }
        
        // Clear existing pending modifications for this month
        $yearMonthParts = explode('-', $yearMonth);
        $stmt = $pdo->prepare("
            DELETE FROM timesheet_modifications 
            WHERE original_record_employee_id = ? 
            AND EXTRACT(YEAR FROM original_record_date) = ?
            AND EXTRACT(MONTH FROM original_record_date) = ?
            AND status = 'pending'
        ");
        $stmt->execute([$employeeId, (int)$yearMonthParts[0], (int)$yearMonthParts[1]]);
        error_log("Cleared existing pending modifications");
        
        $insertCount = 0;
        $directUpdateCount = 0;
        
        foreach ($timesheetData as $row) {
            $date = convertDateToSql($row['date']);
            
            // Get original values - Updated to include new columns
            $stmt = $pdo->prepare("
                SELECT earliest_start, latest_stop, employee_normal_paid_hours, sat_enhancement, sun_enhancement, 
                       nights_enhancement, bank_holiday_enhancement, extra_hours,
                       weekday_overtime, saturday_overtime, sunday_overtime, bank_holiday_overtime
                FROM processed_timesheet WHERE employee_id = ? AND sched_date = ?
            ");
            $stmt->execute([$employeeId, $date]);
            $original = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$original) continue;
            
           // Handle Normal Paid Hours - Direct database update
$newNormalPaidValue = $row['normalPaidHoursInput'] ?? null; // Use null as default
$originalNormalPaidValue = formatTime($original['employee_normal_paid_hours']);

if ($newNormalPaidValue !== null && $newNormalPaidValue !== '' && preg_match('/^\d{2}:\d{2}$/', $newNormalPaidValue) && $newNormalPaidValue !== $originalNormalPaidValue) {
    // Update the database column directly
    $stmt = $pdo->prepare("
        UPDATE processed_timesheet 
        SET employee_normal_paid_hours = ? 
        WHERE employee_id = ? AND sched_date = ?
    ");
    $result = $stmt->execute([
        convertTimeToDbFormat($newNormalPaidValue),
        $employeeId, 
        $date
    ]);
    
    if ($result) {
        $directUpdateCount++;
        error_log("Updated employee_normal_paid_hours for $date: $originalNormalPaidValue -> $newNormalPaidValue");
        
        // Also track as modification for audit
        $stmt = $pdo->prepare("
            INSERT INTO timesheet_modifications 
            (submission_id, original_record_employee_id, original_record_date, field_name, 
             original_value, modified_value, employee_comments, status, modification_date)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', CURRENT_TIMESTAMP)
        ");
        
        $stmt->execute([
            $submissionId,
            $employeeId, 
            $date, 
            'normalPaidHours', 
            $originalNormalPaidValue, 
            $newNormalPaidValue, 
            $row['comments'] ?? ''
        ]);
        $insertCount++;
    }
} else {
    error_log("Skipped update for employee_normal_paid_hours on $date: new=$newNormalPaidValue, original=$originalNormalPaidValue");
}
            
            
            // Handle other fields (traditional modification tracking)
            $fieldMappings = [
                'startTime' => formatTime($original['earliest_start']),
                'stopTime' => formatTime($original['latest_stop']),
                'satEnhancement' => formatTime($original['sat_enhancement']),
                'sunEnhancement' => formatTime($original['sun_enhancement']),
                'nightsEnhancement' => formatTime($original['nights_enhancement']),
                'bankHolidayEnhancement' => formatTime($original['bank_holiday_enhancement']),
                'extraHours' => formatTime($original['extra_hours']),
                'weekdayOvertime' => formatTime($original['weekday_overtime']),
                'satOvertime' => formatTime($original['saturday_overtime']),
                'sunOvertime' => formatTime($original['sunday_overtime']),
                'bankHolidayOvertime' => formatTime($original['bank_holiday_overtime']),
                'comments' => ''
            ];
            
            foreach ($fieldMappings as $field => $originalValue) {
                $currentValue = $row[$field] ?? '';
                
                if ($currentValue !== $originalValue) {
                    error_log("Change detected: $field '$originalValue' -> '$currentValue'");
                    
                    // Insert modification record
                    $stmt = $pdo->prepare("
                        INSERT INTO timesheet_modifications 
                        (submission_id, original_record_employee_id, original_record_date, field_name, 
                         original_value, modified_value, employee_comments, status, modification_date)
                        VALUES (?, ?, ?, ?, ?, ?, ?, 'pending', CURRENT_TIMESTAMP)
                    ");
                    
                    $result = $stmt->execute([
                        $submissionId,
                        $employeeId, 
                        $date, 
                        $field, 
                        $originalValue, 
                        $currentValue, 
                        $row['comments'] ?? ''
                    ]);
                    
                    if ($result) {
                        $insertCount++;
                        error_log("Successfully inserted modification for $field");
                    }
                }
            }
        }
        
        $pdo->commit();
        error_log("NHS Draft saved successfully. Direct updates: $directUpdateCount, Modifications: $insertCount");
        echo json_encode([
            'success' => true, 
            'message' => "Draft saved ($directUpdateCount direct updates, $insertCount modifications)"
        ]);
        
    } catch (Exception $e) {
        $pdo->rollback();
        error_log("NHS Save draft error: " . $e->getMessage());
        echo json_encode(['success' => false, 'error' => 'Failed to save draft: ' . $e->getMessage()]);
    }
}

function handleSubmitTimesheet($pdo, $audit, $session) {
    error_log("=== NHS SUBMIT TIMESHEET STARTED ===");
    
    $input = json_decode(file_get_contents('php://input'), true);
    $employeeId = sanitizeInput($input['employee_id'] ?? '', 'employee_id');
    $yearMonth = $input['year_month'] ?? '';
    $timesheetData = $input['timesheet_data'] ?? [];
    $employeeComments = sanitizeInput($input['employee_comments'] ?? '');
    
    $session->requireEmployeeAccess($employeeId);
    
    // NORMALIZE YEAR_MONTH FORMAT
    $yearMonthParts = explode('-', $yearMonth);
    $year = (int)$yearMonthParts[0];
    $month = (int)$yearMonthParts[1];
    $yearMonth = $year . '-' . str_pad($month, 2, '0', STR_PAD_LEFT);
    
    $audit->logDataAccess($employeeId, 'employee', 'submit_timesheet', $employeeId, 'timesheet_submission', [
        'year_month' => $yearMonth
    ]);
    
    error_log("NHS Submitting for Employee: $employeeId, Month: $yearMonth");
    
    if (empty($employeeId) || empty($yearMonth)) {
        echo json_encode(['success' => false, 'error' => 'Missing employee ID or month']);
        return;
    }
    
   try {
    $pdo->beginTransaction();
    
    // Get employee department/team info from processed_timesheet
    $stmt = $pdo->prepare("
        SELECT DISTINCT muid, team 
        FROM processed_timesheet 
        WHERE employee_id = ? 
        LIMIT 1
    ");
    $stmt->execute([$employeeId]);
    $empInfo = $stmt->fetch(PDO::FETCH_ASSOC);
    $muid = $empInfo['muid'] ?? '';
    $team = $empInfo['team'] ?? '';
    
    error_log("Employee dept info: muid=$muid, team=$team");
    
    // Check if there's already a submission for this month
    $stmt = $pdo->prepare("
        SELECT id, status FROM timesheet_submissions 
        WHERE employee_id = ? AND year_month = ?
    ");
    $stmt->execute([$employeeId, $yearMonth]);
    $existingSubmission = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if ($existingSubmission) {
        // Update existing submission
        $stmt = $pdo->prepare("
            UPDATE timesheet_submissions 
            SET status = 'submitted', 
                submission_date = CURRENT_TIMESTAMP,
                employee_comments = ?,
                muid = ?,
                team = ?
            WHERE employee_id = ? AND year_month = ?
        ");
        $stmt->execute([$employeeComments, $muid, $team, $employeeId, $yearMonth]);
        $submissionId = $existingSubmission['id'];
        error_log("Updated existing submission ID: $submissionId");
    } else {
        // Create new submission
        $stmt = $pdo->prepare("
            INSERT INTO timesheet_submissions 
            (employee_id, year_month, status, submission_date, employee_comments, muid, team)
            VALUES (?, ?, 'submitted', CURRENT_TIMESTAMP, ?, ?, ?)
            RETURNING id
        ");
        $stmt->execute([$employeeId, $yearMonth, $employeeComments, $muid, $team]);
        $submissionId = $stmt->fetch(PDO::FETCH_ASSOC)['id'];
        error_log("Created new submission ID: $submissionId");
    }
    
    // Update any pending modifications to 'submitted' status
    $yearMonthParts = explode('-', $yearMonth);
    $stmt = $pdo->prepare("
        UPDATE timesheet_modifications 
        SET status = 'submitted',
            submission_id = ?
        WHERE original_record_employee_id = ? 
        AND EXTRACT(YEAR FROM original_record_date) = ?
        AND EXTRACT(MONTH FROM original_record_date) = ?
        AND status = 'pending'
    ");
    $result = $stmt->execute([
        $submissionId,
        $employeeId, 
        (int)$yearMonthParts[0], 
        (int)$yearMonthParts[1]
    ]);
    
    $modificationCount = $stmt->rowCount();
    error_log("Updated $modificationCount modifications to submitted status");
    
    $pdo->commit();
    
    echo json_encode([
        'success' => true, 
        'message' => 'Timesheet submitted successfully for manager approval',
        'submission_id' => $submissionId,
        'modifications_submitted' => $modificationCount
    ]);
    
} catch (Exception $e) {
    $pdo->rollback();
    error_log("NHS Submit timesheet error: " . $e->getMessage());
    echo json_encode(['success' => false, 'error' => 'Failed to submit timesheet: ' . $e->getMessage()]);
   }
}

function formatTime($timeValue) {
    if (!$timeValue) return '00:00';
    if (preg_match('/^\d{2}:\d{2}$/', $timeValue)) return $timeValue;
    if (preg_match('/^\d{2}:\d{2}:\d{2}$/', $timeValue)) return substr($timeValue, 0, 5);
    return '00:00';
}

function convertTimeToDbFormat($timeStr) {
    if (!$timeStr || $timeStr === '00:00') return '00:00:00';
    if (preg_match('/^\d{2}:\d{2}$/', $timeStr)) return $timeStr . ':00';
    return $timeStr;
}

function convertDateToSql($dateStr) {
    $parts = explode('/', $dateStr);
    return $parts[2] . '-' . $parts[1] . '-' . $parts[0];
}
?>