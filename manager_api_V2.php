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
                    'manager_portal',
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
            error_log("NHS Manager API: Database connection successful");
            return $pdo;
        } catch (PDOException $e) {
            error_log("NHS Manager API: Database connection failed: " . $e->getMessage());
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

    // --- LOGIN (managers only) ---
    if ($action === 'login') {
        $username = filter_var($input['username'] ?? '', FILTER_SANITIZE_STRING);
        $password = $input['password'] ?? '';

        $stmt = $pdo->prepare("SELECT id, username, first_name, last_name, role, password, approval_level 
                               FROM users 
                               WHERE username = ? AND role = 'manager'");
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

    // All other actions require manager authentication
    $session->requireRole(['manager']);

    // --- GET DEPARTMENTS AND TEAMS ---
    if ($action === 'get_departments_teams') {
        try {
            $audit->logDataAccess($_SESSION['user_id'], $_SESSION['user_role'], 'view_departments_teams', null, 'organizational_data');
            
            // Get all departments (using muid column)
            $deptStmt = $pdo->query("SELECT DISTINCT muid FROM processed_timesheet WHERE muid IS NOT NULL ORDER BY muid");
            $departments = $deptStmt->fetchAll(PDO::FETCH_COLUMN);
            
            // Get all teams grouped by department (using muid column)
            $teamStmt = $pdo->query("SELECT DISTINCT muid, team FROM processed_timesheet WHERE muid IS NOT NULL AND team IS NOT NULL ORDER BY muid, team");
            $teamData = $teamStmt->fetchAll(PDO::FETCH_ASSOC);
            
            $teamsByDept = [];
            foreach ($teamData as $row) {
                $teamsByDept[$row['muid']][] = $row['team'];
            }
            
            echo json_encode([
                "success" => true,
                "departments" => $departments,
                "teams_by_department" => $teamsByDept
            ]);
        } catch (Exception $e) {
            echo json_encode(["success" => false, "error" => "Failed to load departments/teams: " . $e->getMessage()]);
        }
        exit;
    }

    // --- LIST PENDING TIMESHEETS WITH PAY GRADE FILTERING ---
    if ($action === 'list_timesheets') {
        $department = filter_var($input['department'] ?? '', FILTER_SANITIZE_STRING);
        $team = filter_var($input['team'] ?? '', FILTER_SANITIZE_STRING);
        $status = filter_var($input['status'] ?? '', FILTER_SANITIZE_STRING);
        $manager_id = $_SESSION['user_id'];
        
        // Get manager's approval level (pay grade equivalent)
        $stmt = $pdo->prepare("SELECT approval_level FROM users WHERE id = ?");
        $stmt->execute([$manager_id]);
        $manager = $stmt->fetch(PDO::FETCH_ASSOC);
        $manager_approval_level = $manager['approval_level'] ?? null;
        
        if (!$manager_approval_level) {
            echo json_encode(["success" => false, "error" => "Manager approval level not found"]);
            exit;
        }
        
        $audit->logDataAccess($manager_id, $_SESSION['user_role'], 'view_pending_timesheets', null, 'timesheet_data', [
            'department' => $department,
            'team' => $team,
            'status' => $status
        ]);
        
        $whereClauses = [];
        $params = [$manager_approval_level]; // First param for pay grade comparison
        
        if (empty($status)) {
            $whereClauses[] = "ts.status = 'submitted'";
        } else {
            $whereClauses[] = "ts.status = ?";
            $params[] = $status;
        }
        
        if (!empty($department)) {
            $whereClauses[] = "ts.muid = ?";
            $params[] = $department;
        }
        
        if (!empty($team)) {
            $whereClauses[] = "ts.team = ?";
            $params[] = $team;
        }
        
        $whereSQL = implode(' AND ', $whereClauses);
        
        $stmt = $pdo->prepare("
            SELECT ts.id, ts.employee_id, e.employee_name, ts.year_month as period, ts.submission_date as submitted_date, 
                   ts.status, ts.employee_comments as comments, ts.muid as department, ts.team
            FROM timesheet_submissions ts
            JOIN employees e ON ts.employee_id = e.employee_id
            WHERE CAST(e.pay_grade AS INTEGER) < ? AND $whereSQL
            ORDER BY ts.submission_date DESC
        ");
        $stmt->execute($params);
        $timesheets = $stmt->fetchAll();
        
        // Log each employee's timesheet accessed
        $employeeIds = array_unique(array_column($timesheets, 'employee_id'));
        foreach ($employeeIds as $empId) {
            $audit->logDataAccess($manager_id, $_SESSION['user_role'], 'view_employee_timesheet_list', $empId, 'personal_data');
        }
        
        echo json_encode(["success" => true, "data" => $timesheets]);
        exit;
    }

    // --- GET TIMESHEET DETAIL ---
    if ($action === 'get_timesheet_detail') {
        $employee_id = filter_var($input['employee_id'] ?? '', FILTER_SANITIZE_STRING);
        $period = filter_var($input['period'] ?? '', FILTER_SANITIZE_STRING);
        
        $audit->logDataAccess($_SESSION['user_id'], $_SESSION['user_role'], 'view_timesheet_detail', $employee_id, 'personal_data', [
            'period' => $period
        ]);
        
        $yearMonthParts = explode('-', $period);
        $year = (int)$yearMonthParts[0];
        $month = (int)$yearMonthParts[1];

        try {
            // Get complete base data using updated column names including employee details
            $stmt = $pdo->prepare("
                SELECT 
                    sched_date, earliest_start, latest_stop, 
                    total_worked_hours, employee_normal_paid_hours,
                    absence_type, absence_hours, sat_enhancement, sun_enhancement, 
                    nights_enhancement, bank_holiday_enhancement, extra_hours,
                    weekday_overtime, saturday_overtime, sunday_overtime, bank_holiday_overtime,
                    total_overtime_hours, muid, team, employee_name, job_title, site, hpw
                FROM processed_timesheet 
                WHERE employee_id = ? 
                AND EXTRACT(YEAR FROM sched_date) = ?
                AND EXTRACT(MONTH FROM sched_date) = ?
                ORDER BY sched_date ASC
            ");
            $stmt->execute([$employee_id, $year, $month]);
            $timesheetRows = $stmt->fetchAll(PDO::FETCH_ASSOC);

            if (empty($timesheetRows)) {
                echo json_encode(['success' => false, 'error' => "No timesheet data found for employee $employee_id in period $period"]);
                exit;
            }

            // Get department and team info for display
            $deptInfo = [
                'department' => $timesheetRows[0]['muid'] ?? '',
                'team' => $timesheetRows[0]['team'] ?? ''
            ];

            // Get employee info for display
            $employeeInfo = [
                'employee_name' => $timesheetRows[0]['employee_name'] ?? 'Unknown',
                'job_title' => $timesheetRows[0]['job_title'] ?? '',
                'site' => $timesheetRows[0]['site'] ?? '',
                'hpw' => $timesheetRows[0]['hpw'] ?? ''
            ];

            // Get modifications
            $stmt = $pdo->prepare("
                SELECT original_record_date, field_name, original_value, modified_value, 
                       employee_comments, modified_by, modified_by_role, manager_override
                FROM timesheet_modifications 
                WHERE original_record_employee_id = ? 
                AND EXTRACT(YEAR FROM original_record_date) = ?
                AND EXTRACT(MONTH FROM original_record_date) = ?
                AND status IN ('pending', 'submitted')
                ORDER BY original_record_date, field_name, manager_override DESC, modification_date DESC
            ");
            $stmt->execute([$employee_id, $year, $month]);
            $modifications = $stmt->fetchAll(PDO::FETCH_ASSOC);

            // Group modifications by date and field
            $modsByDate = [];
            foreach ($modifications as $mod) {
                $dateKey = $mod['original_record_date'];
                $fieldKey = $mod['field_name'];
                
                if (!isset($modsByDate[$dateKey][$fieldKey]) || $mod['manager_override']) {
                    $modsByDate[$dateKey][$fieldKey] = $mod['modified_value'];
                }
            }

            // Format time helper
            $formatTime = function($timeValue) {
                if (!$timeValue) return '00:00';
                if (preg_match('/^\d{2}:\d{2}$/', $timeValue)) return $timeValue;
                if (preg_match('/^\d{2}:\d{2}:\d{2}$/', $timeValue)) return substr($timeValue, 0, 5);
                return '00:00';
            };

            // Build complete merged dataset
            $combinedData = [];
            foreach ($timesheetRows as $row) {
                $dateKey = $row['sched_date'];
                $dayMods = $modsByDate[$dateKey] ?? [];
                
                $originalStart = $formatTime($row['earliest_start']);
                $originalStop = $formatTime($row['latest_stop']);
                
                $finalStart = $dayMods['startTime'] ?? $originalStart;
                $finalStop = $dayMods['stopTime'] ?? $originalStop;
                
                $combinedData[] = [
                    'date' => $row['sched_date'],
                    'original_start' => $originalStart,
                    'submitted_start' => $finalStart,
                    'original_stop' => $originalStop, 
                    'submitted_stop' => $finalStop,
                    'total_worked_hours' => $formatTime($row['total_worked_hours']),
                    'employee_normal_paid_hours' => $dayMods['normalPaidHours'] ?? $formatTime($row['employee_normal_paid_hours']),
                    'total_overtime_hours' => $formatTime($row['total_overtime_hours']),
                    'absence_type' => $dayMods['absenceType'] ?? ($row['absence_type'] ?? ''),
                    'absence_hours' => $dayMods['absenceHours'] ?? $formatTime($row['absence_hours']),
                    'sat_enhancement' => $dayMods['satEnhancement'] ?? $formatTime($row['sat_enhancement']),
                    'sun_enhancement' => $dayMods['sunEnhancement'] ?? $formatTime($row['sun_enhancement']),
                    'nights_enhancement' => $dayMods['nightsEnhancement'] ?? $formatTime($row['nights_enhancement']),
                    'bank_holiday_enhancement' => $dayMods['bankHolidayEnhancement'] ?? $formatTime($row['bank_holiday_enhancement']),
                    'extra_hours' => $dayMods['extraHours'] ?? $formatTime($row['extra_hours']),
                    'weekday_overtime' => $dayMods['weekdayOvertime'] ?? $formatTime($row['weekday_overtime']),
                    'sat_overtime' => $dayMods['satOvertime'] ?? $formatTime($row['saturday_overtime']),
                    'sun_overtime' => $dayMods['sunOvertime'] ?? $formatTime($row['sunday_overtime']),
                    'bank_holiday_overtime' => $dayMods['bankHolidayOvertime'] ?? $formatTime($row['bank_holiday_overtime']),
                    'comments' => $dayMods['comments'] ?? '',
                    'has_changes' => !empty($dayMods)
                ];
            }

            echo json_encode([
                "success" => true,
                "submitted" => $combinedData,
                "department_info" => $deptInfo,
                "employee_info" => $employeeInfo
            ]);
            
        } catch (Exception $e) {
            error_log("NHS Manager API get_timesheet_detail error: " . $e->getMessage());
            echo json_encode(["success" => false, "error" => "Database error: " . $e->getMessage()]);
        }
        exit;
    }

    // --- SAVE MANAGER CHANGES ---
    if ($action === 'save_manager_changes') {
        $employee_id = filter_var($input['employee_id'] ?? '', FILTER_SANITIZE_STRING);
        $period = filter_var($input['period'] ?? '', FILTER_SANITIZE_STRING);
        $changes = $input['changes'] ?? [];
        $manager_id = $_SESSION['user_id'];

        $audit->logDataAccess($manager_id, $_SESSION['user_role'], 'save_manager_changes', $employee_id, 'timesheet_modification', [
            'period' => $period,
            'changes_count' => count($changes)
        ]);

        if (empty($changes)) {
            echo json_encode(["success" => false, "error" => "No changes provided"]);
            exit;
        }

        $yearMonthParts = explode('-', $period);
        $year = (int)$yearMonthParts[0];
        $month = (int)$yearMonthParts[1];

        $pdo->beginTransaction();
        
        try {
            // Get submission ID and muid/team info
            $stmt = $pdo->prepare("SELECT id, muid, team FROM timesheet_submissions WHERE employee_id = ? AND year_month = ?");
            $stmt->execute([$employee_id, $period]);
            $submission = $stmt->fetch(PDO::FETCH_ASSOC);
            $submissionId = $submission['id'] ?? null;
            $muid = $submission['muid'] ?? '';
            $team = $submission['team'] ?? '';
            
            if (!$submissionId) {
                throw new Exception("No submission found for employee $employee_id, period $period");
            }

            // Get manager info
            $stmt = $pdo->prepare("SELECT username, first_name, last_name FROM users WHERE id = ?");
            $stmt->execute([$manager_id]);
            $manager = $stmt->fetch(PDO::FETCH_ASSOC);
            $managerName = ($manager['first_name'] ?? '') . ' ' . ($manager['last_name'] ?? '');
            
            // Get original timesheet data - Updated column names
            $stmt = $pdo->prepare("
                SELECT sched_date, earliest_start, latest_stop, absence_type, absence_hours,
                       employee_normal_paid_hours, sat_enhancement, sun_enhancement, 
                       nights_enhancement, bank_holiday_enhancement, extra_hours,
                       weekday_overtime, saturday_overtime, sunday_overtime, bank_holiday_overtime
                FROM processed_timesheet 
                WHERE employee_id = ? 
                AND EXTRACT(YEAR FROM sched_date) = ?
                AND EXTRACT(MONTH FROM sched_date) = ?
            ");
            $stmt->execute([$employee_id, $year, $month]);
            $originalRows = $stmt->fetchAll(PDO::FETCH_ASSOC);
            $originalByDate = [];
            foreach ($originalRows as $row) {
                $originalByDate[$row['sched_date']] = $row;
            }

            $savedChanges = 0;
            
            foreach ($changes as $dayIndex => $dayChanges) {
                $dateKey = $dayChanges['date'] ?? null;
                if (!$dateKey) continue;
                
                unset($dayChanges['date']);
                
                $originalRow = $originalByDate[$dateKey];
                
                foreach ($dayChanges as $fieldName => $newValue) {
                    $originalValue = getOriginalFieldValue($originalRow, $fieldName);
                    
                    // Handle employee_normal_paid_hours field - direct database update
                    if ($fieldName === 'normalPaidHours') {
                        $stmt = $pdo->prepare("
                            UPDATE processed_timesheet 
                            SET employee_normal_paid_hours = ? 
                            WHERE employee_id = ? AND sched_date = ?
                        ");
                        $stmt->execute([
                            convertTimeToDbFormat($newValue),
                            $employee_id, 
                            $dateKey
                        ]);
                    }
                    
                    // Check existing modification
                    $stmt = $pdo->prepare("
                        SELECT id, original_value, modified_value, modified_by_role 
                        FROM timesheet_modifications 
                        WHERE original_record_employee_id = ? 
                        AND original_record_date = ? 
                        AND field_name = ?
                        AND status IN ('pending', 'submitted')
                    ");
                    $stmt->execute([$employee_id, $dateKey, $fieldName]);
                    $existingMod = $stmt->fetch(PDO::FETCH_ASSOC);
                    
                    if ($existingMod) {
                        // Update existing record
                        $stmt = $pdo->prepare("
                            UPDATE timesheet_modifications 
                            SET modified_value = ?, 
                                original_employee_value = ?,
                                modified_by = ?, 
                                modified_by_role = 'manager',
                                manager_override = TRUE,
                                modification_date = CURRENT_TIMESTAMP
                            WHERE id = ?
                        ");
                        $stmt->execute([
                            $newValue,
                            $existingMod['modified_value'],
                            $managerName,
                            $existingMod['id']
                        ]);
                    } else {
                        // Create new modification
                        $stmt = $pdo->prepare("
                            INSERT INTO timesheet_modifications (
                                submission_id, original_record_employee_id, original_record_date, field_name,
                                original_value, modified_value, modified_by, modified_by_role,
                                manager_override, modification_date, status
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, 'manager', TRUE, CURRENT_TIMESTAMP, 'submitted')
                        ");
                        $stmt->execute([
                            $submissionId,
                            $employee_id,
                            $dateKey,
                            $fieldName,
                            $originalValue,
                            $newValue,
                            $managerName
                        ]);
                    }
                    $savedChanges++;
                }
            }
            
            $pdo->commit();
            echo json_encode([
                "success" => true,
                "message" => "Manager changes saved successfully ($savedChanges modifications)"
            ]);
            
        } catch (Exception $e) {
            if ($pdo->inTransaction()) {
                $pdo->rollback();
            }
            error_log("NHS Save manager changes error: " . $e->getMessage());
            echo json_encode(["success" => false, "error" => "Failed to save changes: " . $e->getMessage()]);
        }
        exit;
    }

    // --- APPROVE TIMESHEET ---
    if ($action === 'approve_timesheet') {
        $employee_id = filter_var($input['employee_id'] ?? '', FILTER_SANITIZE_STRING);
        $period = filter_var($input['period'] ?? '', FILTER_SANITIZE_STRING);
        $manager_id = $_SESSION['user_id'];

        $audit->logDataAccess($manager_id, $_SESSION['user_role'], 'approve_timesheet', $employee_id, 'timesheet_approval', [
            'period' => $period
        ]);

        $pdo->beginTransaction();
        
        try {
            $yearMonthParts = explode('-', $period);
            $year = (int)$yearMonthParts[0];
            $month = (int)$yearMonthParts[1];

            // Get manager info
            $stmt = $pdo->prepare("SELECT username, first_name, last_name FROM users WHERE id = ?");
            $stmt->execute([$manager_id]);
            $manager = $stmt->fetch(PDO::FETCH_ASSOC);
            $approvedBy = ($manager['first_name'] ?? '') . ' ' . ($manager['last_name'] ?? '');

            // Get submission ID and muid/team
            $stmt = $pdo->prepare("SELECT id, muid, team FROM timesheet_submissions WHERE employee_id = ? AND year_month = ?");
            $stmt->execute([$employee_id, $period]);
            $submission = $stmt->fetch(PDO::FETCH_ASSOC);
            $submissionId = $submission['id'] ?? null;
            $muid = $submission['muid'] ?? '';
            $team = $submission['team'] ?? '';

            // Get complete base data - Updated column names
            $stmt = $pdo->prepare("
                SELECT 
                    sched_date, employee_name, job_title, site, hpw,
                    earliest_start, latest_stop, 
                    total_worked_hours, employee_normal_paid_hours,
                    absence_type, absence_hours, sat_enhancement, sun_enhancement, 
                    nights_enhancement, bank_holiday_enhancement, extra_hours,
                    weekday_overtime, saturday_overtime, sunday_overtime, bank_holiday_overtime,
                    total_overtime_hours, muid, team
                FROM processed_timesheet 
                WHERE employee_id = ? 
                AND EXTRACT(YEAR FROM sched_date) = ?
                AND EXTRACT(MONTH FROM sched_date) = ?
                ORDER BY sched_date ASC
            ");
            $stmt->execute([$employee_id, $year, $month]);
            $timesheetRows = $stmt->fetchAll(PDO::FETCH_ASSOC);

            // Get approved modifications
            $stmt = $pdo->prepare("
                SELECT original_record_date, field_name, modified_value, employee_comments,
                       modified_by, modified_by_role, manager_override
                FROM timesheet_modifications 
                WHERE original_record_employee_id = ? 
                AND EXTRACT(YEAR FROM original_record_date) = ?
                AND EXTRACT(MONTH FROM original_record_date) = ?
                AND status IN ('pending', 'submitted')
                ORDER BY original_record_date, field_name, manager_override DESC
            ");
            $stmt->execute([$employee_id, $year, $month]);
            $modifications = $stmt->fetchAll(PDO::FETCH_ASSOC);

            // Group modifications by date
            $modsByDate = [];
            $employeeComments = '';
            foreach ($modifications as $mod) {
                $dateKey = $mod['original_record_date'];
                $fieldKey = $mod['field_name'];
                
                if (!isset($modsByDate[$dateKey][$fieldKey]) || $mod['manager_override']) {
                    $modsByDate[$dateKey][$fieldKey] = $mod['modified_value'];
                }
                
                if ($mod['employee_comments'] && !$employeeComments) {
                    $employeeComments = $mod['employee_comments'];
                }
            }

            // Format time helper
            $formatTime = function($timeValue) {
                if (!$timeValue) return '00:00:00';
                if (preg_match('/^\d{2}:\d{2}$/', $timeValue)) return $timeValue . ':00';
                if (preg_match('/^\d{2}:\d{2}:\d{2}$/', $timeValue)) return $timeValue;
                return '00:00:00';
            };

            // Insert approved data - Updated field names
            $insertedCount = 0;
            foreach ($timesheetRows as $row) {
                $dateKey = $row['sched_date'];
                $dayMods = $modsByDate[$dateKey] ?? [];
                
                $approvedStartTime = $dayMods['startTime'] ?? $formatTime($row['earliest_start']);
                $approvedStopTime = $dayMods['stopTime'] ?? $formatTime($row['latest_stop']);
                
                $stmt = $pdo->prepare("
				INSERT INTO approved_timesheets (
				submission_id, employee_id, employee_name, sched_date, job_title, site, hpw,
				approved_start_time, approved_stop_time, 
				approved_total_worked_hours, approved_employee_normal_paid_hours,
				approved_normal_paid_hours, approved_total_overtime_hours,
				approved_absence_type, approved_absence_hours,
				approved_sat_enhancement, approved_sun_enhancement, 
				approved_nights_enhancement, approved_bank_holiday_enhancement,
				approved_extra_hours, approved_weekday_overtime, 
				approved_saturday_overtime, approved_sunday_overtime, approved_bank_holiday_overtime,
				employee_comments, approved_by, muid, team, approved_unpaid_breaks, manager_comments
				) VALUES (
				?, ?, ?, ?, ?, ?, ?,
				?, ?, ?, ?, ?, ?,
				?, ?,
				?, ?, ?, ?,
				?, ?, ?, ?, ?,
					?, ?, ?, ?, ?, ?
			)
		");
                
                $result = $stmt->execute([
                    $submissionId, $employee_id, $row['employee_name'], $row['sched_date'],
                    $row['job_title'], $row['site'], $row['hpw'],
                    $approvedStartTime, $approvedStopTime, 
                    $formatTime($row['total_worked_hours']),
                    $dayMods['normalPaidHours'] ?? $formatTime($row['employee_normal_paid_hours']),
					$formatTime($row['employee_normal_paid_hours']),
                    $formatTime($row['total_overtime_hours']),
                    $dayMods['absenceType'] ?? $row['absence_type'],
                    $dayMods['absenceHours'] ?? $formatTime($row['absence_hours']),
                    $dayMods['satEnhancement'] ?? $formatTime($row['sat_enhancement']),
                    $dayMods['sunEnhancement'] ?? $formatTime($row['sun_enhancement']),
                    $dayMods['nightsEnhancement'] ?? $formatTime($row['nights_enhancement']),
                    $dayMods['bankHolidayEnhancement'] ?? $formatTime($row['bank_holiday_enhancement']),
                    $dayMods['extraHours'] ?? $formatTime($row['extra_hours']),
                    $dayMods['weekdayOvertime'] ?? $formatTime($row['weekday_overtime']),
                    $dayMods['satOvertime'] ?? $formatTime($row['saturday_overtime']),
                    $dayMods['sunOvertime'] ?? $formatTime($row['sunday_overtime']),
                    $dayMods['bankHolidayOvertime'] ?? $formatTime($row['bank_holiday_overtime']),
					$employeeComments, $approvedBy, $muid, $team, 
					'00:00:00', // approved_unpaid_breaks
					'', // manager_comments  
                ]);
                
                if ($result) $insertedCount++;
            }

            // Update submission status
            $stmt = $pdo->prepare("
                UPDATE timesheet_submissions
                SET status = 'approved', approval_date = CURRENT_TIMESTAMP, approved_by = ?
                WHERE employee_id = ? AND year_month = ?
            ");
            $stmt->execute([$approvedBy, $employee_id, $period]);

            // Update modifications status
            $stmt = $pdo->prepare("
                UPDATE timesheet_modifications 
                SET status = 'approved', approval_date = CURRENT_TIMESTAMP, approved_by = ?
                WHERE original_record_employee_id = ?
                AND EXTRACT(YEAR FROM original_record_date) = ?
                AND EXTRACT(MONTH FROM original_record_date) = ?
                AND status IN ('pending', 'submitted')
            ");
            $stmt->execute([$approvedBy, $employee_id, $year, $month]);
            
            $pdo->commit();

            echo json_encode([
                "success" => true, 
                "message" => "Timesheet approved and saved for payroll ($insertedCount days processed)"
            ]);
            
        } catch (Exception $e) {
            if ($pdo->inTransaction()) {
                $pdo->rollback();
            }
            error_log("NHS Approve timesheet error: " . $e->getMessage());
            echo json_encode(["success" => false, "error" => "Approval failed: " . $e->getMessage()]);
        }
        exit;
    }

    // --- REJECT TIMESHEET ---
    if ($action === 'reject_timesheet') {
        $employee_id = filter_var($input['employee_id'] ?? '', FILTER_SANITIZE_STRING);
        $period = filter_var($input['period'] ?? '', FILTER_SANITIZE_STRING);
        $reason = filter_var($input['reason'] ?? 'Rejected by manager', FILTER_SANITIZE_STRING);
        $manager_id = $_SESSION['user_id'];

        $audit->logDataAccess($manager_id, $_SESSION['user_role'], 'reject_timesheet', $employee_id, 'timesheet_rejection', [
            'period' => $period,
            'reason' => $reason
        ]);

        // Get manager info
        $stmt = $pdo->prepare("SELECT username, first_name, last_name FROM users WHERE id = ?");
        $stmt->execute([$manager_id]);
        $manager = $stmt->fetch(PDO::FETCH_ASSOC);
        $rejectedBy = ($manager['first_name'] ?? '') . ' ' . ($manager['last_name'] ?? '');

        $pdo->beginTransaction();

        // Update submission status to 'draft'
        $stmt = $pdo->prepare("
            UPDATE timesheet_submissions
            SET status = 'draft', manager_comments = ?, rejected_by = ?, rejection_date = CURRENT_TIMESTAMP
            WHERE employee_id = ? AND year_month = ?
        ");
        $stmt->execute([$reason, $rejectedBy, $employee_id, $period]);

        // Update modifications status to 'pending'
        $yearMonthParts = explode('-', $period);
        $stmt = $pdo->prepare("
            UPDATE timesheet_modifications 
            SET status = 'pending', manager_comments = ?, rejected_by = ?, rejection_date = CURRENT_TIMESTAMP
            WHERE original_record_employee_id = ?
            AND EXTRACT(YEAR FROM original_record_date) = ?
            AND EXTRACT(MONTH FROM original_record_date) = ?
            AND status IN ('pending', 'submitted')
        ");
        $stmt->execute([$reason, $rejectedBy, $employee_id, (int)$yearMonthParts[0], (int)$yearMonthParts[1]]);

        $pdo->commit();

        echo json_encode(["success" => true, "message" => "Timesheet rejected and returned to employee for corrections"]);
        exit;
    }

    if ($action === 'logout') {
        $session->destroySession('user_logout');
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
    error_log("NHS Manager API Error: " . $e->getMessage());
    echo json_encode(["success" => false, "error" => "System error occurred"]);
}

// Helper function - Updated with new field mappings
function getOriginalFieldValue($originalRow, $fieldName) {
    switch($fieldName) {
        case 'startTime': return $originalRow['earliest_start'] ?? '';
        case 'stopTime': return $originalRow['latest_stop'] ?? '';
        case 'normalPaidHours': return $originalRow['employee_normal_paid_hours'] ?? '00:00';
        case 'absenceType': return $originalRow['absence_type'] ?? '';
        case 'absenceHours': return $originalRow['absence_hours'] ?? '00:00';
        case 'satEnhancement': return $originalRow['sat_enhancement'] ?? '00:00';
        case 'sunEnhancement': return $originalRow['sun_enhancement'] ?? '00:00';
        case 'nightsEnhancement': return $originalRow['nights_enhancement'] ?? '00:00';
        case 'bankHolidayEnhancement': return $originalRow['bank_holiday_enhancement'] ?? '00:00';
        case 'extraHours': return $originalRow['extra_hours'] ?? '00:00';
        case 'weekdayOvertime': return $originalRow['weekday_overtime'] ?? '00:00';
        case 'satOvertime': return $originalRow['saturday_overtime'] ?? '00:00';
        case 'sunOvertime': return $originalRow['sunday_overtime'] ?? '00:00';
        case 'bankHolidayOvertime': return $originalRow['bank_holiday_overtime'] ?? '00:00';
        default: return '';
    }
}

function convertTimeToDbFormat($timeStr) {
    if (!$timeStr || $timeStr === '00:00') return '00:00:00';
    if (preg_match('/^\d{2}:\d{2}$/', $timeStr)) return $timeStr . ':00';
    return $timeStr;
}
?>