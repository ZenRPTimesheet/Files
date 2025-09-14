<?php
session_start();

// Security Configuration
ini_set('session.cookie_httponly', 1);
ini_set('session.use_only_cookies', 1);
ini_set('session.cookie_secure', 1);
ini_set('session.cookie_samesite', 'Strict');

// Security Headers
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self';");

// Rate limiting (basic)
if (!isset($_SESSION['requests'])) {
    $_SESSION['requests'] = [];
}
$now = time();
$_SESSION['requests'] = array_filter($_SESSION['requests'], function($timestamp) use ($now) {
    return ($now - $timestamp) < 60; // Keep requests from last minute
});

if (count($_SESSION['requests']) > 60) { // Max 60 requests per minute
    http_response_code(429);
    exit('Too many requests');
}
$_SESSION['requests'][] = $now;

// CSRF Token Generation
function generateCSRFToken() {
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function validateCSRFToken($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

// Input Sanitization
function sanitizeInput($input) {
    if (is_array($input)) {
        return array_map('sanitizeInput', $input);
    }
    return htmlspecialchars(strip_tags(trim($input)), ENT_QUOTES, 'UTF-8');
}

function sanitizeTimeInput($input) {
    if (!preg_match('/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/', $input)) {
        return '00:00';
    }
    return $input;
}

// API handling with enhanced security
if (isset($_GET['path'])) {
    header('Content-Type: application/json');
    
    $path = sanitizeInput($_GET['path']);
    $method = $_SERVER['REQUEST_METHOD'];
    
    // Demo database with hashed passwords
    $employees = [
        'employee' => [
            'id' => 'employee',
            'password' => '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', // password123
            'name' => 'John Smith',
            'site' => 'Royal London Hospital',
            'jobTitle' => 'Staff Nurse',
            'hpw' => '37.5'
        ]
    ];
    
    // Sample timesheet data
    $timesheetData = [
        'employee-2025-01' => [
            [
                'date' => '01/01/2025',
                'startTime' => '08:00',
                'stopTime' => '16:30',
                'unpaidBreaks' => '00:30',
                'normalPaidHours' => '08:00',
                'overtimeHours' => '00:00',
                'absenceType' => 'None',
                'absenceHours' => '00:00',
                'normalPaidHoursInput' => '08:00',
                'satEnhancement' => '00:00',
                'sunEnhancement' => '00:00',
                'nightsEnhancement' => '00:00',
                'bankHolidayEnhancement' => '08:00',
                'extraHours' => '00:00',
                'weekdayOvertime' => '00:00',
                'satOvertime' => '00:00',
                'sunOvertime' => '00:00',
                'bankHolidayOvertime' => '00:00',
                'comments' => 'New Year\'s Day - Bank Holiday'
            ]
        ]
    ];
    
    try {
        switch ($path) {
            case '/login':
                if ($method === 'POST') {
                    $input = json_decode(file_get_contents('php://input'), true);
                    
                    if (!$input || !isset($input['employee_id']) || !isset($input['password'])) {
                        echo json_encode(['success' => false, 'error' => 'Invalid input']);
                        exit;
                    }
                    
                    $employeeId = sanitizeInput($input['employee_id']);
                    $password = $input['password'];
                    
                    if (isset($employees[$employeeId]) && password_verify($password, $employees[$employeeId]['password'])) {
                        $_SESSION['employee_id'] = $employeeId;
                        $_SESSION['last_activity'] = time();
                        
                        echo json_encode([
                            'success' => true,
                            'employee' => [
                                'id' => $employees[$employeeId]['id'],
                                'name' => $employees[$employeeId]['name'],
                                'site' => $employees[$employeeId]['site'],
                                'jobTitle' => $employees[$employeeId]['jobTitle'],
                                'hpw' => $employees[$employeeId]['hpw']
                            ]
                        ]);
                    } else {
                        sleep(1); // Prevent brute force
                        echo json_encode(['success' => false, 'error' => 'Invalid credentials']);
                    }
                }
                break;
                
            case (preg_match('/^\/available-months\/(.+)$/', $path, $matches) ? true : false):
                if (!isset($_SESSION['employee_id'])) {
                    http_response_code(401);
                    echo json_encode(['success' => false, 'error' => 'Unauthorized']);
                    exit;
                }
                
                echo json_encode([
                    'success' => true,
                    'months' => [
                        ['year' => '2025', 'month' => '01', 'display_name' => 'January 2025'],
                        ['year' => '2024', 'month' => '12', 'display_name' => 'December 2024']
                    ]
                ]);
                break;
                
            case (preg_match('/^\/timesheet\/(.+)\/(\d{4})\/(\d{2})$/', $path, $matches) ? true : false):
                if (!isset($_SESSION['employee_id'])) {
                    http_response_code(401);
                    echo json_encode(['success' => false, 'error' => 'Unauthorized']);
                    exit;
                }
                
                $employeeId = sanitizeInput($matches[1]);
                $year = sanitizeInput($matches[2]);
                $month = sanitizeInput($matches[3]);
                $key = "$employeeId-$year-$month";
                
                if ($employeeId !== $_SESSION['employee_id']) {
                    http_response_code(403);
                    echo json_encode(['success' => false, 'error' => 'Access denied']);
                    exit;
                }
                
                $data = isset($timesheetData[$key]) ? $timesheetData[$key] : [];
                
                echo json_encode([
                    'success' => true,
                    'timesheetData' => $data,
                    'originalTimesheetData' => $data,
                    'is_locked' => false,
                    'submission_status' => 'draft',
                    'manager_comments' => '',
                    'modifications_count' => 0
                ]);
                break;
                
            case '/save-draft':
                if ($method === 'POST') {
                    if (!isset($_SESSION['employee_id'])) {
                        http_response_code(401);
                        echo json_encode(['success' => false, 'error' => 'Unauthorized']);
                        exit;
                    }
                    
                    $input = json_decode(file_get_contents('php://input'), true);
                    
                    if (!$input || !isset($input['timesheet_data'])) {
                        echo json_encode(['success' => false, 'error' => 'Invalid input']);
                        exit;
                    }
                    
                    // Sanitize timesheet data
                    $timesheetData = array_map(function($row) {
                        return [
                            'date' => sanitizeInput($row['date'] ?? ''),
                            'startTime' => sanitizeTimeInput($row['startTime'] ?? '00:00'),
                            'stopTime' => sanitizeTimeInput($row['stopTime'] ?? '00:00'),
                            'normalPaidHoursInput' => sanitizeTimeInput($row['normalPaidHoursInput'] ?? '00:00'),
                            'satEnhancement' => sanitizeTimeInput($row['satEnhancement'] ?? '00:00'),
                            'sunEnhancement' => sanitizeTimeInput($row['sunEnhancement'] ?? '00:00'),
                            'nightsEnhancement' => sanitizeTimeInput($row['nightsEnhancement'] ?? '00:00'),
                            'bankHolidayEnhancement' => sanitizeTimeInput($row['bankHolidayEnhancement'] ?? '00:00'),
                            'extraHours' => sanitizeTimeInput($row['extraHours'] ?? '00:00'),
                            'weekdayOvertime' => sanitizeTimeInput($row['weekdayOvertime'] ?? '00:00'),
                            'satOvertime' => sanitizeTimeInput($row['satOvertime'] ?? '00:00'),
                            'sunOvertime' => sanitizeTimeInput($row['sunOvertime'] ?? '00:00'),
                            'bankHolidayOvertime' => sanitizeTimeInput($row['bankHolidayOvertime'] ?? '00:00'),
                            'comments' => sanitizeInput($row['comments'] ?? '')
                        ];
                    }, $input['timesheet_data']);
                    
                    echo json_encode(['success' => true, 'message' => 'Draft saved successfully']);
                }
                break;
                
            case '/submit-timesheet':
                if ($method === 'POST') {
                    if (!isset($_SESSION['employee_id'])) {
                        http_response_code(401);
                        echo json_encode(['success' => false, 'error' => 'Unauthorized']);
                        exit;
                    }
                    
                    echo json_encode(['success' => true, 'message' => 'Timesheet submitted successfully']);
                }
                break;
                
            case '/request-password-reset':
                if ($method === 'POST') {
                    $input = json_decode(file_get_contents('php://input'), true);
                    
                    if (!$input || !isset($input['employee_id'])) {
                        echo json_encode(['success' => false, 'error' => 'Invalid input']);
                        exit;
                    }
                    
                    // In production, this would send an email
                    echo json_encode(['success' => true, 'message' => 'Password reset email sent']);
                }
                break;
                
            default:
                http_response_code(404);
                echo json_encode(['success' => false, 'error' => 'Endpoint not found']);
                break;
        }
    } catch (Exception $e) {
        http_response_code(500);
        echo json_encode(['success' => false, 'error' => 'Server error']);
    }
    exit;
}

// Session timeout check
if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity']) > 1800) {
    session_unset();
    session_destroy();
    session_start();
}
if (isset($_SESSION['employee_id'])) {
    $_SESSION['last_activity'] = time();
}

$csrfToken = generateCSRFToken();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NHS Timesheet System - Employee Portal</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }
        
        .login-container { display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 20px; }
        .login-box { background: white; border-radius: 15px; box-shadow: 0 20px 40px rgba(0,0,0,0.1); overflow: hidden; width: 100%; max-width: 450px; }
        .login-header { background: #005eb8; color: white; padding: 40px 30px 30px; text-align: center; }
        .nhs-logo { font-size: 32px; margin-bottom: 10px; }
        .login-title { font-size: 24px; font-weight: 600; margin-bottom: 8px; }
        .login-subtitle { font-size: 14px; opacity: 0.9; }
        .login-form { padding: 40px 30px; }
        .form-group { margin-bottom: 25px; }
        .form-label { display: block; margin-bottom: 8px; font-weight: 600; color: #495057; font-size: 14px; }
        .form-input, .form-select { width: 100%; padding: 15px; border: 2px solid #e9ecef; border-radius: 8px; font-size: 16px; transition: all 0.3s; background: #f8f9fa; }
        .form-input:focus, .form-select:focus { outline: none; border-color: #005eb8; background: white; box-shadow: 0 0 0 3px rgba(0, 94, 184, 0.1); }
        .login-btn { width: 100%; padding: 15px; background: #005eb8; color: white; border: none; border-radius: 8px; font-size: 16px; font-weight: 600; cursor: pointer; transition: all 0.3s; margin-bottom: 20px; }
        .login-btn:hover { background: #004494; transform: translateY(-2px); box-shadow: 0 5px 15px rgba(0, 94, 184, 0.3); }
        .login-btn:disabled { background: #6c757d; cursor: not-allowed; transform: none; }
        
        .alert { padding: 12px 15px; border-radius: 6px; margin-bottom: 20px; font-size: 14px; border-left: 4px solid; }
        .alert-error { background: #f8d7da; color: #721c24; border-color: #dc3545; }
        .alert-info { background: #e7f3ff; color: #004085; border-color: #005eb8; }
        .alert-success { background: #d1f2eb; color: #0f5132; border-color: #28a745; }
        .alert-warning { background: #fff3cd; color: #856404; border-color: #ffc107; }
        
        .timesheet-container { max-width: 1800px; margin: 20px auto; background: white; border-radius: 15px; box-shadow: 0 10px 30px rgba(0,0,0,0.1); overflow: hidden; }
        .timesheet-header { background: #005eb8; color: white; padding: 20px 30px; display: grid; grid-template-columns: 1fr auto; gap: 20px; align-items: center; }
        .employee-info { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; }
        .info-group { display: flex; flex-direction: column; }
        .info-label { font-size: 12px; opacity: 0.8; margin-bottom: 5px; }
        .info-value { font-size: 16px; font-weight: 600; }
        .header-actions { display: flex; align-items: center; gap: 10px; }
        
        .month-selector { background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 8px; padding: 20px 30px; margin: 0; }
        .month-selector-title { font-size: 18px; font-weight: 600; color: #495057; margin-bottom: 15px; }
        .month-selector-form { display: flex; align-items: end; gap: 15px; }
        .month-input-group { flex: 1; }
        .month-input-group label { display: block; margin-bottom: 5px; font-weight: 500; color: #495057; font-size: 14px; }
        .month-input { width: 100%; padding: 10px; border: 1px solid #ced4da; border-radius: 5px; font-size: 14px; }
        
        .btn { padding: 8px 16px; border: none; border-radius: 5px; cursor: pointer; font-weight: 600; transition: all 0.3s; font-size: 14px; }
        .btn-secondary { background: #6c757d; color: white; }
        .btn-secondary:hover { background: #545b62; }
        .btn-primary { background: #28a745; color: white; }
        .btn-primary:hover { background: #218838; }
        .btn-save { background: #007bff; color: white; margin-left: 10px; }
        .btn-save:hover { background: #0056b3; }
        .btn-submit { background: #28a745; color: white; margin-left: 10px; }
        .btn-submit:hover { background: #218838; }
        
        .hidden { display: none !important; }
        
        /* Desktop Table Styles */
        .timesheet-table { width: 100%; border-collapse: collapse; font-size: 14px; }
        .timesheet-table th { background: #f8f9fa; padding: 12px 8px; text-align: center; border: 1px solid #dee2e6; font-weight: 600; font-size: 11px; color: #495057; }
        .timesheet-table td { padding: 10px 8px; text-align: center; border: 1px solid #dee2e6; vertical-align: middle; }
        .date-cell { background: #e9ecef; font-weight: 600; text-align: left; padding-left: 15px; }
        .time-input { width: 85px; padding: 4px; border: 1px solid #ced4da; border-radius: 3px; text-align: center; font-size: 12px; }
        .time-input.changed { border-color: #007bff; background: #e7f3ff; }
        .time-input:disabled { background: #e9ecef; color: #6c757d; }
        
        /* Mobile Card Layout */
        .mobile-timesheet-card {
            display: none;
            background: white;
            border-radius: 12px;
            margin: 15px 0;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        .mobile-card-header {
            background: #f8f9fa;
            padding: 15px 20px;
            border-bottom: 1px solid #dee2e6;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .mobile-card-title {
            font-weight: 600;
            color: #2c3e50;
            font-size: 16px;
        }
        .mobile-card-body {
            padding: 20px;
        }
        .mobile-card-section {
            margin-bottom: 20px;
        }
        .mobile-card-section:last-child {
            margin-bottom: 0;
        }
        .mobile-section-title {
            font-weight: 600;
            color: #495057;
            margin-bottom: 10px;
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            border-bottom: 2px solid #e9ecef;
            padding-bottom: 5px;
        }
        .mobile-field-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 8px 0;
            border-bottom: 1px solid #f1f3f4;
        }
        .mobile-field-row:last-child {
            border-bottom: none;
        }
        .mobile-field-label {
            font-weight: 500;
            color: #6c757d;
            font-size: 14px;
            flex: 1;
        }
        .mobile-field-value {
            font-weight: 600;
            color: #2c3e50;
            font-size: 14px;
        }
        .mobile-time-input {
            width: 100px;
            padding: 8px;
            border: 1px solid #dee2e6;
            border-radius: 4px;
            font-size: 16px;
            text-align: center;
        }
        .mobile-comments-input {
            width: 100%;
            min-height: 60px;
            padding: 8px 12px;
            border: 1px solid #dee2e6;
            border-radius: 4px;
            font-size: 16px;
            resize: vertical;
            margin-top: 8px;
            font-family: inherit;
        }
        
        .absence-highlight { background: #fff3cd !important; border-color: #ffc107 !important; }
        .readonly { background: #f8f9fa !important; color: #6c757d; font-weight: 500; }
        .locked { background: #e9ecef !important; color: #6c757d; font-weight: 500; }
        .hours-cell { font-weight: 600; }
        .hours-zero { color: #6c757d !important; }
        .hours-positive { color: #005eb8 !important; }
        .paid-hours { background: #d1f2eb !important; color: #0f5132; }
        .overtime-hours { background: #fff3cd !important; color: #856404; }
        .enhancement-cell { background: #e7f3ff; font-weight: 500; }
        .overtime-cell { background: #fff3cd; font-weight: 500; }
        .extra-hours-cell { background: #d1f2eb; font-weight: 500; }
        .normal-paid-input-cell { background: #e8f5e8; font-weight: 500; }
        .comments-input { width: 120px; padding: 4px; border: 1px solid #ced4da; border-radius: 3px; font-size: 11px; }
        .comments-input.changed { border-color: #007bff; background: #e7f3ff; }
        .comments-input:disabled { background: #e9ecef; color: #6c757d; }
        
        .status-info { background: #e7f3ff; border: 1px solid #005eb8; border-radius: 8px; padding: 15px; margin: 20px 30px; }
        .status-info-title { font-weight: 600; color: #005eb8; margin-bottom: 10px; }
        .loading-spinner { width: 20px; height: 20px; border: 2px solid #ffffff; border-top: 2px solid transparent; border-radius: 50%; animation: spin 1s linear infinite; display: inline-block; margin-right: 8px; }
        .save-indicator { position: fixed; top: 20px; right: 20px; background: #28a745; color: white; padding: 10px 15px; border-radius: 5px; display: none; z-index: 1000; }
        .status-badge { padding: 4px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; text-transform: uppercase; }
        .status-draft { background: #e9ecef; color: #495057; }
        .status-submitted { background: #fff3cd; color: #856404; }
        .status-approved { background: #d1f2eb; color: #0f5132; }
        .status-rejected { background: #f8d7da; color: #721c24; }
        .action-buttons { margin: 20px 30px; text-align: right; border-top: 1px solid #dee2e6; padding-top: 20px; }
        .totals-row { background: #f8f9fa !important; border-top: 2px solid #005eb8 !important; font-weight: 600; }
        .totals-row td { font-weight: 600 !important; }
        .absence-text { font-size: 10px; line-height: 1.2; padding: 2px; text-align: center; }
        .field-changed { background: #e7f3ff !important; border: 2px solid #007bff !important; font-weight: bold; }
        .status-pending-changes { background: #fff3cd; color: #856404; border-color: #ffc107; }
        .changes-summary { margin-top: 10px; padding: 10px; background: #f8f9fa; border-radius: 5px; font-size: 12px; color: #495057; }
        .row-has-changes { background: #f8f9fa !important; }
        
        /* Hours Summary Styles */
        .hours-summary { background: #fff8e1; border: 1px solid #ffcc02; border-radius: 8px; padding: 20px; margin: 20px 30px; }
        .hours-summary-title { font-weight: 600; color: #e65100; margin-bottom: 15px; font-size: 18px; text-align: center; }
        .hours-summary-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 20px; }
        .hours-card { background: white; border-radius: 8px; padding: 20px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .hours-card.expected { border-left: 4px solid #28a745; }
        .hours-card.claimed { border-left: 4px solid #007bff; }
        .hours-card.variance { border-left: 4px solid #ffc107; }
        .hours-card.variance.over-claimed { border-left-color: #dc3545; }
        .hours-label { font-size: 14px; color: #6c757d; margin-bottom: 8px; font-weight: 600; }
        .hours-value { font-size: 32px; font-weight: 700; margin-bottom: 5px; }
        .hours-card.expected .hours-value { color: #28a745; }
        .hours-card.claimed .hours-value { color: #007bff; }
        .hours-card.variance .hours-value { color: #ffc107; }
        .hours-card.variance.over-claimed .hours-value { color: #dc3545; }
        .hours-subtitle { font-size: 12px; color: #6c757d; font-style: italic; }
        
        /* Mobile Totals Summary */
        .mobile-totals-card {
            background: #f8f9fa;
            border: 2px solid #005eb8;
            border-radius: 12px;
            padding: 20px;
            margin: 20px 0;
            display: none;
        }
        .mobile-totals-title {
            font-weight: 700;
            color: #005eb8;
            font-size: 18px;
            text-align: center;
            margin-bottom: 15px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .mobile-totals-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 10px;
        }
        .mobile-total-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 8px 12px;
            background: white;
            border-radius: 6px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        .mobile-total-label {
            font-weight: 500;
            color: #495057;
            font-size: 12px;
        }
        .mobile-total-value {
            font-weight: 700;
            color: #2c3e50;
            font-size: 14px;
        }
        
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        
        /* Mobile Responsive Styles */
        @media (max-width: 768px) {
            body { background-attachment: fixed; }
            
            .login-container { padding: 15px; }
            .login-form { padding: 30px 20px; }
            .login-form input, .login-form button { font-size: 16px; }
            
            .timesheet-container { margin: 10px; }
            
            .timesheet-header { 
                padding: 15px 20px;
                grid-template-columns: 1fr;
                gap: 15px;
                text-align: center;
            }
            
            .employee-info { 
                grid-template-columns: 1fr 1fr;
                gap: 10px;
            }
            
            .header-actions { 
                justify-content: center;
            }
            
            .month-selector { 
                padding: 15px 20px;
                margin: 0;
            }
            
            .month-selector-form { 
                flex-direction: column;
                gap: 15px;
            }
            
            .month-input-group { 
                width: 100%;
            }
            
            .btn { 
                width: 100%;
                padding: 12px 20px;
                font-size: 16px;
                margin: 5px 0;
            }
            
            .status-info, .hours-summary { 
                margin: 15px 20px;
                padding: 15px;
            }
            
            .hours-summary-cards { 
                grid-template-columns: 1fr;
                gap: 15px;
            }
            
            .hours-card { 
                padding: 15px;
            }
            
            .hours-value { 
                font-size: 28px;
            }
            
            /* Hide desktop table on mobile */
            .timesheet-table { 
                display: none;
            }
            
            /* Show mobile cards */
            .mobile-timesheet-card { 
                display: block;
            }
            
            .mobile-totals-card {
                display: block;
            }
            
            .action-buttons { 
                margin: 15px 20px;
                text-align: center;
            }
            
            .action-buttons .btn { 
                width: 100%;
                margin: 5px 0;
                padding: 15px;
            }
            
            /* Mobile input improvements */
            .mobile-time-input, .mobile-comments-input { 
                font-size: 16px; /* Prevent zoom on iOS */
            }
            
            .mobile-field-row { 
                flex-direction: column;
                align-items: flex-start;
                gap: 8px;
            }
            
            .mobile-time-input { 
                width: 100%;
                max-width: 200px;
            }
        }
        
        @media (max-width: 480px) {
            .timesheet-container { margin: 5px; }
            
            .timesheet-header { padding: 10px 15px; }
            
            .employee-info { 
                grid-template-columns: 1fr;
                gap: 8px;
            }
            
            .info-value { font-size: 14px; }
            
            .month-selector, .status-info, .hours-summary { 
                margin: 10px 15px;
                padding: 12px;
            }
            
            .mobile-card-header, .mobile-card-body { 
                padding: 15px;
            }
            
            .mobile-card-title { 
                font-size: 14px;
            }
            
            .mobile-section-title { 
                font-size: 12px;
            }
            
            .mobile-field-label, .mobile-field-value { 
                font-size: 13px;
            }
            
            .hours-value { 
                font-size: 24px;
            }
            
            .action-buttons { 
                margin: 10px 15px;
            }
            
            .mobile-totals-grid { 
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div id="loginView" class="login-container">
        <div class="login-box">
            <div class="login-header">
                <div class="nhs-logo">🏥</div>
                <h1 class="login-title">NHS Timesheet System</h1>
                <p class="login-subtitle">Employee Portal</p>
            </div>
            <div class="login-form">
                <div id="errorAlert" class="alert alert-error hidden">Invalid employee ID. Please try again.</div>
                <div class="alert alert-info">Please LogIn below.</div>
                <form id="loginForm">
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrfToken); ?>">
                    <div class="form-group">
                        <label for="employeeId" class="form-label">Employee ID</label>
                        <input type="text" id="employeeId" name="employeeId" class="form-input" placeholder="Enter your employee ID" required autocomplete="username">
                    </div>
                    <div class="form-group">
                        <label for="password" class="form-label">Password</label>
                        <input type="password" id="password" name="password" class="form-input" placeholder="Enter your password" required autocomplete="current-password">
                    </div>
                    <button type="submit" id="loginBtn" class="login-btn">
                        <span id="loginText">Sign In</span>
                        <span id="loginSpinner" class="loading-spinner hidden"></span>
                    </button>
					<div style="text-align: center; margin-top: 15px;">
					<a href="#" onclick="showResetPassword()" style="color: #005eb8; text-decoration: none; font-size: 14px;">Reset Password</a>
					</div>
                </form>
            </div>
        </div>
    </div>

    <div id="timesheetView" class="hidden">
        <div class="timesheet-container">
            <div class="timesheet-header">
                <div class="employee-info">
                    <div class="info-group">
                        <span class="info-label">Employee Name</span>
                        <span class="info-value" id="employeeName">-</span>
                    </div>
                    <div class="info-group">
                        <span class="info-label">Employee ID</span>
                        <span class="info-value" id="employeeIdDisplay">-</span>
                    </div>
                    <div class="info-group">
                        <span class="info-label">Job Title</span>
                        <span class="info-value" id="jobTitle">-</span>
                    </div>
                    <div class="info-group">
                        <span class="info-label">Site</span>
                        <span class="info-value" id="site">-</span>
                    </div>
                    <div class="info-group">
                        <span class="info-label">HPW</span>
                        <span class="info-value" id="hpw">-</span>
                    </div>
                </div>
                <div class="header-actions">
                    <button class="btn btn-secondary" onclick="logout()">Logout</button>
                </div>
            </div>
            
            <div class="month-selector">
                <h3 class="month-selector-title">Select Month to Edit</h3>
                <div class="month-selector-form">
                    <div class="month-input-group">
                        <label for="selectedMonth">Available Months:</label>
                        <select id="selectedMonth" class="month-input">
                            <option value="">-- Select a Month --</option>
                        </select>
                    </div>
                    <button type="button" class="btn btn-primary" onclick="loadSelectedMonth()">Load Timesheet</button>
                </div>
            </div>
            
            <div id="statusInfo" class="status-info hidden">
                <div class="status-info-title">Timesheet Status</div>
                <div id="statusContent"></div>
            </div>
            
            <div id="hoursSummary" class="hours-summary hidden">
                <div class="hours-summary-title">Hours Summary</div>
                <div class="hours-summary-cards">
                    <div class="hours-card expected">
                        <div class="hours-label">Expected Hours:</div>
                        <div class="hours-value" id="expectedHours">00:00</div>
                        <div class="hours-subtitle">(Total Worked + Absence)</div>
                    </div>
                    <div class="hours-card claimed">
                        <div class="hours-label">Employee Claimed:</div>
                        <div class="hours-value" id="claimedHours">00:00</div>
                        <div class="hours-subtitle">(Normal Paid + Absence+ Enhancements + Overtime)</div>
                    </div>
                    <div class="hours-card variance">
                        <div class="hours-label">Variance:</div>
                        <div class="hours-value" id="varianceHours">00:00</div>
                        <div class="hours-subtitle" id="varianceLabel">Balanced</div>
                    </div>
                </div>
            </div>
            
            <div id="timesheetTableContainer" class="hidden">
                <!-- Desktop Table -->
                <div style="overflow-x: auto; margin: 20px 30px;">
                    <table class="timesheet-table">
                        <thead>
                            <tr>
                                <th rowspan="2">Date</th>
                                <th rowspan="2">Start Time</th>
                                <th rowspan="2">Stop Time</th>
                                <th rowspan="2">Unpaid<br>Breaks</th>
                                <th rowspan="2">Total Worked<br>Hours</th>
                                <th rowspan="2">Overtime<br>Hours</th>
                                <th rowspan="2">Absence Type</th>
                                <th rowspan="2">Absence<br>Hours</th>
                                <th rowspan="2">Normal Paid<br>Hours</th>
                                <th colspan="4">Enhancements</th>
                                <th colspan="5">Overtime & Extra Hours</th>
                                <th rowspan="2">Comments</th>
                            </tr>
                            <tr>
                                <th>Sat<br>Enhancement</th>
                                <th>Sun<br>Enhancement</th>
                                <th>Nights<br>Enhancement</th>
                                <th>Bank Holiday<br>Enhancement</th>
                                <th>Extra<br>Hours</th>
                                <th>Weekday<br>Overtime</th>
                                <th>Saturday<br>Overtime</th>
                                <th>Sunday<br>Overtime</th>
                                <th>Bank Holiday<br>Overtime</th>
                            </tr>
                        </thead>
                        <tbody id="timesheetData">
                            <!-- Timesheet rows will be populated here -->
                        </tbody>
                        <tfoot>
                            <tr class="totals-row">
                                <td style="text-align: left; padding-left: 15px;">TOTALS</td>
                                <td>-</td>
                                <td>-</td>
                                <td class="hours-cell" id="totalUnpaidBreaks">00:00</td>
                                <td class="hours-cell" id="totalWorkedHours">00:00</td>
                                <td class="hours-cell" id="totalOvertimeHours">00:00</td>
                                <td>-</td>
                                <td class="hours-cell" id="totalAbsenceHours">00:00</td>
                                <td class="hours-cell" id="totalNormalPaidHours">00:00</td>
                                <td class="enhancement-cell" id="totalSatEnhancement">00:00</td>
                                <td class="enhancement-cell" id="totalSunEnhancement">00:00</td>
                                <td class="enhancement-cell" id="totalNightsEnhancement">00:00</td>
                                <td class="enhancement-cell" id="totalBankHolEnhancement">00:00</td>
                                <td class="extra-hours-cell" id="totalExtraHours">00:00</td>
                                <td class="overtime-cell" id="totalWeekdayOT">00:00</td>
                                <td class="overtime-cell" id="totalSatOT">00:00</td>
                                <td class="overtime-cell" id="totalSunOT">00:00</td>
                                <td class="overtime-cell" id="totalBankHolOT">00:00</td>
                                <td>-</td>
                            </tr>
                        </tfoot>
                    </table>
                </div>
                
                <!-- Mobile Cards Container -->
                <div id="mobileTimesheetCards" style="margin: 20px;"></div>
                
                <!-- Mobile Totals Card -->
                <div class="mobile-totals-card" id="mobileTotalsCard" style="margin: 20px;">
                    <div class="mobile-totals-title">Totals Summary</div>
                    <div class="mobile-totals-grid" id="mobileTotalsGrid">
                        <!-- Totals will be populated here -->
                    </div>
                </div>
                
                <div class="action-buttons">
                    <button type="button" class="btn btn-save" onclick="saveDraft()" id="saveButton" disabled>Save Draft</button>
                    <button type="button" class="btn btn-submit" onclick="submitTimesheet()" id="submitButton" disabled>Submit for Manager Approval</button>
                </div>
            </div>
        </div>
    </div>

    <div class="save-indicator" id="saveIndicator">Saved successfully!</div>

    <script>
        var API_BASE_URL = '<?php echo htmlspecialchars($_SERVER['PHP_SELF']); ?>';
        var currentUser = null;
        var timesheetData = [];
        var originalData = [];
        var hasUnsavedChanges = false;
        var currentMonth = null;
        var isLocked = false;
        var csrfToken = '<?php echo htmlspecialchars($csrfToken); ?>';
        
        document.addEventListener('DOMContentLoaded', function() {
            console.log('NHS Timesheet System - Employee Portal');
            showLogin();
            document.getElementById('loginForm').addEventListener('submit', handleLogin);
            
            // Security: Disable right-click and common dev shortcuts
            document.addEventListener('contextmenu', e => e.preventDefault());
            document.addEventListener('keydown', function(e) {
                if (e.key === 'F12' || (e.ctrlKey && e.shiftKey && (e.key === 'I' || e.key === 'C' || e.key === 'J'))) {
                    e.preventDefault();
                }
            });
        });
        
        function showLogin() {
            document.getElementById('loginView').classList.remove('hidden');
            document.getElementById('timesheetView').classList.add('hidden');
        }
        
        function showTimesheet() {
            console.log('Showing timesheet for user:', currentUser);
            document.getElementById('loginView').classList.add('hidden');
            document.getElementById('timesheetView').classList.remove('hidden');
            
            if (currentUser) {
                document.getElementById('employeeName').textContent = currentUser.name;
                document.getElementById('employeeIdDisplay').textContent = currentUser.employeeId;
                document.getElementById('jobTitle').textContent = currentUser.jobTitle;
                document.getElementById('site').textContent = currentUser.site;
                document.getElementById('hpw').textContent = currentUser.hpw;
                loadAvailableMonths();
            }
        }
        
        async function loadAvailableMonths() {
            console.log('Loading available months for:', currentUser.employeeId);
            if (!currentUser) return;
            
            try {
                const url = API_BASE_URL + '?path=/available-months/' + encodeURIComponent(currentUser.employeeId);
                console.log('Calling URL:', url);
                
                const response = await fetch(url);
                const data = await response.json();
                console.log('Available months response:', data);

                if (data.success) {
                    const selectElement = document.getElementById('selectedMonth');
                    selectElement.innerHTML = '<option value="">-- Select a Month --</option>';
                    
                    data.months.forEach(month => {
                        const option = document.createElement('option');
                        option.value = month.year + '-' + month.month;
                        option.textContent = month.display_name.trim();
                        selectElement.appendChild(option);
                    });
                    console.log('Dropdown populated with', data.months.length, 'months');
                } else {
                    console.error('Failed to load available months:', data.error);
                }
            } catch (error) {
                console.error('Error loading available months:', error);
            }
        }
        
        async function handleLogin(e) {
            e.preventDefault();
            
            const employeeId = document.getElementById('employeeId').value.trim();
            const password = document.getElementById('password').value;
            
            console.log('Attempting login for employee:', employeeId);
            
            try {
                const response = await fetch(API_BASE_URL + '?path=/login', {
                    method: 'POST',
                    headers: { 
                        'Content-Type': 'application/json',
                        'X-Requested-With': 'XMLHttpRequest'
                    },
                    body: JSON.stringify({ 
                        employee_id: employeeId, 
                        password: password,
                        csrf_token: csrfToken
                    })
                });

                const data = await response.json();
                console.log('Login response:', data);

                if (data.success) {
                    currentUser = {
                        employeeId: data.employee.id,
                        name: data.employee.name,
                        site: data.employee.site,
                        jobTitle: data.employee.jobTitle,
                        hpw: data.employee.hpw
                    };
                    console.log('Login successful, currentUser:', currentUser);
                    showTimesheet();
                } else {
                    document.getElementById('errorAlert').textContent = data.error || 'Login failed';
                    document.getElementById('errorAlert').classList.remove('hidden');
                }
            } catch (error) {
                console.error('Login error:', error);
                document.getElementById('errorAlert').textContent = 'Connection error.';
                document.getElementById('errorAlert').classList.remove('hidden');
            }
        }
        
        async function loadSelectedMonth() {
            const selectedValue = document.getElementById('selectedMonth').value;
            if (!selectedValue || !currentUser) {
                alert('Please select a month');
                return;
            }
            
            const parts = selectedValue.split('-');
            const year = parts[0];
            const month = parts[1];
            currentMonth = selectedValue;
            
            console.log('Loading timesheet for:', currentUser.employeeId, 'Year:', year, 'Month:', month);
            
            try {
                const url = API_BASE_URL + '?path=/timesheet/' + encodeURIComponent(currentUser.employeeId) + '/' + encodeURIComponent(year) + '/' + encodeURIComponent(month);
                console.log('Calling URL:', url);
                
                const response = await fetch(url, {
                    headers: {
                        'X-Requested-With': 'XMLHttpRequest'
                    }
                });
                const data = await response.json();
                console.log('Timesheet response:', data);

                if (data.success) {
                    console.log('Timesheet data received:', data.timesheetData);
                    console.log('Original data received:', data.originalTimesheetData);
                    
                    timesheetData = data.timesheetData;
                    originalData = data.originalTimesheetData || JSON.parse(JSON.stringify(data.timesheetData));
                    
                    isLocked = data.is_locked;
                    
                    populateTimesheetTable(timesheetData);
                    createMobileTimesheetCards(timesheetData);
                    updateStatusDisplay(data);
                    calculateHoursSummary();
                    
                    document.getElementById('timesheetTableContainer').classList.remove('hidden');
                    document.getElementById('statusInfo').classList.remove('hidden');
                    document.getElementById('hoursSummary').classList.remove('hidden');
                    
                    resetChangesState();
                    updateButtonStates();
                } else {
                    alert('Failed to load timesheet data: ' + data.error);
                }
            } catch (error) {
                console.error('Timesheet loading error:', error);
                alert('Failed to load timesheet data. Please check your connection.');
            }
        }
        
        function updateStatusDisplay(data) {
            const statusContent = document.getElementById('statusContent');
            let statusHtml = '';
            
            if (data.is_locked) {
                statusHtml = '<div class="status-badge status-submitted">Submitted - Awaiting Manager Approval</div>';
                if (data.submission_status === 'approved') {
                    statusHtml = '<div class="status-badge status-approved">Approved by Manager</div>';
                }
            } else {
                statusHtml = '<div class="status-badge status-draft">Draft - You can edit this timesheet</div>';
                
                if (data.submission_status === 'draft' && data.manager_comments) {
                    statusHtml = '<div class="status-badge status-rejected">Rejected by Manager - Please make corrections</div>';
                    statusHtml += '<div class="changes-summary">Manager Comments: ' + data.manager_comments + '</div>';
                }
                
                if (data.modifications_count && data.modifications_count > 0) {
                    statusHtml += '<br><div class="status-badge status-pending-changes">You have ' + data.modifications_count + ' pending changes</div>';
                }
            }
            
            statusContent.innerHTML = statusHtml;
        }
        
        function calculateHoursSummary() {
            if (!timesheetData || timesheetData.length === 0) {
                return;
            }
            
            let totalWorkedHours = 0;
            let totalAbsenceHours = 0;
            let totalNormalPaidHours = 0;
            let totalEnhancements = 0;
            let totalOvertimeHours = 0;
            
            timesheetData.forEach(row => {
                totalWorkedHours += timeStringToMinutes(row.normalPaidHours || '00:00');
                totalAbsenceHours += timeStringToMinutes(row.absenceHours || '00:00');
                totalNormalPaidHours += timeStringToMinutes(row.normalPaidHoursInput || '00:00');
                totalOvertimeHours += timeStringToMinutes(row.overtimeHours || '00:00');
                
                totalEnhancements += timeStringToMinutes(row.satEnhancement || '00:00');
                totalEnhancements += timeStringToMinutes(row.sunEnhancement || '00:00');
                totalEnhancements += timeStringToMinutes(row.nightsEnhancement || '00:00');
                totalEnhancements += timeStringToMinutes(row.bankHolidayEnhancement || '00:00');
                totalEnhancements += timeStringToMinutes(row.extraHours || '00:00');
                totalEnhancements += timeStringToMinutes(row.weekdayOvertime || '00:00');
                totalEnhancements += timeStringToMinutes(row.satOvertime || '00:00');
                totalEnhancements += timeStringToMinutes(row.sunOvertime || '00:00');
                totalEnhancements += timeStringToMinutes(row.bankHolidayOvertime || '00:00');
            });
            
            const expectedMinutes = totalWorkedHours + totalAbsenceHours;
            const claimedMinutes = totalNormalPaidHours + totalAbsenceHours + totalEnhancements + totalOvertimeHours;
            const varianceMinutes = claimedMinutes - expectedMinutes;
            
            // Update display
            document.getElementById('expectedHours').textContent = minutesToTimeString(expectedMinutes);
            document.getElementById('claimedHours').textContent = minutesToTimeString(claimedMinutes);
            
            const varianceElement = document.getElementById('varianceHours');
            const varianceCard = varianceElement.closest('.hours-card');
            const varianceLabel = document.getElementById('varianceLabel');
            
            if (varianceMinutes === 0) {
                varianceElement.textContent = '00:00';
                varianceCard.classList.remove('over-claimed');
                varianceLabel.textContent = 'Balanced';
            } else if (varianceMinutes > 0) {
                varianceElement.textContent = minutesToTimeString(varianceMinutes);
                varianceCard.classList.add('over-claimed');
                varianceLabel.textContent = 'Over-claimed';
            } else {
                varianceElement.textContent = minutesToTimeString(Math.abs(varianceMinutes));
                varianceCard.classList.remove('over-claimed');
                varianceLabel.textContent = 'Under-claimed';
            }
        }
        
        function populateTimesheetTable(data) {
            console.log('Populating table with data:', data);
            console.log('Comparing against original data:', originalData);
            
            const tbody = document.getElementById('timesheetData');
            tbody.innerHTML = '';
            
            data.forEach((row, index) => {
                const tr = document.createElement('tr');
                const hasAbsence = row.absenceType && row.absenceType !== 'None' && row.absenceType.trim() !== '';
                const canEdit = !isLocked;
                const timeInputClass = hasAbsence ? 'time-input absence-highlight' : 'time-input';
                
                const original = originalData[index] || {};
                
                const startTimeChanged = row.startTime !== (original.startTime || '00:00');
                const stopTimeChanged = row.stopTime !== (original.stopTime || '00:00');
                const normalPaidHoursChanged = (row.normalPaidHoursInput || '00:00') !== (original.normalPaidHoursInput || '00:00');
                const satEnhancementChanged = (row.satEnhancement || '00:00') !== (original.satEnhancement || '00:00');
                const sunEnhancementChanged = (row.sunEnhancement || '00:00') !== (original.sunEnhancement || '00:00');
                const nightsEnhancementChanged = (row.nightsEnhancement || '00:00') !== (original.nightsEnhancement || '00:00');
                const bankHolidayEnhancementChanged = (row.bankHolidayEnhancement || '00:00') !== (original.bankHolidayEnhancement || '00:00');
                const extraHoursChanged = (row.extraHours || '00:00') !== (original.extraHours || '00:00');
                const weekdayOvertimeChanged = (row.weekdayOvertime || '00:00') !== (original.weekdayOvertime || '00:00');
                const satOvertimeChanged = (row.satOvertime || '00:00') !== (original.satOvertime || '00:00');
                const sunOvertimeChanged = (row.sunOvertime || '00:00') !== (original.sunOvertime || '00:00');
                const bankHolidayOvertimeChanged = (row.bankHolidayOvertime || '00:00') !== (original.bankHolidayOvertime || '00:00');
                const commentsChanged = (row.comments || '') !== (original.comments || '');
                
                const hasChanges = startTimeChanged || stopTimeChanged || normalPaidHoursChanged || satEnhancementChanged || 
                                 sunEnhancementChanged || nightsEnhancementChanged || bankHolidayEnhancementChanged ||
                                 extraHoursChanged || weekdayOvertimeChanged || satOvertimeChanged || 
                                 sunOvertimeChanged || bankHolidayOvertimeChanged || commentsChanged;
                
                if (hasChanges) {
                    tr.classList.add('row-has-changes');
                }
                
                tr.innerHTML = `
                    <td class="date-cell ${hasChanges ? 'field-changed' : ''}">${formatDateDisplay(row.date)}</td>
                    <td>
                        <input type="time" class="${timeInputClass} ${startTimeChanged ? 'field-changed' : ''}" 
                               value="${row.startTime}" data-field="startTime" data-index="${index}" 
                               ${canEdit ? '' : 'disabled'} onchange="handleFieldChange(${index}, 'startTime', this.value)">
                    </td>
                    <td>
                        <input type="time" class="${timeInputClass} ${stopTimeChanged ? 'field-changed' : ''}" 
                               value="${row.stopTime}" data-field="stopTime" data-index="${index}" 
                               ${canEdit ? '' : 'disabled'} onchange="handleFieldChange(${index}, 'stopTime', this.value)">
                    </td>
                    <td class="hours-cell readonly ${getHoursColorClass(row.unpaidBreaks)}">${row.unpaidBreaks}</td>
                    <td class="hours-cell locked paid-hours ${getHoursColorClass(row.normalPaidHours || '00:00')}">${row.normalPaidHours || '00:00'}</td>
                    <td class="hours-cell locked overtime-hours ${getHoursColorClass(row.overtimeHours || '00:00')}">${row.overtimeHours || '00:00'}</td>
                    <td class="locked ${hasAbsence ? 'absence-highlight' : ''} absence-text">${row.absenceType || 'None'}</td>
                    <td class="hours-cell locked ${hasAbsence ? 'absence-highlight' : ''} ${getHoursColorClass(row.absenceHours)}">${row.absenceHours}</td>
                    <td class="normal-paid-input-cell">
                        <input type="time" class="time-input ${normalPaidHoursChanged ? 'field-changed' : ''}" value="${row.normalPaidHoursInput || '00:00'}" data-field="normalPaidHoursInput" data-index="${index}" 
                               ${canEdit ? '' : 'disabled'} onchange="handleFieldChange(${index}, 'normalPaidHoursInput', this.value)">
                    </td>
                    <td class="enhancement-cell">
                        <input type="time" class="time-input ${satEnhancementChanged ? 'field-changed' : ''}" value="${row.satEnhancement || '00:00'}" data-field="satEnhancement" data-index="${index}" 
                               ${canEdit ? '' : 'disabled'} onchange="handleFieldChange(${index}, 'satEnhancement', this.value)">
                    </td>
                    <td class="enhancement-cell">
                        <input type="time" class="time-input ${sunEnhancementChanged ? 'field-changed' : ''}" value="${row.sunEnhancement || '00:00'}" data-field="sunEnhancement" data-index="${index}" 
                               ${canEdit ? '' : 'disabled'} onchange="handleFieldChange(${index}, 'sunEnhancement', this.value)">
                    </td>
                    <td class="enhancement-cell">
                        <input type="time" class="time-input ${nightsEnhancementChanged ? 'field-changed' : ''}" value="${row.nightsEnhancement || '00:00'}" data-field="nightsEnhancement" data-index="${index}" 
                               ${canEdit ? '' : 'disabled'} onchange="handleFieldChange(${index}, 'nightsEnhancement', this.value)">
                    </td>
                    <td class="enhancement-cell">
                        <input type="time" class="time-input ${bankHolidayEnhancementChanged ? 'field-changed' : ''}" value="${row.bankHolidayEnhancement || '00:00'}" data-field="bankHolidayEnhancement" data-index="${index}" 
                               ${canEdit ? '' : 'disabled'} onchange="handleFieldChange(${index}, 'bankHolidayEnhancement', this.value)">
                    </td>
                    <td class="extra-hours-cell">
                        <input type="time" class="time-input ${extraHoursChanged ? 'field-changed' : ''}" value="${row.extraHours || '00:00'}" data-field="extraHours" data-index="${index}" 
                               ${canEdit ? '' : 'disabled'} onchange="handleFieldChange(${index}, 'extraHours', this.value)">
                    </td>
                    <td class="overtime-cell">
                        <input type="time" class="time-input ${weekdayOvertimeChanged ? 'field-changed' : ''}" value="${row.weekdayOvertime || '00:00'}" data-field="weekdayOvertime" data-index="${index}" 
                               ${canEdit ? '' : 'disabled'} onchange="handleFieldChange(${index}, 'weekdayOvertime', this.value)">
                    </td>
                    <td class="overtime-cell">
                        <input type="time" class="time-input ${satOvertimeChanged ? 'field-changed' : ''}" value="${row.satOvertime || '00:00'}" data-field="satOvertime" data-index="${index}" 
                               ${canEdit ? '' : 'disabled'} onchange="handleFieldChange(${index}, 'satOvertime', this.value)">
                    </td>
                    <td class="overtime-cell">
                        <input type="time" class="time-input ${sunOvertimeChanged ? 'field-changed' : ''}" value="${row.sunOvertime || '00:00'}" data-field="sunOvertime" data-index="${index}" 
                               ${canEdit ? '' : 'disabled'} onchange="handleFieldChange(${index}, 'sunOvertime', this.value)">
                    </td>
                    <td class="overtime-cell">
                        <input type="time" class="time-input ${bankHolidayOvertimeChanged ? 'field-changed' : ''}" value="${row.bankHolidayOvertime || '00:00'}" data-field="bankHolidayOvertime" data-index="${index}" 
                               ${canEdit ? '' : 'disabled'} onchange="handleFieldChange(${index}, 'bankHolidayOvertime', this.value)">
                    </td>
                    <td>
                        <input type="text" class="comments-input ${commentsChanged ? 'field-changed' : ''}" value="${row.comments || ''}" data-field="comments" data-index="${index}" 
                               ${canEdit ? '' : 'disabled'} placeholder="Add comments..." onchange="handleFieldChange(${index}, 'comments', this.value)">
                    </td>
                `;
                tbody.appendChild(tr);
            });
            
            updateTotals();
        }
        
        function createMobileTimesheetCards(data) {
            const container = document.getElementById('mobileTimesheetCards');
            container.innerHTML = '';
            
            if (!data || data.length === 0) {
                container.innerHTML = '<div style="text-align: center; color: #6c757d; padding: 40px;">No timesheet data available</div>';
                return;
            }
            
            data.forEach((row, index) => {
                const hasAbsence = row.absenceType && row.absenceType !== 'None' && row.absenceType.trim() !== '';
                const canEdit = !isLocked;
                
                const original = originalData[index] || {};
                const startTimeChanged = row.startTime !== (original.startTime || '00:00');
                const stopTimeChanged = row.stopTime !== (original.stopTime || '00:00');
                const hasChanges = startTimeChanged || stopTimeChanged ||
                    (row.normalPaidHoursInput || '00:00') !== (original.normalPaidHoursInput || '00:00') ||
                    (row.satEnhancement || '00:00') !== (original.satEnhancement || '00:00') ||
                    (row.sunEnhancement || '00:00') !== (original.sunEnhancement || '00:00') ||
                    (row.nightsEnhancement || '00:00') !== (original.nightsEnhancement || '00:00') ||
                    (row.bankHolidayEnhancement || '00:00') !== (original.bankHolidayEnhancement || '00:00') ||
                    (row.extraHours || '00:00') !== (original.extraHours || '00:00') ||
                    (row.weekdayOvertime || '00:00') !== (original.weekdayOvertime || '00:00') ||
                    (row.satOvertime || '00:00') !== (original.satOvertime || '00:00') ||
                    (row.sunOvertime || '00:00') !== (original.sunOvertime || '00:00') ||
                    (row.bankHolidayOvertime || '00:00') !== (original.bankHolidayOvertime || '00:00') ||
                    (row.comments || '') !== (original.comments || '');
                
                const card = document.createElement('div');
                card.className = 'mobile-timesheet-card';
                if (hasChanges) card.classList.add('field-changed');
                
                card.innerHTML = `
                    <div class="mobile-card-header">
                        <div class="mobile-card-title">${formatDateDisplay(row.date)}</div>
                        <div>
                            ${hasAbsence ? '<span class="status-badge status-warning">Absence</span>' : ''}
                            ${hasChanges ? '<span class="status-badge status-pending-changes">Changed</span>' : ''}
                        </div>
                    </div>
                    <div class="mobile-card-body">
                        <div class="mobile-card-section">
                            <div class="mobile-section-title">Work Hours</div>
                            <div class="mobile-field-row">
                                <span class="mobile-field-label">Start Time:</span>
                                <input type="time" class="mobile-time-input ${startTimeChanged ? 'field-changed' : ''}" 
                                       value="${row.startTime}" data-field="startTime" data-index="${index}" 
                                       ${canEdit ? '' : 'disabled'} onchange="handleFieldChange(${index}, 'startTime', this.value)">
                            </div>
                            <div class="mobile-field-row">
                                <span class="mobile-field-label">Stop Time:</span>
                                <input type="time" class="mobile-time-input ${stopTimeChanged ? 'field-changed' : ''}" 
                                       value="${row.stopTime}" data-field="stopTime" data-index="${index}" 
                                       ${canEdit ? '' : 'disabled'} onchange="handleFieldChange(${index}, 'stopTime', this.value)">
                            </div>
                            <div class="mobile-field-row">
                                <span class="mobile-field-label">Unpaid Breaks:</span>
                                <span class="mobile-field-value ${getHoursColorClass(row.unpaidBreaks)}">${row.unpaidBreaks}</span>
                            </div>
                            <div class="mobile-field-row">
                                <span class="mobile-field-label">Total Worked:</span>
                                <span class="mobile-field-value ${getHoursColorClass(row.normalPaidHours || '00:00')}">${row.normalPaidHours || '00:00'}</span>
                            </div>
                            <div class="mobile-field-row">
                                <span class="mobile-field-label">Overtime Hours:</span>
                                <span class="mobile-field-value ${getHoursColorClass(row.overtimeHours || '00:00')}">${row.overtimeHours || '00:00'}</span>
                            </div>
                        </div>
                        
                        ${hasAbsence ? `
                        <div class="mobile-card-section">
                            <div class="mobile-section-title">Absence</div>
                            <div class="mobile-field-row">
                                <span class="mobile-field-label">Type:</span>
                                <span class="mobile-field-value">${row.absenceType}</span>
                            </div>
                            <div class="mobile-field-row">
                                <span class="mobile-field-label">Hours:</span>
                                <span class="mobile-field-value">${row.absenceHours}</span>
                            </div>
                        </div>
                        ` : ''}
                        
                        <div class="mobile-card-section">
                            <div class="mobile-section-title">Normal Paid Hours</div>
                            <div class="mobile-field-row">
                                <span class="mobile-field-label">Paid Hours:</span>
                                <input type="time" class="mobile-time-input" value="${row.normalPaidHoursInput || '00:00'}" 
                                       data-field="normalPaidHoursInput" data-index="${index}" 
                                       ${canEdit ? '' : 'disabled'} onchange="handleFieldChange(${index}, 'normalPaidHoursInput', this.value)">
                            </div>
                        </div>
                        
                        <div class="mobile-card-section">
                            <div class="mobile-section-title">Enhancements</div>
                            <div class="mobile-field-row">
                                <span class="mobile-field-label">Saturday:</span>
                                <input type="time" class="mobile-time-input" value="${row.satEnhancement || '00:00'}" 
                                       data-field="satEnhancement" data-index="${index}" 
                                       ${canEdit ? '' : 'disabled'} onchange="handleFieldChange(${index}, 'satEnhancement', this.value)">
                            </div>
                            <div class="mobile-field-row">
                                <span class="mobile-field-label">Sunday:</span>
                                <input type="time" class="mobile-time-input" value="${row.sunEnhancement || '00:00'}" 
                                       data-field="sunEnhancement" data-index="${index}" 
                                       ${canEdit ? '' : 'disabled'} onchange="handleFieldChange(${index}, 'sunEnhancement', this.value)">
                            </div>
                            <div class="mobile-field-row">
                                <span class="mobile-field-label">Nights:</span>
                                <input type="time" class="mobile-time-input" value="${row.nightsEnhancement || '00:00'}" 
                                       data-field="nightsEnhancement" data-index="${index}" 
                                       ${canEdit ? '' : 'disabled'} onchange="handleFieldChange(${index}, 'nightsEnhancement', this.value)">
                            </div>
                            <div class="mobile-field-row">
                                <span class="mobile-field-label">Bank Holiday:</span>
                                <input type="time" class="mobile-time-input" value="${row.bankHolidayEnhancement || '00:00'}" 
                                       data-field="bankHolidayEnhancement" data-index="${index}" 
                                       ${canEdit ? '' : 'disabled'} onchange="handleFieldChange(${index}, 'bankHolidayEnhancement', this.value)">
                            </div>
                        </div>
                        
                        <div class="mobile-card-section">
                            <div class="mobile-section-title">Overtime & Extra Hours</div>
                            <div class="mobile-field-row">
                                <span class="mobile-field-label">Extra Hours:</span>
                                <input type="time" class="mobile-time-input" value="${row.extraHours || '00:00'}" 
                                       data-field="extraHours" data-index="${index}" 
                                       ${canEdit ? '' : 'disabled'} onchange="handleFieldChange(${index}, 'extraHours', this.value)">
                            </div>
                            <div class="mobile-field-row">
                                <span class="mobile-field-label">Weekday OT:</span>
                                <input type="time" class="mobile-time-input" value="${row.weekdayOvertime || '00:00'}" 
                                       data-field="weekdayOvertime" data-index="${index}" 
                                       ${canEdit ? '' : 'disabled'} onchange="handleFieldChange(${index}, 'weekdayOvertime', this.value)">
                            </div>
                            <div class="mobile-field-row">
                                <span class="mobile-field-label">Saturday OT:</span>
                                <input type="time" class="mobile-time-input" value="${row.satOvertime || '00:00'}" 
                                       data-field="satOvertime" data-index="${index}" 
                                       ${canEdit ? '' : 'disabled'} onchange="handleFieldChange(${index}, 'satOvertime', this.value)">
                            </div>
                            <div class="mobile-field-row">
                                <span class="mobile-field-label">Sunday OT:</span>
                                <input type="time" class="mobile-time-input" value="${row.sunOvertime || '00:00'}" 
                                       data-field="sunOvertime" data-index="${index}" 
                                       ${canEdit ? '' : 'disabled'} onchange="handleFieldChange(${index}, 'sunOvertime', this.value)">
                            </div>
                            <div class="mobile-field-row">
                                <span class="mobile-field-label">Bank Holiday OT:</span>
                                <input type="time" class="mobile-time-input" value="${row.bankHolidayOvertime || '00:00'}" 
                                       data-field="bankHolidayOvertime" data-index="${index}" 
                                       ${canEdit ? '' : 'disabled'} onchange="handleFieldChange(${index}, 'bankHolidayOvertime', this.value)">
                            </div>
                        </div>
                        
                        <div class="mobile-card-section">
                            <div class="mobile-section-title">Comments</div>
                            <textarea class="mobile-comments-input" data-field="comments" data-index="${index}" 
                                      ${canEdit ? '' : 'disabled'} onchange="handleFieldChange(${index}, 'comments', this.value)"
                                      placeholder="Add comments...">${row.comments || ''}</textarea>
                        </div>
                    </div>
                `;
                container.appendChild(card);
            });
            
            // Show mobile totals on mobile
            updateMobileTotals();
        }
        
        function updateMobileTotals() {
            if (!timesheetData || timesheetData.length === 0) return;
            
            let totalUnpaidBreaks = 0;
            let totalWorkedHours = 0;
            let totalOvertimeHours = 0;
            let totalAbsenceHours = 0;
            let totalNormalPaidHours = 0;
            let totalSatEnhancement = 0;
            let totalSunEnhancement = 0;
            let totalNightsEnhancement = 0;
            let totalBankHolEnhancement = 0;
            let totalExtraHours = 0;
            let totalWeekdayOT = 0;
            let totalSatOT = 0;
            let totalSunOT = 0;
            let totalBankHolOT = 0;
            
            timesheetData.forEach(row => {
                totalUnpaidBreaks += timeStringToMinutes(row.unpaidBreaks);
                totalWorkedHours += timeStringToMinutes(row.normalPaidHours || '00:00');
                totalOvertimeHours += timeStringToMinutes(row.overtimeHours || '00:00');
                totalAbsenceHours += timeStringToMinutes(row.absenceHours);
                totalNormalPaidHours += timeStringToMinutes(row.normalPaidHoursInput || '00:00');
                totalSatEnhancement += timeStringToMinutes(row.satEnhancement);
                totalSunEnhancement += timeStringToMinutes(row.sunEnhancement);
                totalNightsEnhancement += timeStringToMinutes(row.nightsEnhancement);
                totalBankHolEnhancement += timeStringToMinutes(row.bankHolidayEnhancement);
                totalExtraHours += timeStringToMinutes(row.extraHours || '00:00');
                totalWeekdayOT += timeStringToMinutes(row.weekdayOvertime);
                totalSatOT += timeStringToMinutes(row.satOvertime);
                totalSunOT += timeStringToMinutes(row.sunOvertime);
                totalBankHolOT += timeStringToMinutes(row.bankHolidayOvertime);
            });
            
            const grid = document.getElementById('mobileTotalsGrid');
            grid.innerHTML = `
                <div class="mobile-total-item">
                    <span class="mobile-total-label">Unpaid Breaks:</span>
                    <span class="mobile-total-value">${minutesToTimeString(totalUnpaidBreaks)}</span>
                </div>
                <div class="mobile-total-item">
                    <span class="mobile-total-label">Total Worked:</span>
                    <span class="mobile-total-value">${minutesToTimeString(totalWorkedHours)}</span>
                </div>
                <div class="mobile-total-item">
                    <span class="mobile-total-label">Overtime Hours:</span>
                    <span class="mobile-total-value">${minutesToTimeString(totalOvertimeHours)}</span>
                </div>
                <div class="mobile-total-item">
                    <span class="mobile-total-label">Absence Hours:</span>
                    <span class="mobile-total-value">${minutesToTimeString(totalAbsenceHours)}</span>
                </div>
                <div class="mobile-total-item">
                    <span class="mobile-total-label">Normal Paid:</span>
                    <span class="mobile-total-value">${minutesToTimeString(totalNormalPaidHours)}</span>
                </div>
                <div class="mobile-total-item">
                    <span class="mobile-total-label">Sat Enhancement:</span>
                    <span class="mobile-total-value">${minutesToTimeString(totalSatEnhancement)}</span>
                </div>
                <div class="mobile-total-item">
                    <span class="mobile-total-label">Sun Enhancement:</span>
                    <span class="mobile-total-value">${minutesToTimeString(totalSunEnhancement)}</span>
                </div>
                <div class="mobile-total-item">
                    <span class="mobile-total-label">Nights Enhancement:</span>
                    <span class="mobile-total-value">${minutesToTimeString(totalNightsEnhancement)}</span>
                </div>
                <div class="mobile-total-item">
                    <span class="mobile-total-label">Bank Hol Enhancement:</span>
                    <span class="mobile-total-value">${minutesToTimeString(totalBankHolEnhancement)}</span>
                </div>
                <div class="mobile-total-item">
                    <span class="mobile-total-label">Extra Hours:</span>
                    <span class="mobile-total-value">${minutesToTimeString(totalExtraHours)}</span>
                </div>
                <div class="mobile-total-item">
                    <span class="mobile-total-label">Weekday OT:</span>
                    <span class="mobile-total-value">${minutesToTimeString(totalWeekdayOT)}</span>
                </div>
                <div class="mobile-total-item">
                    <span class="mobile-total-label">Saturday OT:</span>
                    <span class="mobile-total-value">${minutesToTimeString(totalSatOT)}</span>
                </div>
                <div class="mobile-total-item">
                    <span class="mobile-total-label">Sunday OT:</span>
                    <span class="mobile-total-value">${minutesToTimeString(totalSunOT)}</span>
                </div>
                <div class="mobile-total-item">
                    <span class="mobile-total-label">Bank Hol OT:</span>
                    <span class="mobile-total-value">${minutesToTimeString(totalBankHolOT)}</span>
                </div>
            `;
        }
        
        function handleFieldChange(index, field, value) {
            if (isLocked) return;
            
            timesheetData[index][field] = value;
            markFieldChanged(index, field);
            
            hasUnsavedChanges = true;
            updateButtonStates();
            calculateHoursSummary(); // Update hours summary in real-time
            
            if (field === 'startTime' || field === 'stopTime') {
                const commentsInput = document.querySelector(`[data-index="${index}"][data-field="comments"]`);
                const currentComment = timesheetData[index]['comments'] || '';
                
                if (!currentComment.trim()) {
                    commentsInput.classList.add('required-comment');
                    commentsInput.placeholder = 'Comment required for time changes';
                    
                    let requirementMsg = commentsInput.parentElement.querySelector('.comment-requirement');
                    if (!requirementMsg) {
                        requirementMsg = document.createElement('div');
                        requirementMsg.className = 'comment-requirement';
                        requirementMsg.textContent = 'Comment required';
                        commentsInput.parentElement.appendChild(requirementMsg);
                    }
                    requirementMsg.classList.add('show');
                } else {
                    commentsInput.classList.remove('required-comment');
                    const requirementMsg = commentsInput.parentElement.querySelector('.comment-requirement');
                    if (requirementMsg) requirementMsg.classList.remove('show');
                }
            }
            
            if (field !== 'comments') {
                updateTotals();
                updateMobileTotals();
            }
        }
        
        function markFieldChanged(index, field) {
            const input = document.querySelector(`[data-index="${index}"][data-field="${field}"]`);
            if (input) {
                input.classList.add('changed');
            }
        }
        
        function getHoursColorClass(timeValue) {
            if (!timeValue || timeValue === '00:00' || timeValue === '00:00:00') {
                return 'hours-zero';
            }
            return 'hours-positive';
        }
        
        function updateTotals() {
            if (!timesheetData || timesheetData.length === 0) return;
            
            let totalUnpaidBreaks = 0;
            let totalWorkedHours = 0;
            let totalOvertimeHours = 0;
            let totalAbsenceHours = 0;
            let totalNormalPaidHours = 0;
            let totalSatEnhancement = 0;
            let totalSunEnhancement = 0;
            let totalNightsEnhancement = 0;
            let totalBankHolEnhancement = 0;
            let totalExtraHours = 0;
            let totalWeekdayOT = 0;
            let totalSatOT = 0;
            let totalSunOT = 0;
            let totalBankHolOT = 0;
            
            timesheetData.forEach(row => {
                totalUnpaidBreaks += timeStringToMinutes(row.unpaidBreaks);
                totalWorkedHours += timeStringToMinutes(row.normalPaidHours || '00:00');
                totalOvertimeHours += timeStringToMinutes(row.overtimeHours || '00:00');
                totalAbsenceHours += timeStringToMinutes(row.absenceHours);
                totalNormalPaidHours += timeStringToMinutes(row.normalPaidHoursInput || '00:00');
                totalSatEnhancement += timeStringToMinutes(row.satEnhancement);
                totalSunEnhancement += timeStringToMinutes(row.sunEnhancement);
                totalNightsEnhancement += timeStringToMinutes(row.nightsEnhancement);
                totalBankHolEnhancement += timeStringToMinutes(row.bankHolidayEnhancement);
                totalExtraHours += timeStringToMinutes(row.extraHours || '00:00');
                totalWeekdayOT += timeStringToMinutes(row.weekdayOvertime);
                totalSatOT += timeStringToMinutes(row.satOvertime);
                totalSunOT += timeStringToMinutes(row.sunOvertime);
                totalBankHolOT += timeStringToMinutes(row.bankHolidayOvertime);
            });
            
            updateTotalCell('totalUnpaidBreaks', totalUnpaidBreaks);
            updateTotalCell('totalWorkedHours', totalWorkedHours);
            updateTotalCell('totalOvertimeHours', totalOvertimeHours);
            updateTotalCell('totalAbsenceHours', totalAbsenceHours);
            updateTotalCell('totalNormalPaidHours', totalNormalPaidHours);
            updateTotalCell('totalSatEnhancement', totalSatEnhancement);
            updateTotalCell('totalSunEnhancement', totalSunEnhancement);
            updateTotalCell('totalNightsEnhancement', totalNightsEnhancement);
            updateTotalCell('totalBankHolEnhancement', totalBankHolEnhancement);
            updateTotalCell('totalExtraHours', totalExtraHours);
            updateTotalCell('totalWeekdayOT', totalWeekdayOT);
            updateTotalCell('totalSatOT', totalSatOT);
            updateTotalCell('totalSunOT', totalSunOT);
            updateTotalCell('totalBankHolOT', totalBankHolOT);
        }
        
        function updateTotalCell(cellId, totalMinutes) {
            const timeString = minutesToTimeString(totalMinutes);
            const cell = document.getElementById(cellId);
            if (cell) {
                cell.textContent = timeString;
                cell.classList.remove('hours-zero', 'hours-positive');
                cell.classList.add(getHoursColorClass(timeString));
            }
        }
        
        function updateButtonStates() {
            const saveButton = document.getElementById('saveButton');
            const submitButton = document.getElementById('submitButton');
            
            if (isLocked) {
                saveButton.disabled = true;
                submitButton.disabled = true;
                saveButton.textContent = 'Locked';
                submitButton.textContent = 'Already Submitted';
            } else {
                saveButton.disabled = !hasUnsavedChanges;
                submitButton.disabled = hasUnsavedChanges;
                
                saveButton.textContent = hasUnsavedChanges ? 'Save Draft' : 'No Changes';
                submitButton.textContent = hasUnsavedChanges ? 'Save Changes First' : 'Submit for Manager Approval';
            }
        }
        
        async function saveDraft() {
            if (!hasUnsavedChanges || isLocked) return;
            
            let missingComments = [];
            timesheetData.forEach((row, index) => {
                const original = originalData[index];
                if (original && (row.startTime !== original.startTime || row.stopTime !== original.stopTime)) {
                    if (!row.comments || !row.comments.trim()) {
                        missingComments.push(`${formatDateDisplay(row.date)}`);
                    }
                }
            });
            
            if (missingComments.length > 0) {
                alert(`Comments are required for time changes on the following dates:\n${missingComments.join(', ')}`);
                return;
            }
            
            try {
                const response = await fetch(API_BASE_URL + '?path=/save-draft', {
                    method: 'POST',
                    headers: { 
                        'Content-Type': 'application/json',
                        'X-Requested-With': 'XMLHttpRequest'
                    },
                    body: JSON.stringify({
                        employee_id: currentUser.employeeId,
                        year_month: currentMonth,
                        timesheet_data: timesheetData,
                        csrf_token: csrfToken
                    })
                });
                
                const data = await response.json();
                
                if (data.success) {
                    showSaveIndicator('Draft saved successfully!');
                    hasUnsavedChanges = false;
                    updateButtonStates();
                    document.querySelectorAll('.changed').forEach(el => el.classList.remove('changed'));
                } else {
                    alert('Failed to save draft: ' + data.error);
                }
            } catch (error) {
                console.error('Save error:', error);
                alert('Failed to save draft. Please try again.');
            }
        }
        
        async function submitTimesheet() {
            if (hasUnsavedChanges) {
                alert('Please save your changes before submitting.');
                return;
            }
            
            const employeeComments = prompt('Optional: Add any comments about this timesheet submission:') || '';
            
            const confirmSubmit = confirm('Submit this timesheet for manager approval? Once submitted, you cannot make further changes until your manager reviews it.');
            if (!confirmSubmit) return;
            
            try {
                const response = await fetch(API_BASE_URL + '?path=/submit-timesheet', {
                    method: 'POST',
                    headers: { 
                        'Content-Type': 'application/json',
                        'X-Requested-With': 'XMLHttpRequest'
                    },
                    body: JSON.stringify({
                        employee_id: currentUser.employeeId,
                        year_month: currentMonth,
                        timesheet_data: timesheetData,
                        employee_comments: employeeComments,
                        csrf_token: csrfToken
                    })
                });
                
                const data = await response.json();
                
                if (data.success) {
                    showSaveIndicator('Timesheet submitted successfully!');
                    isLocked = true;
                    updateButtonStates();
                    updateStatusDisplay({
                        is_locked: true,
                        submission_status: 'submitted'
                    });
                    
                    document.querySelectorAll('input').forEach(input => {
                        if (input.type !== 'button' && input.type !== 'submit') {
                            input.disabled = true;
                        }
                    });
                } else {
                    alert('Failed to submit timesheet: ' + data.error);
                }
            } catch (error) {
                console.error('Submit error:', error);
                alert('Failed to submit timesheet. Please try again.');
            }
        }
        
        function timeStringToMinutes(timeStr) {
            if (!timeStr || timeStr === '00:00' || timeStr === '00:00:00') return 0;
            const parts = timeStr.split(':');
            return parseInt(parts[0]) * 60 + parseInt(parts[1]);
        }
        
        function minutesToTimeString(minutes) {
            if (!minutes || minutes === 0) return '00:00';
            const hours = Math.floor(minutes / 60);
            const mins = Math.round(minutes % 60);
            return `${hours.toString().padStart(2, '0')}:${mins.toString().padStart(2, '0')}`;
        }
        
        function showSaveIndicator(message) {
            const indicator = document.getElementById('saveIndicator');
            indicator.textContent = message;
            indicator.style.display = 'block';
            setTimeout(() => {
                indicator.style.display = 'none';
            }, 3000);
        }
        
        function resetChangesState() {
            hasUnsavedChanges = false;
            document.querySelectorAll('.changed').forEach(el => el.classList.remove('changed'));
        }
        
        function formatDateDisplay(dateStr) {
            const parts = dateStr.split('/');
            const date = new Date(parts[2], parts[1] - 1, parts[0]);
            
            const days = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
            const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
            
            const dayName = days[date.getDay()];
            const day = date.getDate();
            const month = months[date.getMonth()];
            
            return `${dayName} ${day} ${month}`;
        }
        
        function logout() {
            currentUser = null;
            currentMonth = null;
            isLocked = false;
            hasUnsavedChanges = false;
            document.getElementById('employeeId').value = '';
            document.getElementById('password').value = '';
            document.getElementById('timesheetTableContainer').classList.add('hidden');
            document.getElementById('statusInfo').classList.add('hidden');
            document.getElementById('hoursSummary').classList.add('hidden');
            showLogin();
        }
		
		function showResetPassword() {
			const employeeId = prompt('Enter your Employee ID to receive a password reset email:');
			if (!employeeId) return;
    
			requestPasswordReset(employeeId.trim());
		}

		async function requestPasswordReset(employeeId) {
			try {
				const response = await fetch(API_BASE_URL + '?path=/request-password-reset', {
					method: 'POST',
					headers: { 
						'Content-Type': 'application/json',
						'X-Requested-With': 'XMLHttpRequest'
					},
					body: JSON.stringify({
						employee_id: employeeId,
						csrf_token: csrfToken
					})
				});
        
				const data = await response.json();
        
				if (data.success) {
					alert('Password reset instructions have been sent to your registered email address. Please check your email and follow the link to reset your password.');
				} else {
					alert('Error: ' + data.error);
				}
			} catch (error) {
				console.error('Password reset request error:', error);
				alert('Connection error. Please try again.');
			}
		}
    </script>
</body>
</html>