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

// API handling for password reset
if (isset($_GET['path'])) {
    header('Content-Type: application/json');
    
    $path = sanitizeInput($_GET['path']);
    $method = $_SERVER['REQUEST_METHOD'];
    
    try {
        switch ($path) {
            case '/request-password-reset':
                if ($method === 'POST') {
                    $input = json_decode(file_get_contents('php://input'), true);
                    
                    if (!$input || !isset($input['username'])) {
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
if (isset($_SESSION['user_id'])) {
    $_SESSION['last_activity'] = time();
}

$csrfToken = generateCSRFToken();
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NHS Manager Timesheet Portal</title>
<style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: 'Segoe UI', Tahoma, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height:100vh; padding:20px;}
    .container { max-width: 1800px; margin: 0 auto; background: white; border-radius: 15px; box-shadow: 0 20px 40px rgba(0,0,0,0.1); overflow: hidden;}
    .header { background: linear-gradient(135deg, #2c3e50 0%, #3498db 100%); color: white; padding: 25px 30px; text-align: center; position: relative;}
    .header h1 { margin:0; font-size: 28px; }
    
    /* Login Modal */
    .login-modal {position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.5);display:flex;align-items:center;justify-content:center;z-index:1000;}
    .login-form {background:white;padding:40px;border-radius:15px;max-width:400px;width:90%;box-shadow:0 20px 40px rgba(0,0,0,0.3);}
    .login-form h2 {margin-bottom:20px;text-align:center; color: #2c3e50;}
    .login-form input {width:100%;padding:12px;border:2px solid #e9ecef;border-radius:8px;font-size:1rem;margin-bottom:15px;}
    .login-form button {width:100%;padding:14px;background:linear-gradient(135deg,#007bff,#0056b3);color:white;border:none;border-radius:8px;font-size:1rem;cursor:pointer;}
    .error {color:#dc3545;margin-bottom:10px;text-align:center;padding:10px;background:#f8d7da;border-radius:5px;}
    .reset-password-link {text-align:center;margin-top:15px;}
    .reset-password-link a {color:#005eb8;text-decoration:none;font-size:14px;}
    
    /* Filter Section */
    .filter-section { 
        background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%); 
        padding: 20px 30px; 
        border-bottom: 1px solid #dee2e6;
    }
    .filter-container {
        display: flex;
        gap: 20px;
        align-items: center;
        flex-wrap: wrap;
    }
    .filter-group {
        display: flex;
        flex-direction: column;
        min-width: 200px;
    }
    .filter-group label {
        font-weight: 600;
        color: #2c3e50;
        margin-bottom: 5px;
        font-size: 14px;
    }
    .filter-group select {
        padding: 8px 12px;
        border: 2px solid #dee2e6;
        border-radius: 6px;
        background: white;
        font-size: 14px;
        color: #495057;
        cursor: pointer;
    }
    .filter-group select:focus {
        outline: none;
        border-color: #007bff;
        box-shadow: 0 0 0 0.2rem rgba(0,123,255,.25);
    }
    .filter-actions {
        display: flex;
        gap: 10px;
        align-items: end;
    }
    .btn-filter { 
        background: #28a745; 
        color: white; 
        padding: 8px 16px; 
        border: none; 
        border-radius: 6px; 
        cursor: pointer; 
        font-weight: 600;
    }
    .btn-filter:hover { background: #218838; }
    .btn-clear { 
        background: #6c757d; 
        color: white; 
        padding: 8px 16px; 
        border: none; 
        border-radius: 6px; 
        cursor: pointer; 
        font-weight: 600;
    }
    .btn-clear:hover { background: #545b62; }
    
    /* Tables - Desktop */
    .main-table { width:100%; border-collapse: collapse; margin-top:20px; font-size: 14px; }
    .main-table th, .main-table td { border:1px solid #e9ecef; padding:12px; text-align:center; }
    .main-table th { background:#343a40; color:white; font-weight: 600; }
    .main-table tr:hover { background:#f8f9fa; }
    
    /* Detail Table - Desktop */
    .detail-table { 
        width: 100%; 
        border-collapse: collapse; 
        font-size: 11px; 
        margin: 20px 0; 
        table-layout: fixed;
    }
    .detail-table th { 
        background: #f8f9fa; 
        padding: 8px 4px; 
        text-align: center; 
        border: 1px solid #dee2e6; 
        font-weight: 600; 
        font-size: 9px; 
        color: #495057; 
        vertical-align: middle;
        white-space: nowrap;
    }
    .detail-table td { 
        padding: 6px 4px; 
        text-align: center; 
        border: 1px solid #dee2e6; 
        vertical-align: middle; 
    }
    .date-cell { 
        background: #e9ecef; 
        font-weight: 600; 
        text-align: left; 
        padding-left: 8px; 
        width: 100px;
        font-size: 10px;
    }
    
    /* Mobile Card Layout */
    .timesheet-card {
        display: none;
        background: white;
        border-radius: 12px;
        margin: 15px 0;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        overflow: hidden;
    }
    .card-header {
        background: #f8f9fa;
        padding: 15px 20px;
        border-bottom: 1px solid #dee2e6;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }
    .card-title {
        font-weight: 600;
        color: #2c3e50;
        font-size: 16px;
    }
    .card-body {
        padding: 20px;
    }
    .card-section {
        margin-bottom: 20px;
    }
    .card-section:last-child {
        margin-bottom: 0;
    }
    .section-title {
        font-weight: 600;
        color: #495057;
        margin-bottom: 10px;
        font-size: 14px;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    .field-row {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 8px 0;
        border-bottom: 1px solid #f1f3f4;
    }
    .field-row:last-child {
        border-bottom: none;
    }
    .field-label {
        font-weight: 500;
        color: #6c757d;
        font-size: 14px;
    }
    .field-value {
        font-weight: 600;
        color: #2c3e50;
        font-size: 14px;
    }
    .mobile-input {
        width: 100px;
        padding: 6px 8px;
        border: 1px solid #dee2e6;
        border-radius: 4px;
        font-size: 14px;
        text-align: center;
    }
    .mobile-textarea {
        width: 100%;
        min-height: 60px;
        padding: 8px 12px;
        border: 1px solid #dee2e6;
        border-radius: 4px;
        font-size: 14px;
        resize: vertical;
        margin-top: 8px;
    }
    
    /* Status and other elements */
    .highlight-diff { background: #ffe6e6 !important; font-weight: bold; border: 2px solid #dc3545 !important; }
    .manager-changed { background: #e7f3ff !important; border: 2px solid #007bff !important; }
    .hours-cell { font-weight: 600; }
    .hours-zero { color: #6c757d; }
    .hours-enhanced { color: #dc3545 !important; font-weight: bold !important; }
    .employee-modified { color: #dc3545 !important; font-weight: bold !important; background: #fff5f5 !important; }
    .enhancement-cell { background: #e7f3ff; font-weight: 500; }
    .overtime-cell { background: #fff3cd; font-weight: 500; }
    .extra-hours-cell { background: #d1f2eb; font-weight: 500; }
    .paid-hours { background: #d1f2eb !important; color: #0f5132; }
    .overtime-hours { background: #fff3cd !important; color: #856404; }
    .absence-highlight { background: #fff3cd !important; border-color: #ffc107 !important; }
    .totals-row { background: #f8f9fa !important; border-top: 2px solid #005eb8 !important; font-weight: 600; }
    .totals-row td { font-weight: 600 !important; }
    
    /* Employee Info Display */
    .employee-info {
        background: linear-gradient(135deg, #e8f5e8 0%, #c8e6c8 100%);
        padding: 15px 20px;
        margin: 15px 0;
        border-radius: 8px;
        border-left: 4px solid #28a745;
    }
    .employee-info h3 {
        margin: 0 0 8px 0;
        color: #155724;
        font-size: 16px;
    }
    .employee-info p {
        margin: 4px 0;
        color: #424242;
        font-weight: 500;
    }
    
    /* Hours Summary Display */
    .hours-summary {
        background: linear-gradient(135deg, #fff3e0 0%, #ffe0b2 100%);
        padding: 15px 20px;
        margin: 15px 0;
        border-radius: 8px;
        border-left: 4px solid #ff9800;
    }
    .hours-summary h3 {
        margin: 0 0 12px 0;
        color: #e65100;
        font-size: 16px;
    }
    .summary-grid {
        display: grid;
        grid-template-columns: 1fr 1fr 1fr;
        gap: 20px;
    }
    .summary-item {
        text-align: center;
        padding: 12px;
        border-radius: 6px;
        background: white;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    .summary-item label {
        display: block;
        font-weight: 600;
        margin-bottom: 4px;
        font-size: 12px;
    }
    .summary-item span {
        display: block;
        font-size: 18px;
        font-weight: bold;
        margin-bottom: 4px;
    }
    .summary-item small {
        font-size: 10px;
        color: #666;
    }
    .expected { border-top: 3px solid #4caf50; }
    .expected span { color: #4caf50; }
    .claimed { border-top: 3px solid #2196f3; }
    .claimed span { color: #2196f3; }
    .variance { border-top: 3px solid #ff5722; }
    .variance span { color: #ff5722; }
    
    /* Editable Fields */
    .editable-time {
        width: 80px;
        padding: 8px;
        border: 1px solid #dee2e6;
        border-radius: 4px;
        font-size: 12px;
        text-align: center;
        font-weight: 500;
        background: white;
    }
    .editable-time:focus {
        outline: none;
        border: 2px solid #007bff;
        background: #f8f9fa;
    }
    .editable-time.changed {
        background: #e7f3ff !important;
        border: 2px solid #007bff !important;
        font-weight: bold;
    }
    .editable-time.employee-value {
        color: #dc3545 !important;
        font-weight: bold !important;
        background: #fff5f5;
        border-color: #dc3545;
    }
    .editable-time.employee-value:focus {
        background: #fff0f0;
        border-color: #dc3545;
    }
    .editable-time.manager-changed {
        background: #e7f3ff !important;
        border-color: #007bff;
        color: #0056b3;
        font-weight: bold;
    }
    .editable-time.manager-changed:focus {
        background: #d1ecf1;
        border-color: #007bff;
    }
    
    /* Special styling for time inputs vs text inputs */
    .editable-time[type="time"] {
        width: 90px;
        font-size: 10px;
    }
    .editable-time[type="text"] {
        width: 65px;
        font-size: 11px;
    }
    
    .editable-select {
        width: 90px;
        padding: 3px 2px;
        border: 1px solid #ccc;
        border-radius: 3px;
        font-size: 9px;
        background: white;
    }
    .editable-select:focus {
        outline: none;
        border: 2px solid #007bff;
    }
    .editable-select.employee-value {
        color: #dc3545 !important;
        font-weight: bold !important;
        background: #fff5f5;
        border-color: #dc3545;
    }
    
    /* Value highlighting for read-only cells */
    .employee-hours {
        color: #dc3545 !important;
        font-weight: bold !important;
        background: #fff5f5 !important;
    }
    
    .editable-textarea {
        width: 130px;
        height: 40px;
        padding: 6px 8px;
        border: 1px solid #dee2e6;
        border-radius: 4px;
        font-size: 10px;
        resize: vertical;
        background: white;
        font-family: inherit;
    }
    .editable-textarea:focus {
        outline: none;
        border: 2px solid #007bff;
    }
    .editable-textarea.employee-value {
        color: #dc3545 !important;
        font-weight: bold !important;
        background: #fff5f5;
        border-color: #dc3545;
    }
    .editable-textarea.employee-value:focus {
        background: #fff0f0;
        border-color: #dc3545;
    }
    
    /* Buttons */
    button { padding:8px 16px; border:none; border-radius:6px; cursor:pointer; font-weight: 600; margin: 0 5px; transition: all 0.3s; }
    .btn-primary { background:#28a745; color:white; }
    .btn-primary:hover { background:#218838; transform: translateY(-1px); }
    .btn-success { background:#17a2b8; color:white; }
    .btn-success:hover { background:#138496; transform: translateY(-1px); }
    .btn-danger { background:#dc3545; color:white; }
    .btn-danger:hover { background:#c82333; transform: translateY(-1px); }
    .btn-back { background:#6c757d; color:white; }
    .btn-back:hover { background:#545b62; }
    .btn-view { background:#007bff; color:white; font-size: 12px; padding: 6px 12px; }
    .btn-view:hover { background:#0056b3; }
    
    /* Layout */
    .content-section { padding: 20px 30px; }
    .detail-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 2px solid #dee2e6; }
    .detail-title { font-size: 24px; font-weight: 600; color: #2c3e50; }
    .action-buttons { margin-top: 20px; text-align: center; padding-top: 20px; border-top: 2px solid #dee2e6; }
    
    /* Status badges */
    .status-badge { padding: 4px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; text-transform: uppercase; }
    .status-submitted { background: #fff3cd; color: #856404; }
    .status-approved { background: #d1f2eb; color: #0f5132; }
    .status-rejected { background: #f8d7da; color: #721c24; }
    
    /* Department/Team badges */
    .dept-badge { 
        background: linear-gradient(135deg, #e3f2fd, #bbdefb); 
        color: #1565c0; 
        padding: 3px 8px; 
        border-radius: 12px; 
        font-size: 10px; 
        font-weight: 600; 
        margin-right: 5px;
    }
    .team-badge { 
        background: linear-gradient(135deg, #f3e5f5, #e1bee7); 
        color: #7b1fa2; 
        padding: 3px 8px; 
        border-radius: 12px; 
        font-size: 10px; 
        font-weight: 600; 
    }
    
    /* Save indicator */
    .save-indicator {
        position: fixed;
        top: 20px;
        right: 20px;
        background: #28a745;
        color: white;
        padding: 10px 20px;
        border-radius: 8px;
        font-weight: 600;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        display: none;
        z-index: 1000;
    }
    .save-indicator.show { display: block; }
    
    /* Responsive */
    .table-container { overflow-x: auto; margin: 0 -30px; padding: 0 30px; }
    
    .hidden { display: none !important; }
    
    /* Mobile Responsive Styles */
    @media (max-width: 768px) {
        body { padding: 10px; }
        
        .header { 
            padding: 15px 20px; 
            flex-direction: column;
            gap: 10px;
        }
        .header h1 { font-size: 20px; }
        
        #logout-btn {
            position: static !important;
            top: auto !important;
            right: auto !important;
            margin: 10px 0 0 0;
        }
        
        .content-section { padding: 15px 20px; }
        
        .filter-container {
            flex-direction: column;
            gap: 15px;
        }
        
        .filter-group {
            min-width: 100%;
        }
        
        .filter-actions {
            width: 100%;
            justify-content: center;
        }
        
        .detail-header {
            flex-direction: column;
            gap: 15px;
            text-align: center;
        }
        
        .detail-title { font-size: 18px; }
        
        .summary-grid {
            grid-template-columns: 1fr;
            gap: 15px;
        }
        
        /* Hide desktop tables on mobile */
        .main-table, .detail-table { display: none; }
        
        /* Show mobile cards */
        .timesheet-card { display: block; }
        
        /* Stack action buttons */
        .action-buttons {
            display: flex;
            flex-direction: column;
            gap: 10px;
        }
        
        .action-buttons button {
            width: 100%;
            margin: 0;
            padding: 12px;
        }
        
        /* Responsive inputs */
        .mobile-input {
            width: 80px;
            font-size: 16px; /* Prevent zoom on iOS */
        }
        
        .mobile-textarea {
            font-size: 16px; /* Prevent zoom on iOS */
        }
        
        /* Touch-friendly buttons */
        .btn-view {
            padding: 8px 12px;
            font-size: 12px;
            min-height: 36px;
        }
        
        .login-form {
            padding: 30px 20px;
        }
        
        .login-form input {
            font-size: 16px; /* Prevent zoom on iOS */
            padding: 15px;
        }
        
        .login-form button {
            padding: 16px;
            font-size: 16px;
        }
    }
    
    @media (max-width: 480px) {
        body { padding: 5px; }
        
        .container {
            border-radius: 10px;
        }
        
        .header {
            padding: 10px 15px;
        }
        
        .content-section {
            padding: 10px 15px;
        }
        
        .filter-section {
            padding: 15px 20px;
        }
        
        .card-header,
        .card-body {
            padding: 15px;
        }
        
        .field-row {
            flex-direction: column;
            align-items: flex-start;
            gap: 5px;
        }
        
        .mobile-input {
            width: 100%;
            max-width: 150px;
        }
        
        .summary-item {
            padding: 15px;
        }
        
        .summary-item span {
            font-size: 24px;
        }
    }
</style>
</head>
<body>
<!-- Save Indicator -->
<div id="save-indicator" class="save-indicator">Changes saved successfully!</div>

<!-- Login Modal -->
<div id="login-modal" class="login-modal">
    <div class="login-form">
        <h2>NHS Manager Login</h2>
        <div id="login-error" class="error" style="display:none;"></div>
        <input type="text" id="username" placeholder="Username" required>
        <input type="password" id="password" placeholder="Password" required>
        <button onclick="loginUser()">Sign In</button>
        <div class="reset-password-link">
            <a href="#" onclick="showResetPassword()">Reset Password</a>
        </div>
    </div>
</div>

<!-- Main Container -->
<div class="container" id="main-container" style="display:none;">
    <div class="header">
        <h1>NHS Manager Timesheet Approvals</h1>
        <button id="logout-btn" class="btn-back" onclick="logout()" style="display: none;">Logout</button>
    </div>

    <!-- Filter Section -->
    <div id="filterSection" class="filter-section" style="display:none;">
        <div class="filter-container">
            <div class="filter-group">
                <label for="departmentFilter">Department:</label>
                <select id="departmentFilter" onchange="onDepartmentChange()">
                    <option value="">All Departments</option>
                </select>
            </div>
            <div class="filter-group">
                <label for="teamFilter">Team:</label>
                <select id="teamFilter">
                    <option value="">All Teams</option>
                </select>
            </div>
            <div class="filter-group">
                <label for="statusFilter">Status:</label>
                <select id="statusFilter">
                    <option value="">All Status</option>
                    <option value="submitted">Submitted</option>
                    <option value="approved">Approved</option>
                </select>
            </div>
            <div class="filter-actions">
                <button class="btn-filter" onclick="applyFilters()">Apply Filters</button>
                <button class="btn-clear" onclick="clearFilters()">Clear All</button>
            </div>
        </div>
    </div>

    <!-- Timesheet List -->
    <div id="listSection" class="content-section">
        <h2 style="margin-bottom: 20px; color: #2c3e50;">Pending Timesheets</h2>
        <div class="table-container">
            <!-- Desktop Table -->
            <table class="main-table">
                <thead>
                    <tr>
                        <th>Employee ID</th>
			<th>Employee Name</th>
                        <th>Period</th>
                        <th>Department</th>
                        <th>Team</th>
                        <th>Submitted</th>
                        <th>Status</th>
                        <th>Comments</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody id="timesheetList"></tbody>
            </table>
            
            <!-- Mobile Cards Container -->
            <div id="mobileTimesheetCards"></div>
        </div>
    </div>

    <!-- Detail View -->
    <div id="detailSection" class="content-section" style="display:none;">
        <div class="detail-header">
            <h2 id="detailTitle" class="detail-title"></h2>
            <button class="btn-back" onclick="backToList()">← Back to List</button>
        </div>
        
        <!-- Employee Info -->
        <div id="employeeInfo" class="employee-info" style="display:none;">
            <h3>Employee Details</h3>
            <p><strong>Name:</strong> <span id="employeeName">-</span> | <strong>Job Title:</strong> <span id="employeeJobTitle">-</span> | <strong>Site:</strong> <span id="employeeSite">-</span> | <strong>HPW:</strong> <span id="employeeHPW">-</span></p>
            <p><strong>Department:</strong> <span id="employeeDepartment">-</span> | <strong>Team:</strong> <span id="employeeTeam">-</span></p>
        </div>
        
        <!-- Hours Summary Card -->
        <div id="hoursSummary" class="hours-summary" style="display:none;">
            <h3>Hours Summary</h3>
            <div class="summary-grid">
                <div class="summary-item expected">
                    <label>Expected Hours:</label>
                    <span id="expectedHours">00:00</span>
                    <small>(Total Work Hours + Absence)</small>
                </div>
                <div class="summary-item claimed">
                    <label>Employee Claimed:</label>
                    <span id="claimedHours">00:00</span>
                    <small>(Normal Paid + Absence + Enhancements + Overtime)</small>
                </div>
                <div class="summary-item variance">
                    <label>Variance:</label>
                    <span id="varianceHours">00:00</span>
                    <small id="varianceNote">-</small>
                </div>
            </div>
        </div>
        
        <div class="table-container">
            <!-- Desktop Detail Table -->
            <table class="detail-table">
                <thead>
                    <tr>
                        <th rowspan="2" style="width: 120px;">Date</th>
                        <th rowspan="2" style="width: 100px;">Start Time</th>
                        <th rowspan="2" style="width: 100px;">Stop Time</th>
                        <th rowspan="2" style="width: 70px;">Total Worked<br>Hours</th>
                        <th rowspan="2" style="width: 120px;">Normal Paid<br>Hours</th>
                        <th rowspan="2" style="width: 70px;">Overtime<br>Hours</th>
                        <th rowspan="2" style="width: 100px;">Absence Type</th>
                        <th rowspan="2" style="width: 70px;">Absence<br>Hours</th>
                        <th colspan="4" style="width: 260px;">Enhancements</th>
                        <th colspan="5" style="width: 325px;">Overtime & Extra Hours</th>
                        <th rowspan="2" style="width: 140px;">Comments</th>
                    </tr>
                    <tr>
                        <th style="width: 65px;">Sat<br>Enhancement</th>
                        <th style="width: 65px;">Sun<br>Enhancement</th>
                        <th style="width: 65px;">Nights<br>Enhancement</th>
                        <th style="width: 65px;">Bank Hol<br>Enhancement</th>
                        <th style="width: 65px;">Extra<br>Hours</th>
                        <th style="width: 65px;">Weekday<br>Overtime</th>
                        <th style="width: 65px;">Saturday<br>Overtime</th>
                        <th style="width: 65px;">Sunday<br>Overtime</th>
                        <th style="width: 65px;">Bank Hol<br>Overtime</th>
                    </tr>
                </thead>
                <tbody id="detailTable"></tbody>
                <tfoot>
                    <tr class="totals-row">
                        <td style="text-align: left; padding-left: 12px;">TOTALS</td>
                        <td>-</td>
                        <td>-</td>
                        <td class="hours-cell" id="totalWorkedHours">00:00</td>
                        <td class="hours-cell" id="totalNormalPaidHours">00:00</td>
                        <td class="hours-cell" id="totalOvertimeHours">00:00</td>
                        <td>-</td>
                        <td class="hours-cell" id="totalAbsenceHours">00:00</td>
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
            
            <!-- Mobile Detail Cards -->
            <div id="mobileDetailCards"></div>
        </div>
        
        <div class="action-buttons">
            <button class="btn-success" onclick="saveChanges()">Save Changes</button>
            <button class="btn-primary" onclick="approve()">Approve Timesheet</button>
            <button class="btn-danger" onclick="reject()">Reject Timesheet</button>
        </div>
    </div>
</div>

<script>
// Configuration
const API_URL = 'manager_api.php';
var csrfToken = '<?php echo htmlspecialchars($csrfToken); ?>';

// Global variables
let currentUser = null;
let currentDetail = { employee_id: null, period: null };
let originalData = {};
let pendingChanges = {};
let departmentsTeams = {};

// Utility functions
function timeToMinutes(timeStr) {
    if (!timeStr || timeStr === '00:00' || timeStr === '-') return 0;
    const parts = timeStr.split(':');
    return parseInt(parts[0]) * 60 + parseInt(parts[1]);
}

function minutesToTime(minutes) {
    const hours = Math.floor(minutes / 60);
    const mins = minutes % 60;
    return `${hours.toString().padStart(2, '0')}:${mins.toString().padStart(2, '0')}`;
}

function formatDateDisplay(dateStr) {
    let date;
    if (dateStr.includes('/')) {
        const parts = dateStr.split('/');
        date = new Date(parts[2], parts[1] - 1, parts[0]);
    } else {
        date = new Date(dateStr);
    }
    
    const days = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
    const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
    
    const dayName = days[date.getDay()];
    const day = date.getDate();
    const month = months[date.getMonth()];
    
    return `${dayName} ${day} ${month}`;
}

function convertTimeFormat(timeStr) {
    if (!timeStr || timeStr === '-') return '';
    if (timeStr.includes(':')) {
        const parts = timeStr.split(':');
        return `${parts[0].padStart(2, '0')}:${parts[1].padStart(2, '0')}`;
    }
    return timeStr;
}

function getHoursColorClass(timeValue) {
    if (!timeValue || timeValue === '00:00' || timeValue === '00:00:00') {
        return 'hours-zero';
    }
    return 'hours-enhanced';
}

function isEmployeeModified(value) {
    return value && value !== '00:00' && value !== '00:00:00' && value.trim() !== '';
}

// Authentication functions
async function loginUser() {
    console.log('Attempting manager login...');
    try {
        const res = await fetch(API_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                action: 'login',
                username: document.getElementById('username').value,
                password: document.getElementById('password').value
            })
        });
        
        const data = await res.json();
        console.log('Manager login response:', data);
        
        if (data.success) {
            currentUser = data.user;
	    console.log('Stored currentUser:', currentUser);
	    console.log('Manager ID:', currentUser.id);
	    console.log('All currentUser keys:', Object.keys(currentUser));    
            document.getElementById('login-modal').style.display = 'none';
            document.getElementById('main-container').style.display = 'block';
            document.getElementById('logout-btn').style.display = 'block';
            document.getElementById('filterSection').style.display = 'block';
            
            await loadDepartmentsTeams();
            await loadList();
        } else {
            document.getElementById('logout-btn').style.display = 'none';
            document.getElementById('main-container').style.display = 'none';
            document.getElementById('login-error').style.display = 'block';
            document.getElementById('login-error').innerText = data.error;
        }
    } catch (error) {
        console.error('Manager login error:', error);
        document.getElementById('login-error').style.display = 'block';
        document.getElementById('login-error').innerText = 'Connection error';
    }
}

function logout() {
    currentUser = null;
    document.getElementById('main-container').style.display = 'none';
    document.getElementById('logout-btn').style.display = 'none';
    document.getElementById('filterSection').style.display = 'none';
    document.getElementById('login-modal').style.display = 'flex';
    document.getElementById('username').value = '';
    document.getElementById('password').value = '';
    
    // Reset other state
    currentDetail = { employee_id: null, period: null };
    originalData = {};
    pendingChanges = {};
    departmentsTeams = {};
}

function showResetPassword() {
    const username = prompt('Enter your Username to receive a password reset email:');
    if (!username) return;

    requestPasswordReset(username.trim());
}

async function requestPasswordReset(username) {
    try {
        const response = await fetch('<?php echo htmlspecialchars($_SERVER['PHP_SELF']); ?>' + '?path=/request-password-reset', {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            },
            body: JSON.stringify({
                username: username,
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

// Data loading functions
async function loadDepartmentsTeams() {
    try {
        const res = await fetch(API_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: 'get_departments_teams' })
        });
        
        const data = await res.json();
        console.log('Departments/Teams response:', data);
        
        if (data.success) {
            departmentsTeams = data;
            populateDepartmentFilter(data.departments);
        }
    } catch (error) {
        console.error('Load departments/teams error:', error);
    }
}

function populateDepartmentFilter(departments) {
    const deptSelect = document.getElementById('departmentFilter');
    deptSelect.innerHTML = '<option value="">All Departments</option>';
    
    departments.forEach(dept => {
        const option = document.createElement('option');
        option.value = dept;
        option.textContent = dept;
        deptSelect.appendChild(option);
    });
}

function onDepartmentChange() {
    const selectedDept = document.getElementById('departmentFilter').value;
    const teamSelect = document.getElementById('teamFilter');
    
    teamSelect.innerHTML = '<option value="">All Teams</option>';
    
    if (selectedDept && departmentsTeams.teams_by_department[selectedDept]) {
        departmentsTeams.teams_by_department[selectedDept].forEach(team => {
            const option = document.createElement('option');
            option.value = team;
            option.textContent = team;
            teamSelect.appendChild(option);
        });
    }
}

async function loadList() {
    console.log('Loading timesheet list...');
    
    const department = document.getElementById('departmentFilter').value;
    const team = document.getElementById('teamFilter').value;
    const status = document.getElementById('statusFilter').value;
    
    if (!department && !team && !status) {
        const tbody = document.getElementById('timesheetList');
        const mobileContainer = document.getElementById('mobileTimesheetCards');
        tbody.innerHTML = '<tr><td colspan="9" style="text-align: center; color: #6c757d; padding: 40px;">Please select Department, Team or Status filters to view timesheets</td></tr>';
        return;
    }
    
    try {
        const res = await fetch(API_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                action: 'list_timesheets',
                department: department,
                team: team,
                status: status,
                manager_id: currentUser.id
            })
        });
        
        const data = await res.json();
        console.log('List response:', data);
        
        const tbody = document.getElementById('timesheetList');
        tbody.innerHTML = '';
        
        if (data.success && data.data) {
            if (data.data.length === 0) {
                tbody.innerHTML = '<tr><td colspan="9" style="text-align: center; color: #6c757d; padding: 40px;">No timesheets found for selected filters</td></tr>';
            } else {
                data.data.forEach(row => {
                    const tr = document.createElement('tr');
                    tr.innerHTML = `
                        <td><strong>${row.employee_id}</strong></td>
			<td>${row.employee_name}</td>
                        <td>${row.period}</td>
                        <td><span class="dept-badge">${row.department || 'N/A'}</span></td>
                        <td><span class="team-badge">${row.team || 'N/A'}</span></td>
                        <td>${new Date(row.submitted_date).toLocaleString()}</td>
                        <td><span class="status-badge status-${row.status}">${row.status}</span></td>
                        <td>${row.comments || '-'}</td>
                        <td><button class="btn-view" onclick="viewDetail('${row.employee_id}','${row.period}')">View Details</button></td>
                    `;
                    tbody.appendChild(tr);
                });
            }
            
            // Create mobile cards
            createMobileTimesheetCards(data.data);
        } else {
            tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; color: #dc3545; padding: 40px;">Error loading timesheets: ' + (data.error || 'Unknown error') + '</td></tr>';
            document.getElementById('mobileTimesheetCards').innerHTML = '<div style="text-align: center; color: #dc3545; padding: 40px;">Error loading timesheets</div>';
        }
    } catch (error) {
        console.error('Load list error:', error);
        document.getElementById('timesheetList').innerHTML = '<tr><td colspan="8" style="text-align: center; color: #dc3545; padding: 40px;">Connection error</td></tr>';
        document.getElementById('mobileTimesheetCards').innerHTML = '<div style="text-align: center; color: #dc3545; padding: 40px;">Connection error</div>';
    }
    updateListSectionTitle();
}

// Mobile UI functions
function createMobileTimesheetCards(data) {
    const container = document.getElementById('mobileTimesheetCards');
    container.innerHTML = '';
    
    if (!data || data.length === 0) {
        container.innerHTML = '';
        return;
    }
    
    data.forEach(row => {
        const card = document.createElement('div');
        card.className = 'timesheet-card';
        card.innerHTML = `
            <div class="card-header">
                <div class="card-title">Employee ${row.employee_id}</div>
                <span class="status-badge status-${row.status}">${row.status}</span>
            </div>
            <div class="card-body">
                <div class="field-row">
                    <span class="field-label">Period:</span>
                    <span class="field-value">${row.period}</span>
                </div>
                <div class="field-row">
                    <span class="field-label">Department:</span>
                    <span class="field-value"><span class="dept-badge">${row.department || 'N/A'}</span></span>
                </div>
                <div class="field-row">
                    <span class="field-label">Team:</span>
                    <span class="field-value"><span class="team-badge">${row.team || 'N/A'}</span></span>
                </div>
                <div class="field-row">
                    <span class="field-label">Submitted:</span>
                    <span class="field-value">${new Date(row.submitted_date).toLocaleDateString()}</span>
                </div>
                <div class="field-row">
                    <span class="field-label">Comments:</span>
                    <span class="field-value">${row.comments || '-'}</span>
                </div>
                <div style="margin-top: 15px; text-align: center;">
                    <button class="btn-view" onclick="viewDetail('${row.employee_id}','${row.period}')">View Details</button>
                </div>
            </div>
        `;
        container.appendChild(card);
    });
}

function createMobileDetailCards(data) {
    const container = document.getElementById('mobileDetailCards');
    container.innerHTML = '';
    
    if (!data || data.length === 0) {
        container.innerHTML = '<div style="text-align: center; color: #dc3545; padding: 40px;">No data available</div>';
        return;
    }
    
    data.forEach((row, index) => {
        const startChanged = row.original_start !== row.submitted_start;
        const stopChanged = row.original_stop !== row.submitted_stop;
        
        const card = document.createElement('div');
        card.className = 'timesheet-card';
        card.innerHTML = `
            <div class="card-header">
                <div class="card-title">${formatDateDisplay(row.date)}</div>
                ${row.absence_type && row.absence_type !== 'None' ? '<span class="status-badge status-warning">Absence</span>' : ''}
            </div>
            <div class="card-body">
                <div class="card-section">
                    <div class="section-title">Work Hours</div>
                    <div class="field-row">
                        <span class="field-label">Start Time:</span>
                        <input type="time" class="mobile-input editable-time ${startChanged ? 'employee-value' : ''}" 
                               value="${convertTimeFormat(row.submitted_start)}" 
                               data-field="startTime" data-index="${index}" 
                               onchange="trackChange(this)">
                    </div>
                    <div class="field-row">
                        <span class="field-label">Stop Time:</span>
                        <input type="time" class="mobile-input editable-time ${stopChanged ? 'employee-value' : ''}" 
                               value="${convertTimeFormat(row.submitted_stop)}" 
                               data-field="stopTime" data-index="${index}" 
                               onchange="trackChange(this)">
                    </div>
                    <div class="field-row">
                        <span class="field-label">Total Worked:</span>
                        <span class="field-value ${getHoursColorClass(row.total_worked_hours)}">${row.total_worked_hours || '00:00'}</span>
                    </div>
                    <div class="field-row">
                        <span class="field-label">Normal Paid:</span>
                        <input type="time" class="mobile-input editable-time ${isEmployeeModified(row.employee_normal_paid_hours) ? 'employee-value' : ''}" 
                               value="${convertTimeFormat(row.employee_normal_paid_hours)}" 
                               data-field="normalPaidHours" data-index="${index}" 
                               onchange="trackChange(this)">
                    </div>
                </div>
                
                ${row.absence_type && row.absence_type !== 'None' ? `
                <div class="card-section">
                    <div class="section-title">Absence</div>
                    <div class="field-row">
                        <span class="field-label">Type:</span>
                        <span class="field-value">${row.absence_type}</span>
                    </div>
                    <div class="field-row">
                        <span class="field-label">Hours:</span>
                        <span class="field-value">${row.absence_hours || '00:00'}</span>
                    </div>
                </div>
                ` : ''}
                
                <div class="card-section">
                    <div class="section-title">Enhancements</div>
                    <div class="field-row">
                        <span class="field-label">Saturday:</span>
                        <input type="text" class="mobile-input editable-time ${isEmployeeModified(row.sat_enhancement) ? 'employee-value' : ''}" 
                               value="${row.sat_enhancement || '00:00'}" 
                               data-field="satEnhancement" data-index="${index}" 
                               onchange="trackChange(this)" onblur="formatOnBlur(this)">
                    </div>
                    <div class="field-row">
                        <span class="field-label">Sunday:</span>
                        <input type="text" class="mobile-input editable-time ${isEmployeeModified(row.sun_enhancement) ? 'employee-value' : ''}" 
                               value="${row.sun_enhancement || '00:00'}" 
                               data-field="sunEnhancement" data-index="${index}" 
                               onchange="trackChange(this)" onblur="formatOnBlur(this)">
                    </div>
                    <div class="field-row">
                        <span class="field-label">Nights:</span>
                        <input type="text" class="mobile-input editable-time ${isEmployeeModified(row.nights_enhancement) ? 'employee-value' : ''}" 
                               value="${row.nights_enhancement || '00:00'}" 
                               data-field="nightsEnhancement" data-index="${index}" 
                               onchange="trackChange(this)" onblur="formatOnBlur(this)">
                    </div>
                    <div class="field-row">
                        <span class="field-label">Bank Holiday:</span>
                        <input type="text" class="mobile-input editable-time ${isEmployeeModified(row.bank_holiday_enhancement) ? 'employee-value' : ''}" 
                               value="${row.bank_holiday_enhancement || '00:00'}" 
                               data-field="bankHolidayEnhancement" data-index="${index}" 
                               onchange="trackChange(this)" onblur="formatOnBlur(this)">
                    </div>
                </div>
                
                <div class="card-section">
                    <div class="section-title">Overtime & Extra Hours</div>
                    <div class="field-row">
                        <span class="field-label">Extra Hours:</span>
                        <input type="text" class="mobile-input editable-time ${isEmployeeModified(row.extra_hours) ? 'employee-value' : ''}" 
                               value="${row.extra_hours || '00:00'}" 
                               data-field="extraHours" data-index="${index}" 
                               onchange="trackChange(this)" onblur="formatOnBlur(this)">
                    </div>
                    <div class="field-row">
                        <span class="field-label">Weekday OT:</span>
                        <input type="text" class="mobile-input editable-time ${isEmployeeModified(row.weekday_overtime) ? 'employee-value' : ''}" 
                               value="${row.weekday_overtime || '00:00'}" 
                               data-field="weekdayOvertime" data-index="${index}" 
                               onchange="trackChange(this)" onblur="formatOnBlur(this)">
                    </div>
                    <div class="field-row">
                        <span class="field-label">Saturday OT:</span>
                        <input type="text" class="mobile-input editable-time ${isEmployeeModified(row.sat_overtime) ? 'employee-value' : ''}" 
                               value="${row.sat_overtime || '00:00'}" 
                               data-field="satOvertime" data-index="${index}" 
                               onchange="trackChange(this)" onblur="formatOnBlur(this)">
                    </div>
                    <div class="field-row">
                        <span class="field-label">Sunday OT:</span>
                        <input type="text" class="mobile-input editable-time ${isEmployeeModified(row.sun_overtime) ? 'employee-value' : ''}" 
                               value="${row.sun_overtime || '00:00'}" 
                               data-field="sunOvertime" data-index="${index}" 
                               onchange="trackChange(this)" onblur="formatOnBlur(this)">
                    </div>
                    <div class="field-row">
                        <span class="field-label">Bank Holiday OT:</span>
                        <input type="text" class="mobile-input editable-time ${isEmployeeModified(row.bank_holiday_overtime) ? 'employee-value' : ''}" 
                               value="${row.bank_holiday_overtime || '00:00'}" 
                               data-field="bankHolidayOvertime" data-index="${index}" 
                               onchange="trackChange(this)" onblur="formatOnBlur(this)">
                    </div>
                </div>
                
                <div class="card-section">
                    <div class="section-title">Comments</div>
                    <textarea class="mobile-textarea editable-textarea ${row.comments && row.comments.trim() ? 'employee-value' : ''}" 
                              data-field="comments" data-index="${index}" 
                              onchange="trackChange(this)"
                              placeholder="Add comments...">${row.comments || ''}</textarea>
                </div>
            </div>
        `;
        container.appendChild(card);
    });
}

// Detail view functions
async function viewDetail(employee_id, period) {
    console.log(`Loading detail for ${employee_id}, ${period}`);
    
    try {
        const res = await fetch(API_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                action: 'get_timesheet_detail', 
                employee_id: employee_id, 
                period: period 
            })
        });
        
        const data = await res.json();
        console.log('Detail response:', data);
        
        if (data.success && data.submitted) {
            originalData = data.submitted;
            currentDetail = { employee_id: employee_id, period: period };
            pendingChanges = {};
            
            // Show detail section, hide list
            document.getElementById('listSection').style.display = 'none';
            document.getElementById('detailSection').style.display = 'block';
            document.getElementById('detailTitle').innerText = `Employee ${employee_id} - ${period}`;
            
            // Show employee info
            if (data.employee_info) {
                document.getElementById('employeeName').innerText = data.employee_info.employee_name || '-';
                document.getElementById('employeeJobTitle').innerText = data.employee_info.job_title || '-';
                document.getElementById('employeeSite').innerText = data.employee_info.site || '-';
                document.getElementById('employeeHPW').innerText = data.employee_info.hpw || '-';
                document.getElementById('employeeInfo').style.display = 'block';
            }

            // Show department/team info  
            if (data.department_info) {
                document.getElementById('employeeDepartment').innerText = data.department_info.department || '-';
                document.getElementById('employeeTeam').innerText = data.department_info.team || '-';
            }
            
            // Build and show desktop table
            buildDetailTable(data.submitted);
            
            // Build mobile cards
            createMobileDetailCards(data.submitted);
            
            // Calculate and show hours summary
            calculateAndShowHoursSummary(data.submitted);
        } else {
            alert('Error loading timesheet details: ' + (data.error || 'Unknown error'));
        }
    } catch (error) {
        console.error('View detail error:', error);
        alert('Connection error while loading details');
    }
}

function buildDetailTable(data) {
    const tbody = document.getElementById('detailTable');
    tbody.innerHTML = '';
    
    let totals = {
        workedHours: 0,
        normalPaidHours: 0,
        overtimeHours: 0,
        absenceHours: 0,
        satEnhancement: 0,
        sunEnhancement: 0,
        nightsEnhancement: 0,
        bankHolEnhancement: 0,
        extraHours: 0,
        weekdayOT: 0,
        satOT: 0,
        sunOT: 0,
        bankHolOT: 0
    };
    
    data.forEach((row, index) => {
        const tr = document.createElement('tr');
        
        const startChanged = row.original_start !== row.submitted_start;
        const stopChanged = row.original_stop !== row.submitted_stop;
        
        tr.innerHTML = `
            <td class="date-cell">${formatDateDisplay(row.date)}</td>
            <td><input type="time" class="editable-time ${startChanged ? 'employee-value' : ''}" value="${convertTimeFormat(row.submitted_start)}" data-field="startTime" data-index="${index}" onchange="trackChange(this)"></td>
            <td><input type="time" class="editable-time ${stopChanged ? 'employee-value' : ''}" value="${convertTimeFormat(row.submitted_stop)}" data-field="stopTime" data-index="${index}" onchange="trackChange(this)"></td>
            <td class="hours-cell ${getHoursColorClass(row.total_worked_hours)}">${row.total_worked_hours || '00:00'}</td>
            <td><input type="time" class="editable-time ${isEmployeeModified(row.employee_normal_paid_hours) ? 'employee-value' : ''}" value="${convertTimeFormat(row.employee_normal_paid_hours)}" data-field="normalPaidHours" data-index="${index}" onchange="trackChange(this)"></td>
            <td class="hours-cell overtime-hours">${row.overtime_hours || '00:00'}</td>
            <td>${row.absence_type || '-'}</td>
            <td class="hours-cell ${row.absence_hours && row.absence_hours !== '00:00' ? 'absence-highlight' : ''}">${row.absence_hours || '00:00'}</td>
            <td class="enhancement-cell"><input type="text" class="editable-time ${isEmployeeModified(row.sat_enhancement) ? 'employee-value' : ''}" value="${row.sat_enhancement || '00:00'}" data-field="satEnhancement" data-index="${index}" onchange="trackChange(this)" onblur="formatOnBlur(this)"></td>
            <td class="enhancement-cell"><input type="text" class="editable-time ${isEmployeeModified(row.sun_enhancement) ? 'employee-value' : ''}" value="${row.sun_enhancement || '00:00'}" data-field="sunEnhancement" data-index="${index}" onchange="trackChange(this)" onblur="formatOnBlur(this)"></td>
            <td class="enhancement-cell"><input type="text" class="editable-time ${isEmployeeModified(row.nights_enhancement) ? 'employee-value' : ''}" value="${row.nights_enhancement || '00:00'}" data-field="nightsEnhancement" data-index="${index}" onchange="trackChange(this)" onblur="formatOnBlur(this)"></td>
            <td class="enhancement-cell"><input type="text" class="editable-time ${isEmployeeModified(row.bank_holiday_enhancement) ? 'employee-value' : ''}" value="${row.bank_holiday_enhancement || '00:00'}" data-field="bankHolidayEnhancement" data-index="${index}" onchange="trackChange(this)" onblur="formatOnBlur(this)"></td>
            <td class="extra-hours-cell"><input type="text" class="editable-time ${isEmployeeModified(row.extra_hours) ? 'employee-value' : ''}" value="${row.extra_hours || '00:00'}" data-field="extraHours" data-index="${index}" onchange="trackChange(this)" onblur="formatOnBlur(this)"></td>
            <td class="overtime-cell"><input type="text" class="editable-time ${isEmployeeModified(row.weekday_overtime) ? 'employee-value' : ''}" value="${row.weekday_overtime || '00:00'}" data-field="weekdayOvertime" data-index="${index}" onchange="trackChange(this)" onblur="formatOnBlur(this)"></td>
            <td class="overtime-cell"><input type="text" class="editable-time ${isEmployeeModified(row.sat_overtime) ? 'employee-value' : ''}" value="${row.sat_overtime || '00:00'}" data-field="satOvertime" data-index="${index}" onchange="trackChange(this)" onblur="formatOnBlur(this)"></td>
            <td class="overtime-cell"><input type="text" class="editable-time ${isEmployeeModified(row.sun_overtime) ? 'employee-value' : ''}" value="${row.sun_overtime || '00:00'}" data-field="sunOvertime" data-index="${index}" onchange="trackChange(this)" onblur="formatOnBlur(this)"></td>
            <td class="overtime-cell"><input type="text" class="editable-time ${isEmployeeModified(row.bank_holiday_overtime) ? 'employee-value' : ''}" value="${row.bank_holiday_overtime || '00:00'}" data-field="bankHolidayOvertime" data-index="${index}" onchange="trackChange(this)" onblur="formatOnBlur(this)"></td>
            <td><textarea class="editable-textarea ${row.comments && row.comments.trim() ? 'employee-value' : ''}" data-field="comments" data-index="${index}" onchange="trackChange(this)" placeholder="Comments...">${row.comments || ''}</textarea></td>
        `;
        
        tbody.appendChild(tr);
        
        // Add to totals
        totals.workedHours += timeToMinutes(row.total_worked_hours || '00:00');
        totals.normalPaidHours += timeToMinutes(row.employee_normal_paid_hours || '00:00');
        totals.overtimeHours += timeToMinutes(row.overtime_hours || '00:00');
        totals.absenceHours += timeToMinutes(row.absence_hours || '00:00');
        totals.satEnhancement += timeToMinutes(row.sat_enhancement || '00:00');
        totals.sunEnhancement += timeToMinutes(row.sun_enhancement || '00:00');
        totals.nightsEnhancement += timeToMinutes(row.nights_enhancement || '00:00');
        totals.bankHolEnhancement += timeToMinutes(row.bank_holiday_enhancement || '00:00');
        totals.extraHours += timeToMinutes(row.extra_hours || '00:00');
        totals.weekdayOT += timeToMinutes(row.weekday_overtime || '00:00');
        totals.satOT += timeToMinutes(row.sat_overtime || '00:00');
        totals.sunOT += timeToMinutes(row.sun_overtime || '00:00');
        totals.bankHolOT += timeToMinutes(row.bank_holiday_overtime || '00:00');
    });
    
    // Update totals row
    document.getElementById('totalWorkedHours').innerText = minutesToTime(totals.workedHours);
    document.getElementById('totalNormalPaidHours').innerText = minutesToTime(totals.normalPaidHours);
    document.getElementById('totalOvertimeHours').innerText = minutesToTime(totals.overtimeHours);
    document.getElementById('totalAbsenceHours').innerText = minutesToTime(totals.absenceHours);
    document.getElementById('totalSatEnhancement').innerText = minutesToTime(totals.satEnhancement);
    document.getElementById('totalSunEnhancement').innerText = minutesToTime(totals.sunEnhancement);
    document.getElementById('totalNightsEnhancement').innerText = minutesToTime(totals.nightsEnhancement);
    document.getElementById('totalBankHolEnhancement').innerText = minutesToTime(totals.bankHolEnhancement);
    document.getElementById('totalExtraHours').innerText = minutesToTime(totals.extraHours);
    document.getElementById('totalWeekdayOT').innerText = minutesToTime(totals.weekdayOT);
    document.getElementById('totalSatOT').innerText = minutesToTime(totals.satOT);
    document.getElementById('totalSunOT').innerText = minutesToTime(totals.sunOT);
    document.getElementById('totalBankHolOT').innerText = minutesToTime(totals.bankHolOT);
}

function calculateAndShowHoursSummary(data) {
    let expectedTotal = 0;
    let claimedTotal = 0;
    
    data.forEach(row => {
        expectedTotal += timeToMinutes(row.total_worked_hours || '00:00');
        expectedTotal += timeToMinutes(row.absence_hours || '00:00');
        
        claimedTotal += timeToMinutes(row.employee_normal_paid_hours || '00:00');
        claimedTotal += timeToMinutes(row.absence_hours || '00:00');
        claimedTotal += timeToMinutes(row.sat_enhancement || '00:00');
        claimedTotal += timeToMinutes(row.sun_enhancement || '00:00');
        claimedTotal += timeToMinutes(row.nights_enhancement || '00:00');
        claimedTotal += timeToMinutes(row.bank_holiday_enhancement || '00:00');
        claimedTotal += timeToMinutes(row.extra_hours || '00:00');
        claimedTotal += timeToMinutes(row.weekday_overtime || '00:00');
        claimedTotal += timeToMinutes(row.sat_overtime || '00:00');
        claimedTotal += timeToMinutes(row.sun_overtime || '00:00');
        claimedTotal += timeToMinutes(row.bank_holiday_overtime || '00:00');
    });
    
    const variance = claimedTotal - expectedTotal;
    
    document.getElementById('expectedHours').innerText = minutesToTime(expectedTotal);
    document.getElementById('claimedHours').innerText = minutesToTime(claimedTotal);
    document.getElementById('varianceHours').innerText = minutesToTime(Math.abs(variance));
    
    const varianceNote = document.getElementById('varianceNote');
    if (variance > 0) {
        varianceNote.innerText = '(Over-claimed)';
        varianceNote.style.color = '#dc3545';
    } else if (variance < 0) {
        varianceNote.innerText = '(Under-claimed)';
        varianceNote.style.color = '#fd7e14';
    } else {
        varianceNote.innerText = '(Perfect match)';
        varianceNote.style.color = '#28a745';
    }
    
    document.getElementById('hoursSummary').style.display = 'block';
}

// Edit tracking functions
function trackChange(element) {
    const field = element.getAttribute('data-field');
    const index = element.getAttribute('data-index');
    const value = element.value;
    
    if (!pendingChanges[index]) {
        pendingChanges[index] = {};
    }
    
    pendingChanges[index][field] = value;
    element.classList.add('manager-changed');
    
    console.log('Change tracked:', { index, field, value });
}

function formatOnBlur(element) {
    const value = element.value;
    if (value && !value.includes(':')) {
        // Try to format as time if it's just a number
        const num = parseInt(value);
        if (!isNaN(num) && num >= 0) {
            const hours = Math.floor(num / 100);
            const minutes = num % 100;
            if (minutes < 60) {
                element.value = `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}`;
                trackChange(element);
            }
        }
    }
}

// Navigation functions
function backToList() {
    document.getElementById('detailSection').style.display = 'none';
    document.getElementById('listSection').style.display = 'block';
    document.getElementById('hoursSummary').style.display = 'none';
    document.getElementById('employeeInfo').style.display = 'none';
    
    currentDetail = { employee_id: null, period: null };
    originalData = {};
    pendingChanges = {};
}

// Filter functions
function applyFilters() {
    loadList();
}

function clearFilters() {
    document.getElementById('departmentFilter').value = '';
    document.getElementById('teamFilter').value = '';
    document.getElementById('statusFilter').value = '';
    loadList();
}

function updateListSectionTitle() {
    const status = document.getElementById('statusFilter').value;
    const title = document.querySelector('#listSection h2');
    
    if (status === 'approved') {
        title.textContent = 'Approved Timesheets';
        title.style.color = '#28a745';
    } else if (status === 'submitted') {
        title.textContent = 'Pending Timesheets';
        title.style.color = '#2c3e50';
    } else {
        title.textContent = 'Timesheets';
        title.style.color = '#2c3e50';
    }
}

// Action functions
async function saveChanges() {
    if (Object.keys(pendingChanges).length === 0) {
        alert('No changes to save');
        return;
    }
    
    console.log('Saving changes:', pendingChanges);
    
    try {
        const res = await fetch(API_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                action: 'save_manager_changes',
                employee_id: currentDetail.employee_id,
                period: currentDetail.period,
                changes: pendingChanges,
		manager_id: currentUser.id
            })
        });
        
        const data = await res.json();
        console.log('Save response:', data);
        
        if (data.success) {
            showSaveIndicator();
            pendingChanges = {};
            
            // Remove manager-changed classes
            document.querySelectorAll('.manager-changed').forEach(el => {
                el.classList.remove('manager-changed');
            });
        } else {
            alert('Error saving changes: ' + (data.error || 'Unknown error'));
        }
    } catch (error) {
        console.error('Save error:', error);
        alert('Connection error while saving changes');
    }
}

async function approve() {
    if (Object.keys(pendingChanges).length > 0) {
        const confirmSave = confirm('You have unsaved changes. Save before approving?');
        if (confirmSave) {
            await saveChanges();
        }
    }
    
    const confirmApprove = confirm(`Approve timesheet for Employee ${currentDetail.employee_id} - ${currentDetail.period}?`);
    if (!confirmApprove) return;
    
    try {
        const res = await fetch(API_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                action: 'approve_timesheet',
                employee_id: currentDetail.employee_id,
                period: currentDetail.period,
		manager_id: currentUser.id
            })
        });
        
        const data = await res.json();
        console.log('Approve response:', data);
        
        if (data.success) {
            alert('Timesheet approved successfully!');
            backToList();
            loadList(); // Refresh the list
        } else {
            alert('Error approving timesheet: ' + (data.error || 'Unknown error'));
        }
    } catch (error) {
        console.error('Approve error:', error);
        alert('Connection error while approving timesheet');
    }
}

async function reject() {
    const reason = prompt('Please provide a reason for rejection:');
    if (!reason || reason.trim() === '') {
        alert('Rejection reason is required');
        return;
    }
    
    const confirmReject = confirm(`Reject timesheet for Employee ${currentDetail.employee_id} - ${currentDetail.period}?\n\nReason: ${reason}`);
    if (!confirmReject) return;
    
    try {
        const res = await fetch(API_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                action: 'reject_timesheet',
                employee_id: currentDetail.employee_id,
                period: currentDetail.period,
                reason: reason,
		manager_id: currentUser.id
            })
        });
        
        const data = await res.json();
        console.log('Reject response:', data);
        
        if (data.success) {
            alert('Timesheet rejected successfully!');
            backToList();
            loadList(); // Refresh the list
        } else {
            alert('Error rejecting timesheet: ' + (data.error || 'Unknown error'));
        }
    } catch (error) {
        console.error('Reject error:', error);
        alert('Connection error while rejecting timesheet');
    }
}

function showSaveIndicator() {
    const indicator = document.getElementById('save-indicator');
    indicator.classList.add('show');
    setTimeout(() => {
        indicator.classList.remove('show');
    }, 3000);
}

// Event listeners
document.addEventListener('DOMContentLoaded', function() {
    console.log('NHS Manager Timesheet Portal - Version 2.0');
    
    // Security: Disable right-click and common dev shortcuts
    document.addEventListener('contextmenu', e => e.preventDefault());
    document.addEventListener('keydown', function(e) {
        if (e.key === 'F12' || (e.ctrlKey && e.shiftKey && (e.key === 'I' || e.key === 'C' || e.key === 'J'))) {
            e.preventDefault();
        }
    });
    
    document.getElementById('username').addEventListener('keypress', function(e) {
        if (e.key === 'Enter') loginUser();
    });
    
    document.getElementById('password').addEventListener('keypress', function(e) {
        if (e.key === 'Enter') loginUser();
    });
});
</script>
</body>
</html>