<?php
// Security Headers
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');
header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self';");
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Permissions-Policy: geolocation=(), microphone=(), camera=()');

// Session security settings
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 1);
ini_set('session.use_strict_mode', 1);

// Start session
session_start();

// CSRF Token generation
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Function to validate CSRF token
function validateCSRF($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

// Function to sanitize input
function sanitizeInput($input) {
    return htmlspecialchars(trim($input), ENT_QUOTES, 'UTF-8');
}

// Function to validate input length
function validateLength($input, $min = 1, $max = 255) {
    $len = strlen($input);
    return $len >= $min && $len <= $max;
}

// Function to validate username format
function validateUsername($username) {
    return preg_match('/^[a-zA-Z0-9_]{3,50}$/', $username);
}

// Rate limiting (simple implementation)
function checkRateLimit() {
    if (!isset($_SESSION['last_request'])) {
        $_SESSION['last_request'] = time();
        $_SESSION['request_count'] = 1;
        return true;
    }
    
    $time_diff = time() - $_SESSION['last_request'];
    if ($time_diff < 1) { // 1 second between requests
        $_SESSION['request_count']++;
        if ($_SESSION['request_count'] > 10) {
            return false; // Too many requests
        }
    } else {
        $_SESSION['request_count'] = 1;
        $_SESSION['last_request'] = time();
    }
    return true;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NHS Admin Portal - User Management</title>
<style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: Arial, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; padding: 20px; }
    .container { max-width: 1400px; margin: 0 auto; background: white; border-radius: 15px; box-shadow: 0 20px 40px rgba(0,0,0,0.1); overflow: hidden; }
    .header { background: linear-gradient(135deg, #2c3e50 0%, #c0392b 100%); color: white; padding: 25px 30px; text-align: center; position: relative; }
    .header h1 { margin: 0; font-size: 28px; }
    
    /* Login Modal */
    .login-modal { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); display: flex; align-items: center; justify-content: center; z-index: 1000; }
    .login-form { background: white; padding: 40px; border-radius: 15px; max-width: 400px; width: 90%; box-shadow: 0 20px 40px rgba(0,0,0,0.3); }
    .login-form h2 { margin-bottom: 20px; text-align: center; color: #2c3e50; }
    .login-form input { width: 100%; padding: 12px; border: 2px solid #e9ecef; border-radius: 8px; font-size: 1rem; margin-bottom: 15px; }
    .login-form button { width: 100%; padding: 14px; background: linear-gradient(135deg, #c0392b, #8b0000); color: white; border: none; border-radius: 8px; font-size: 1rem; cursor: pointer; }
    .error { color: #dc3545; margin-bottom: 10px; text-align: center; padding: 10px; background: #f8d7da; border-radius: 5px; }
    
    /* Navigation */
    .nav-bar { background: #f8f9fa; padding: 15px 30px; border-bottom: 2px solid #dee2e6; display: flex; justify-content: space-between; align-items: center; }
    .nav-buttons { display: flex; gap: 10px; }
    .nav-btn { padding: 8px 16px; border: none; border-radius: 6px; cursor: pointer; font-weight: 600; transition: all 0.3s; }
    .nav-btn.active { background: #dc3545; color: white; }
    .nav-btn:not(.active) { background: #e9ecef; color: #495057; }
    .nav-btn:hover { transform: translateY(-1px); }
    
    /* Content Sections */
    .content-section { padding: 30px; display: none; }
    .content-section.active { display: block; }
    
    /* Tables */
    .data-table { width: 100%; border-collapse: collapse; margin: 20px 0; font-size: 14px; }
    .data-table th, .data-table td { border: 1px solid #e9ecef; padding: 12px; text-align: left; }
    .data-table th { background: #343a40; color: white; font-weight: 600; text-align: center; }
    .data-table tr:hover { background: #f8f9fa; }
    
    /* Forms */
    .form-container { background: #f8f9fa; padding: 25px; border-radius: 12px; margin: 20px 0; }
    .form-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 20px; }
    .form-group { display: flex; flex-direction: column; }
    .form-group label { font-weight: 600; margin-bottom: 5px; color: #2c3e50; }
    .form-group input, .form-group select { padding: 10px; border: 2px solid #dee2e6; border-radius: 6px; font-size: 14px; }
    .form-group input:focus, .form-group select:focus { outline: none; border-color: #dc3545; box-shadow: 0 0 0 0.2rem rgba(220,53,69,.25); }
    
    /* Buttons */
    .btn { padding: 10px 20px; border: none; border-radius: 6px; cursor: pointer; font-weight: 600; margin: 5px; transition: all 0.3s; }
    .btn-primary { background: #dc3545; color: white; }
    .btn-primary:hover { background: #c82333; transform: translateY(-1px); }
    .btn-success { background: #28a745; color: white; }
    .btn-success:hover { background: #218838; transform: translateY(-1px); }
    .btn-danger { background: #dc3545; color: white; }
    .btn-danger:hover { background: #c82333; transform: translateY(-1px); }
    .btn-warning { background: #ffc107; color: #212529; }
    .btn-warning:hover { background: #e0a800; transform: translateY(-1px); }
    .btn-secondary { background: #6c757d; color: white; }
    .btn-secondary:hover { background: #545b62; }
    
    /* Status badges */
    .role-badge { padding: 4px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; text-transform: uppercase; }
    .role-admin { background: #dc3545; color: white; }
    .role-manager { background: #007bff; color: white; }
    .role-supervisor { background: #28a745; color: white; }
    .role-employee { background: #6c757d; color: white; }
    
    .level-badge { padding: 4px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; }
    .level-4 { background: #dc3545; color: white; }
    .level-3 { background: #007bff; color: white; }
    .level-2 { background: #28a745; color: white; }
    .level-1 { background: #ffc107; color: #212529; }
    
    /* Stats Cards */
    .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
    .stat-card { background: linear-gradient(135deg, #fff, #f8f9fa); padding: 20px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); text-align: center; }
    .stat-card h3 { color: #2c3e50; margin-bottom: 10px; }
    .stat-card .stat-number { font-size: 2em; font-weight: bold; color: #dc3545; }
    .stat-card .stat-label { color: #6c757d; font-size: 14px; }
    
    /* Modal */
    .modal { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); display: none; align-items: center; justify-content: center; z-index: 1000; }
    .modal-content { background: white; padding: 30px; border-radius: 15px; max-width: 500px; width: 90%; max-height: 80vh; overflow-y: auto; }
    .modal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
    .modal-title { font-size: 1.5em; color: #2c3e50; }
    .close-btn { background: none; border: none; font-size: 1.5em; cursor: pointer; color: #6c757d; }
    .close-btn:hover { color: #dc3545; }
    
    /* Search and Filter */
    .search-bar { width: 100%; padding: 10px; border: 2px solid #dee2e6; border-radius: 6px; font-size: 14px; margin-bottom: 20px; }
    .filter-row { display: flex; gap: 15px; margin-bottom: 20px; align-items: end; }
    .filter-group { min-width: 150px; }
    
    /* Activity Log */
    .activity-item { background: white; border-left: 4px solid #dc3545; padding: 15px; margin: 10px 0; border-radius: 0 8px 8px 0; }
    .activity-date { font-size: 12px; color: #6c757d; }
    .activity-action { font-weight: 600; color: #2c3e50; }
    .activity-details { color: #495057; font-size: 14px; }
    
    /* Reports */
    .report-container { background: white; border-radius: 8px; padding: 20px; margin: 20px 0; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    .report-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }
    .report-title { color: #2c3e50; font-size: 1.2em; font-weight: 600; }
    
    /* Responsive */
    @media (max-width: 768px) {
        body { padding: 10px; }
        .form-grid { grid-template-columns: 1fr; }
        .nav-buttons { flex-wrap: wrap; }
        .stats-grid { grid-template-columns: 1fr; }
        .filter-row { flex-direction: column; align-items: stretch; }
    }
    
    .hidden { display: none !important; }
    .text-danger { color: #dc3545; }
    .text-success { color: #28a745; }
    .text-warning { color: #ffc107; }
</style>
</head>
<body>

<!-- Login Modal -->
<div id="login-modal" class="login-modal">
    <div class="login-form">
        <h2>NHS Admin Login</h2>
        <div id="login-error" class="error" style="display:none;"></div>
        <form id="login-form">
            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
            <input type="text" id="username" name="username" placeholder="Admin Username" required maxlength="50">
            <input type="password" id="password" name="password" placeholder="Password" required maxlength="255">
            <button type="submit">Sign In</button>
        </form>
    </div>
</div>

<!-- Main Container -->
<div class="container" id="main-container" style="display:none;">
    <div class="header">
        <h1>NHS Admin Portal - System Management</h1>
        <button id="logout-btn" class="btn btn-secondary" onclick="logout()" style="position: absolute; top: 20px; right: 30px;">Logout</button>
    </div>

    <!-- Navigation -->
    <div class="nav-bar">
        <div class="nav-buttons">
            <button class="nav-btn active" onclick="showSection('dashboard')">Dashboard</button>
            <button class="nav-btn" onclick="showSection('managers')">Manage Users</button>
            <button class="nav-btn" onclick="showSection('leavers')">Handle Leavers</button>
            <button class="nav-btn" onclick="showSection('passwords')">Password Management</button>
            <button class="nav-btn" onclick="showSection('reports')">Reports & Analytics</button>
            <button class="nav-btn" onclick="showSection('activity')">Activity Log</button>
        </div>
        <div>
            <span id="current-admin">Admin Portal</span>
        </div>
    </div>

    <!-- Dashboard Section -->
    <div id="dashboard" class="content-section active">
        <h2 style="margin-bottom: 20px; color: #2c3e50;">System Overview</h2>
        <div class="stats-grid" id="stats-container">
            <div class="stat-card">
                <h3>Total Users</h3>
                <div class="stat-number" id="total-users">0</div>
                <div class="stat-label">Active accounts</div>
            </div>
            <div class="stat-card">
                <h3>Managers</h3>
                <div class="stat-number" id="total-managers">0</div>
                <div class="stat-label">Level 3+ users</div>
            </div>
            <div class="stat-card">
                <h3>Pending Approvals</h3>
                <div class="stat-number" id="pending-approvals">0</div>
                <div class="stat-label">Awaiting approval</div>
            </div>
            <div class="stat-card">
                <h3>This Month</h3>
                <div class="stat-number" id="monthly-activity">0</div>
                <div class="stat-label">New submissions</div>
            </div>
        </div>
        
        <div class="form-container">
            <h3>Quick Actions</h3>
            <div style="display: flex; gap: 15px; flex-wrap: wrap;">
                <button class="btn btn-primary" onclick="showSection('managers')">Add New Manager</button>
                <button class="btn btn-warning" onclick="showSection('leavers')">Process Leaver</button>
                <button class="btn btn-success" onclick="runEmployeeSync()">Sync Employee Data</button>
                <button class="btn btn-secondary" onclick="showSection('reports')">View Reports</button>
            </div>
        </div>
        
        <div class="form-container">
            <h3>Recent System Activity</h3>
            <div id="recent-activity">
                <p style="color: #6c757d;">Loading recent activity...</p>
            </div>
        </div>
    </div>

    <!-- User Management Section -->
    <div id="managers" class="content-section">
        <h2 style="margin-bottom: 20px; color: #2c3e50;">User Management</h2>
        
        <div class="form-container">
            <h3>Add New Manager/User</h3>
            <form id="user-form" onsubmit="saveUser(event)">
                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                <div class="form-grid">
                    <div class="form-group">
                        <label for="new-username">Username/Employee ID:</label>
                        <input type="text" id="new-username" name="username" required placeholder="e.g., 31661434" maxlength="50" pattern="[a-zA-Z0-9_]{3,50}">
                    </div>
                    <div class="form-group">
                        <label for="new-password">Temporary Password:</label>
                        <input type="password" id="new-password" name="password" required placeholder="Must change on first login" minlength="8" maxlength="255">
                    </div>
                    <div class="form-group">
                        <label for="new-firstname">First Name:</label>
                        <input type="text" id="new-firstname" name="firstname" required maxlength="100">
                    </div>
                    <div class="form-group">
                        <label for="new-lastname">Last Name:</label>
                        <input type="text" id="new-lastname" name="lastname" required maxlength="100">
                    </div>
                    <div class="form-group">
                        <label for="new-role">Role:</label>
                        <select id="new-role" name="role" required onchange="updateApprovalLevel()">
                            <option value="">Select Role</option>
                            <option value="supervisor">Supervisor</option>
                            <option value="manager">Manager</option>
                            <option value="admin">System Admin</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label for="new-approval-level">Approval Level:</label>
                        <select id="new-approval-level" name="approval_level" required>
                            <option value="">Select Level</option>
                            <option value="2">Level 2 - Supervisor (can approve employees)</option>
                            <option value="3">Level 3 - Manager (can approve employees & supervisors)</option>
                            <option value="4">Level 4 - Senior Manager (can approve all levels)</option>
                        </select>
                    </div>
                </div>
                <div style="text-align: center;">
                    <button type="submit" class="btn btn-success">Add User</button>
                    <button type="button" class="btn btn-secondary" onclick="clearForm()">Clear Form</button>
                </div>
            </form>
        </div>

        <div class="form-container">
            <h3>Current Users</h3>
            <div class="filter-row">
                <div class="filter-group">
                    <input type="text" id="user-search" class="search-bar" placeholder="Search users..." onkeyup="filterUsers()" maxlength="100">
                </div>
                <div class="filter-group">
                    <label>Filter by Role:</label>
                    <select id="role-filter" onchange="filterUsers()">
                        <option value="">All Roles</option>
                        <option value="admin">Admin</option>
                        <option value="manager">Manager</option>
                        <option value="supervisor">Supervisor</option>
                    </select>
                </div>
                <div class="filter-group">
                    <label>Filter by Level:</label>
                    <select id="level-filter" onchange="filterUsers()">
                        <option value="">All Levels</option>
                        <option value="4">Level 4</option>
                        <option value="3">Level 3</option>
                        <option value="2">Level 2</option>
                        <option value="1">Level 1</option>
                    </select>
                </div>
            </div>
            <div style="overflow-x: auto;">
                <table class="data-table" id="users-table">
                    <thead>
                        <tr>
                            <th>Username</th>
                            <th>Name</th>
                            <th>Role</th>
                            <th>Approval Level</th>
                            <th>Last Login</th>
                            <th>Status</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody id="users-table-body">
                        <tr><td colspan="7" style="text-align: center; padding: 20px;">Loading users...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- Leavers Section -->
    <div id="leavers" class="content-section">
        <h2 style="margin-bottom: 20px; color: #2c3e50;">Handle Leavers</h2>
        
        <div class="form-container">
            <h3>Process Employee Departure</h3>
            <form id="leaver-form" onsubmit="processLeaver(event)">
                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                <div class="form-grid">
                    <div class="form-group">
                        <label for="leaver-search">Search Employee:</label>
                        <input type="text" id="leaver-search" name="employee_search" placeholder="Enter username or name" onkeyup="searchEmployees()" maxlength="100">
                        <div id="employee-suggestions" style="background: white; border: 1px solid #ddd; max-height: 200px; overflow-y: auto; display: none;"></div>
                    </div>
                    <div class="form-group">
                        <label for="leaving-date">Last Working Day:</label>
                        <input type="date" id="leaving-date" name="leaving_date" required>
                    </div>
                    <div class="form-group">
                        <label for="leaver-reason">Reason for Leaving:</label>
                        <select id="leaver-reason" name="reason" required>
                            <option value="">Select Reason</option>
                            <option value="resignation">Resignation</option>
                            <option value="retirement">Retirement</option>
                            <option value="termination">Termination</option>
                            <option value="redundancy">Redundancy</option>
                            <option value="other">Other</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label for="handover-manager">Handover to Manager:</label>
                        <select id="handover-manager" name="handover_manager">
                            <option value="">Select Manager (optional)</option>
                        </select>
                    </div>
                </div>
                <div class="form-group">
                    <label for="leaver-notes">Additional Notes:</label>
                    <textarea id="leaver-notes" name="notes" rows="3" style="width: 100%; padding: 10px; border: 2px solid #dee2e6; border-radius: 6px;" placeholder="Any additional information about the departure..." maxlength="1000"></textarea>
                </div>
                <div style="text-align: center; margin-top: 20px;">
                    <button type="submit" class="btn btn-danger">Process Departure</button>
                    <button type="button" class="btn btn-secondary" onclick="clearLeaverForm()">Clear Form</button>
                </div>
            </form>
        </div>
        
        <div class="form-container">
            <h3>Recent Departures</h3>
            <div style="overflow-x: auto;">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Employee</th>
                            <th>Last Working Day</th>
                            <th>Reason</th>
                            <th>Processed By</th>
                            <th>Date Processed</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody id="leavers-table-body">
                        <tr><td colspan="6" style="text-align: center; padding: 20px;">Loading recent departures...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- Password Management Section -->
    <div id="passwords" class="content-section">
        <h2 style="margin-bottom: 20px; color: #2c3e50;">Password Management</h2>
        
        <div class="form-container">
            <h3>Reset User Password</h3>
            <form id="password-form" onsubmit="resetPassword(event)">
                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                <div class="form-grid">
                    <div class="form-group">
                        <label for="pwd-username">Select User:</label>
                        <select id="pwd-username" name="user_id" required>
                            <option value="">Choose user for password reset</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label for="new-temp-password">New Temporary Password:</label>
                        <input type="password" id="new-temp-password" name="new_password" required placeholder="User must change on next login" minlength="8" maxlength="255">
                    </div>
                </div>
                <div class="form-group">
                    <label>
                        <input type="checkbox" id="force-change" name="force_change" checked>
                        Force password change on next login
                    </label>
                </div>
                <div class="form-group">
                    <label for="reset-reason">Reason for Reset:</label>
                    <textarea id="reset-reason" name="reason" rows="2" style="width: 100%; padding: 10px; border: 2px solid #dee2e6; border-radius: 6px;" placeholder="Brief reason for password reset..." maxlength="500"></textarea>
                </div>
                <div style="text-align: center; margin-top: 20px;">
                    <button type="submit" class="btn btn-warning">Reset Password</button>
                    <button type="button" class="btn btn-secondary" onclick="clearPasswordForm()">Clear Form</button>
                </div>
            </form>
        </div>
        
        <div class="form-container">
            <h3>Password Reset History</h3>
            <div style="overflow-x: auto;">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Username</th>
                            <th>Reset Date</th>
                            <th>Reset By</th>
                            <th>Reason</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody id="password-history-body">
                        <tr><td colspan="5" style="text-align: center; padding: 20px;">Loading password reset history...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- Reports Section -->
    <div id="reports" class="content-section">
        <h2 style="margin-bottom: 20px; color: #2c3e50;">Reports & Analytics</h2>
        
        <div class="form-container">
            <h3>Generate Reports</h3>
            <form id="report-form" onsubmit="generateReport(event)">
                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                <div class="form-grid">
                    <div class="form-group">
                        <label for="report-type">Report Type:</label>
                        <select id="report-type" name="report_type">
                            <option value="approval-history">Approval History</option>
                            <option value="user-activity">User Activity Summary</option>
                            <option value="manager-workload">Manager Workload Analysis</option>
                            <option value="system-usage">System Usage Statistics</option>
                            <option value="compliance-audit">Compliance Audit Trail</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label for="report-period">Time Period:</label>
                        <select id="report-period" name="period">
                            <option value="7">Last 7 days</option>
                            <option value="30">Last 30 days</option>
                            <option value="90">Last 90 days</option>
                            <option value="365">Last 12 months</option>
                            <option value="custom">Custom Range</option>
                        </select>
                    </div>
                </div>
                <div id="custom-date-range" style="display: none;">
                    <div class="form-grid">
                        <div class="form-group">
                            <label for="start-date">Start Date:</label>
                            <input type="date" id="start-date" name="start_date">
                        </div>
                        <div class="form-group">
                            <label for="end-date">End Date:</label>
                            <input type="date" id="end-date" name="end_date">
                        </div>
                    </div>
                </div>
                <div style="text-align: center; margin-top: 20px;">
                    <button type="submit" class="btn btn-primary">Generate Report</button>
                    <button type="button" class="btn btn-success" onclick="exportReport()">Export to CSV</button>
                </div>
            </form>
        </div>
        
        <div class="report-container" id="report-results" style="display: none;">
            <div class="report-header">
                <h4 class="report-title" id="report-title">Report Results</h4>
                <span id="report-generated">Generated: <span id="report-timestamp"></span></span>
            </div>
            <div id="report-content"></div>
        </div>
    </div>

    <!-- Activity Log Section -->
    <div id="activity" class="content-section">
        <h2 style="margin-bottom: 20px; color: #2c3e50;">System Activity Log</h2>
        
        <div class="form-container">
            <h3>Filter Activity</h3>
            <div class="filter-row">
                <div class="filter-group">
                    <label>Activity Type:</label>
                    <select id="activity-filter">
                        <option value="">All Activities</option>
                        <option value="login">User Logins</option>
                        <option value="user_created">User Created</option>
                        <option value="user_modified">User Modified</option>
                        <option value="password_reset">Password Resets</option>
                        <option value="approval">Approvals</option>
                        <option value="system">System Events</option>
                    </select>
                </div>
                <div class="filter-group">
                    <label>Date Range:</label>
                    <select id="activity-period">
                        <option value="1">Today</option>
                        <option value="7">Last 7 days</option>
                        <option value="30">Last 30 days</option>
                        <option value="90">Last 90 days</option>
                    </select>
                </div>
                <div class="filter-group">
                    <button class="btn btn-primary" onclick="loadActivityLog()">Apply Filters</button>
                </div>
            </div>
        </div>
        
        <div class="form-container">
            <h3>Recent Activity</h3>
            <div id="activity-log">
                <p style="color: #6c757d;">Loading activity log...</p>
            </div>
        </div>
    </div>
</div>

<!-- Edit User Modal -->
<div id="edit-modal" class="modal">
    <div class="modal-content">
        <div class="modal-header">
            <h3 class="modal-title">Edit User</h3>
            <button class="close-btn" onclick="closeEditModal()">&times;</button>
        </div>
        <form id="edit-form" onsubmit="updateUser(event)">
            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
            <input type="hidden" id="edit-user-id" name="user_id">
            <div class="form-group">
                <label for="edit-username">Username:</label>
                <input type="text" id="edit-username" name="username" readonly style="background: #f8f9fa;">
            </div>
            <div class="form-group">
                <label for="edit-firstname">First Name:</label>
                <input type="text" id="edit-firstname" name="firstname" required maxlength="100">
            </div>
            <div class="form-group">
                <label for="edit-lastname">Last Name:</label>
                <input type="text" id="edit-lastname" name="lastname" required maxlength="100">
            </div>
            <div class="form-group">
                <label for="edit-role">Role:</label>
                <select id="edit-role" name="role" required>
                    <option value="supervisor">Supervisor</option>
                    <option value="manager">Manager</option>
                    <option value="admin">Admin</option>
                </select>
            </div>
            <div class="form-group">
                <label for="edit-approval-level">Approval Level:</label>
                <select id="edit-approval-level" name="approval_level" required>
                    <option value="2">Level 2 - Supervisor</option>
                    <option value="3">Level 3 - Manager</option>
                    <option value="4">Level 4 - Senior Manager</option>
                </select>
            </div>
            <div style="text-align: center; margin-top: 20px;">
                <button type="submit" class="btn btn-success">Update User</button>
                <button type="button" class="btn btn-secondary" onclick="closeEditModal()">Cancel</button>
            </div>
        </form>
    </div>
</div>

<script>
// Global variables
let currentAdmin = null;
let allUsers = [];
let allEmployees = [];

// API Configuration
const API_URL = 'admin_api.php';

// CSRF Token for AJAX requests
const CSRF_TOKEN = '<?php echo $_SESSION['csrf_token']; ?>';

// Input validation functions
function validateInput(value, type, minLength = 1, maxLength = 255) {
    if (!value || value.length < minLength || value.length > maxLength) {
        return false;
    }
    
    switch(type) {
        case 'username':
            return /^[a-zA-Z0-9_]{3,50}$/.test(value);
        case 'email':
            return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
        case 'name':
            return /^[a-zA-Z\s-']{1,100}$/.test(value);
        default:
            return true;
    }
}

function sanitizeInput(input) {
    const div = document.createElement('div');
    div.textContent = input;
    return div.innerHTML;
}

// Enhanced fetch function with CSRF protection
async function secureRequest(url, data) {
    if (!data.csrf_token) {
        data.csrf_token = CSRF_TOKEN;
    }
    
    try {
        const response = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            },
            credentials: 'same-origin',
            body: JSON.stringify(data)
        });
        
        if (!response.ok) {
            throw new Error('Network response was not ok');
        }
        
        return await response.json();
    } catch (error) {
        console.error('Request error:', error);
        throw error;
    }
}

// Authentication
async function loginAdmin() {
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    
    // Client-side validation
    if (!validateInput(username, 'username')) {
        showError('Invalid username format');
        return;
    }
    
    if (!password || password.length < 8) {
        showError('Password must be at least 8 characters');
        return;
    }
    
    try {
        const data = await secureRequest(API_URL, {
            action: 'admin_login',
            username: sanitizeInput(username),
            password: password
        });
        
        if (data.success) {
            currentAdmin = data.user;
            document.getElementById('login-modal').style.display = 'none';
            document.getElementById('main-container').style.display = 'block';
            document.getElementById('current-admin').innerText = `Welcome, ${data.user.firstName} ${data.user.lastName}`;
            
            // Load initial data
            loadDashboardStats();
            loadUsers();
            loadActivityLog();
        } else {
            showError(data.error || 'Login failed');
        }
    } catch (error) {
        console.error('Login error:', error);
        showError('Connection error');
    }
}

function showError(message) {
    const errorDiv = document.getElementById('login-error');
    errorDiv.style.display = 'block';
    errorDiv.innerText = message;
    setTimeout(() => {
        errorDiv.style.display = 'none';
    }, 5000);
}

function logout() {
    currentAdmin = null;
    document.getElementById('main-container').style.display = 'none';
    document.getElementById('login-modal').style.display = 'flex';
    document.getElementById('username').value = '';
    document.getElementById('password').value = '';
    allUsers = [];
    allEmployees = [];
}

// Navigation
function showSection(sectionName) {
    // Hide all sections
    document.querySelectorAll('.content-section').forEach(section => {
        section.classList.remove('active');
    });
    
    // Remove active class from all nav buttons
    document.querySelectorAll('.nav-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    
    // Show selected section
    document.getElementById(sectionName).classList.add('active');
    
    // Add active class to clicked button
    event.target.classList.add('active');
    
    // Load section-specific data
    switch(sectionName) {
        case 'dashboard':
            loadDashboardStats();
            break;
        case 'managers':
            loadUsers();
            break;
        case 'leavers':
            loadRecentLeavers();
            break;
        case 'passwords':
            loadPasswordHistory();
            loadUsersForPasswordReset();
            break;
        case 'reports':
            // Reports loaded on demand
            break;
        case 'activity':
            loadActivityLog();
            break;
    }
}

// Dashboard functions
async function loadDashboardStats() {
    try {
        const data = await secureRequest(API_URL, { action: 'get_user_stats' });
        
        if (data.success) {
            document.getElementById('total-users').innerText = data.stats.total_users || 0;
            document.getElementById('total-managers').innerText = data.stats.managers || 0;
            document.getElementById('pending-approvals').innerText = data.stats.pending_approvals || 0;
            document.getElementById('monthly-activity').innerText = data.stats.monthly_submissions || 0;
        }
    } catch (error) {
        console.error('Stats error:', error);
    }
}

// User management functions
async function loadUsers() {
    try {
        const data = await secureRequest(API_URL, { action: 'get_all_users' });
        
        if (data.success) {
            allUsers = data.users;
            displayUsersTable(data.users);
        }
    } catch (error) {
        console.error('Load users error:', error);
    }
}

function displayUsersTable(users) {
    const tbody = document.getElementById('users-table-body');
    tbody.innerHTML = '';
    
    if (!users || users.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: #6c757d;">No users found</td></tr>';
        return;
    }
    
    users.forEach(user => {
        const row = document.createElement('tr');
        const lastLogin = user.last_login_date ? new Date(user.last_login_date).toLocaleDateString() : 'Never';
        const status = user.status || 'Active';
        
        row.innerHTML = `
            <td><strong>${sanitizeInput(user.username)}</strong></td>
            <td>${sanitizeInput(user.first_name || '')} ${sanitizeInput(user.last_name || '')}</td>
            <td><span class="role-badge role-${user.role}">${sanitizeInput(user.role)}</span></td>
            <td><span class="level-badge level-${user.approval_level}">Level ${user.approval_level}</span></td>
            <td>${lastLogin}</td>
            <td><span class="text-${status === 'Active' ? 'success' : 'danger'}">${sanitizeInput(status)}</span></td>
            <td>
                <button class="btn btn-warning" onclick="editUser(${user.id})">Edit</button>
                <button class="btn btn-danger" onclick="deleteUser(${user.id}, '${sanitizeInput(user.username)}')">Disable</button>
            </td>
        `;
        tbody.appendChild(row);
    });
}

function filterUsers() {
    const searchTerm = document.getElementById('user-search').value.toLowerCase();
    const roleFilter = document.getElementById('role-filter').value;
    const levelFilter = document.getElementById('level-filter').value;
    
    const filteredUsers = allUsers.filter(user => {
        const matchesSearch = !searchTerm || 
            user.username.toLowerCase().includes(searchTerm) ||
            (user.first_name && user.first_name.toLowerCase().includes(searchTerm)) ||
            (user.last_name && user.last_name.toLowerCase().includes(searchTerm));
            
        const matchesRole = !roleFilter || user.role === roleFilter;
        const matchesLevel = !levelFilter || user.approval_level == levelFilter;
        
        return matchesSearch && matchesRole && matchesLevel;
    });
    
    displayUsersTable(filteredUsers);
}

async function saveUser(event) {
    event.preventDefault();
    
    const formData = new FormData(event.target);
    const userData = {
        action: 'add_user',
        csrf_token: formData.get('csrf_token'),
        username: formData.get('username'),
        password: formData.get('password'),
        firstName: formData.get('firstname'),
        lastName: formData.get('lastname'),
        role: formData.get('role'),
        approvalLevel: formData.get('approval_level')
    };
    
    // Client-side validation
    if (!validateInput(userData.username, 'username')) {
        alert('Invalid username format. Use only letters, numbers, and underscores (3-50 characters)');
        return;
    }
    
    if (!validateInput(userData.firstName, 'name', 1, 100)) {
        alert('Invalid first name');
        return;
    }
    
    if (!validateInput(userData.lastName, 'name', 1, 100)) {
        alert('Invalid last name');
        return;
    }
    
    if (userData.password.length < 8) {
        alert('Password must be at least 8 characters');
        return;
    }
    
    try {
        const data = await secureRequest(API_URL, userData);
        
        if (data.success) {
            alert('User added successfully!');
            clearForm();
            loadUsers();
            loadDashboardStats();
        } else {
            alert('Error adding user: ' + (data.error || 'Unknown error'));
        }
    } catch (error) {
        console.error('Save user error:', error);
        alert('Connection error while adding user');
    }
}

function clearForm() {
    document.getElementById('user-form').reset();
}

function updateApprovalLevel() {
    const role = document.getElementById('new-role').value;
    const levelSelect = document.getElementById('new-approval-level');
    
    // Auto-suggest approval level based on role
    if (role === 'supervisor') {
        levelSelect.value = '2';
    } else if (role === 'manager') {
        levelSelect.value = '3';
    } else if (role === 'admin') {
        levelSelect.value = '4';
    }
}

// Leavers functions
async function processLeaver(event) {
    event.preventDefault();
    
    const formData = new FormData(event.target);
    const leaverData = {
        action: 'process_leaver',
        csrf_token: formData.get('csrf_token'),
        employee_search: formData.get('employee_search'),
        leaving_date: formData.get('leaving_date'),
        reason: formData.get('reason'),
        handover_manager: formData.get('handover_manager'),
        notes: formData.get('notes')
    };
    
    try {
        const data = await secureRequest(API_URL, leaverData);
        
        if (data.success) {
            alert('Employee departure processed successfully!');
            clearLeaverForm();
            loadRecentLeavers();
        } else {
            alert('Error processing departure: ' + (data.error || 'Unknown error'));
        }
    } catch (error) {
        console.error('Process leaver error:', error);
        alert('Connection error while processing departure');
    }
}

function clearLeaverForm() {
    document.getElementById('leaver-form').reset();
}

async function loadRecentLeavers() {
    try {
        const data = await secureRequest(API_URL, { action: 'get_recent_leavers' });
        
        const tbody = document.getElementById('leavers-table-body');
        if (data.success && data.leavers && data.leavers.length > 0) {
            tbody.innerHTML = '';
            data.leavers.forEach(leaver => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${sanitizeInput(leaver.employee_name)}</td>
                    <td>${leaver.leaving_date}</td>
                    <td>${sanitizeInput(leaver.reason)}</td>
                    <td>${sanitizeInput(leaver.processed_by)}</td>
                    <td>${leaver.date_processed}</td>
                    <td>${sanitizeInput(leaver.status)}</td>
                `;
                tbody.appendChild(row);
            });
        } else {
            tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: #6c757d;">No recent departures</td></tr>';
        }
    } catch (error) {
        console.error('Load leavers error:', error);
    }
}

// Password management functions
async function resetPassword(event) {
    event.preventDefault();
    
    const formData = new FormData(event.target);
    const passwordData = {
        action: 'reset_password',
        csrf_token: formData.get('csrf_token'),
        user_id: formData.get('user_id'),
        new_password: formData.get('new_password'),
        force_change: formData.get('force_change') ? 1 : 0,
        reason: formData.get('reason')
    };
    
    if (passwordData.new_password.length < 8) {
        alert('New password must be at least 8 characters');
        return;
    }
    
    try {
        const data = await secureRequest(API_URL, passwordData);
        
        if (data.success) {
            alert('Password reset successfully!');
            clearPasswordForm();
            loadPasswordHistory();
        } else {
            alert('Error resetting password: ' + (data.error || 'Unknown error'));
        }
    } catch (error) {
        console.error('Password reset error:', error);
        alert('Connection error while resetting password');
    }
}

function clearPasswordForm() {
    document.getElementById('password-form').reset();
}

async function loadPasswordHistory() {
    try {
        const data = await secureRequest(API_URL, { action: 'get_password_history' });
        
        const tbody = document.getElementById('password-history-body');
        if (data.success && data.history && data.history.length > 0) {
            tbody.innerHTML = '';
            data.history.forEach(record => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td>${sanitizeInput(record.username)}</td>
                    <td>${record.reset_date}</td>
                    <td>${sanitizeInput(record.reset_by)}</td>
                    <td>${sanitizeInput(record.reason || 'N/A')}</td>
                    <td>${sanitizeInput(record.status)}</td>
                `;
                tbody.appendChild(row);
            });
        } else {
            tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: #6c757d;">No password resets recorded</td></tr>';
        }
    } catch (error) {
        console.error('Load password history error:', error);
    }
}

async function loadUsersForPasswordReset() {
    // Populate password reset dropdown with users
    const select = document.getElementById('pwd-username');
    select.innerHTML = '<option value="">Choose user for password reset</option>';
    
    allUsers.forEach(user => {
        const option = document.createElement('option');
        option.value = user.id;
        option.textContent = `${sanitizeInput(user.username)} - ${sanitizeInput(user.first_name)} ${sanitizeInput(user.last_name)}`;
        select.appendChild(option);
    });
}

// Reports functions
async function generateReport(event) {
    if (event) event.preventDefault();
    
    const reportType = document.getElementById('report-type').value;
    const period = document.getElementById('report-period').value;
    
    // Show loading
    document.getElementById('report-results').style.display = 'block';
    document.getElementById('report-content').innerHTML = '<p>Generating report...</p>';
    
    try {
        const data = await secureRequest(API_URL, {
            action: 'generate_report',
            reportType: reportType,
            period: period,
            start_date: document.getElementById('start-date').value,
            end_date: document.getElementById('end-date').value
        });
        
        if (data.success) {
            displayReport(data.report, reportType);
        } else {
            document.getElementById('report-content').innerHTML = 
                '<p style="color: #dc3545;">Error generating report: ' + sanitizeInput(data.error || 'Unknown error') + '</p>';
        }
    } catch (error) {
        console.error('Report error:', error);
        document.getElementById('report-content').innerHTML = 
            '<p style="color: #dc3545;">Connection error while generating report</p>';
    }
}

function displayReport(reportData, reportType) {
    const container = document.getElementById('report-content');
    document.getElementById('report-timestamp').innerText = new Date().toLocaleString();
    
    switch(reportType) {
        case 'approval-history':
            document.getElementById('report-title').innerText = 'Approval History Report';
            container.innerHTML = `
                <div class="stats-grid">
                    <div class="stat-card">
                        <h3>Total Approvals</h3>
                        <div class="stat-number">${reportData.total_approvals || 0}</div>
                    </div>
                    <div class="stat-card">
                        <h3>Average Processing Time</h3>
                        <div class="stat-number">${reportData.avg_processing_time || '0'}</div>
                        <div class="stat-label">hours</div>
                    </div>
                </div>
            `;
            break;
        default:
            container.innerHTML = '<p>Report data: ' + sanitizeInput(JSON.stringify(reportData)) + '</p>';
    }
}

function exportReport() {
    alert('Export functionality would be implemented here');
}

// Activity log functions
async function loadActivityLog() {
    try {
        const data = await secureRequest(API_URL, { 
            action: 'get_activity_log',
            activity_type: document.getElementById('activity-filter').value,
            period: document.getElementById('activity-period').value
        });
        
        const container = document.getElementById('activity-log');
        if (data.success && data.activities && data.activities.length > 0) {
            container.innerHTML = '';
            data.activities.forEach(activity => {
                const activityDiv = document.createElement('div');
                activityDiv.className = 'activity-item';
                activityDiv.innerHTML = `
                    <div class="activity-date">${activity.date}</div>
                    <div class="activity-action">${sanitizeInput(activity.action)}</div>
                    <div class="activity-details">${sanitizeInput(activity.details)}</div>
                `;
                container.appendChild(activityDiv);
            });
        } else {
            container.innerHTML = `
                <div class="activity-item">
                    <div class="activity-date">Today, 14:30</div>
                    <div class="activity-action">User Login</div>
                    <div class="activity-details">Admin user 'admin' logged into the system</div>
                </div>
                <div class="activity-item">
                    <div class="activity-date">Today, 09:15</div>
                    <div class="activity-action">User Created</div>
                    <div class="activity-details">New manager 'john.smith' added to the system</div>
                </div>
            `;
        }
    } catch (error) {
        console.error('Activity log error:', error);
    }
}

// Utility functions
async function runEmployeeSync() {
    if (confirm('This will sync employee data from the timesheets table. Continue?')) {
        try {
            const data = await secureRequest(API_URL, { action: 'sync_employees' });
            
            if (data.success) {
                alert(`Employee sync completed. ${data.synced_count} employees synced.`);
                loadDashboardStats();
            } else {
                alert('Error syncing employees: ' + (data.error || 'Unknown error'));
            }
        } catch (error) {
            console.error('Sync error:', error);
            alert('Connection error during sync');
        }
    }
}

// Edit and delete functions
function editUser(userId) {
    const user = allUsers.find(u => u.id == userId);
    if (!user) return;
    
    document.getElementById('edit-user-id').value = user.id;
    document.getElementById('edit-username').value = user.username;
    document.getElementById('edit-firstname').value = user.first_name || '';
    document.getElementById('edit-lastname').value = user.last_name || '';
    document.getElementById('edit-role').value = user.role;
    document.getElementById('edit-approval-level').value = user.approval_level;
    
    document.getElementById('edit-modal').style.display = 'flex';
}

function closeEditModal() {
    document.getElementById('edit-modal').style.display = 'none';
}

async function updateUser(event) {
    event.preventDefault();
    
    const formData = new FormData(event.target);
    const userData = {
        action: 'update_user',
        csrf_token: formData.get('csrf_token'),
        user_id: formData.get('user_id'),
        firstName: formData.get('firstname'),
        lastName: formData.get('lastname'),
        role: formData.get('role'),
        approvalLevel: formData.get('approval_level')
    };
    
    try {
        const data = await secureRequest(API_URL, userData);
        
        if (data.success) {
            alert('User updated successfully!');
            closeEditModal();
            loadUsers();
        } else {
            alert('Error updating user: ' + (data.error || 'Unknown error'));
        }
    } catch (error) {
        console.error('Update user error:', error);
        alert('Connection error while updating user');
    }
}

async function deleteUser(userId, username) {
    if (confirm(`Are you sure you want to disable user '${username}'? This action can be reversed.`)) {
        try {
            const data = await secureRequest(API_URL, {
                action: 'disable_user',
                user_id: userId
            });
            
            if (data.success) {
                alert('User disabled successfully!');
                loadUsers();
                loadDashboardStats();
            } else {
                alert('Error disabling user: ' + (data.error || 'Unknown error'));
            }
        } catch (error) {
            console.error('Delete user error:', error);
            alert('Connection error while disabling user');
        }
    }
}

function searchEmployees() {
    const searchTerm = document.getElementById('leaver-search').value;
    if (searchTerm.length < 2) {
        document.getElementById('employee-suggestions').style.display = 'none';
        return;
    }
    
    // This would typically search the database
    // For now, just hide the suggestions
    document.getElementById('employee-suggestions').style.display = 'none';
}

// Event listeners
document.addEventListener('DOMContentLoaded', function() {
    // Login form event listener
    document.getElementById('login-form').addEventListener('submit', function(e) {
        e.preventDefault();
        loginAdmin();
    });
    
    document.getElementById('username').addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            e.preventDefault();
            loginAdmin();
        }
    });
    
    document.getElementById('password').addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            e.preventDefault();
            loginAdmin();
        }
    });
    
    document.getElementById('report-period').addEventListener('change', function() {
        const customRange = document.getElementById('custom-date-range');
        customRange.style.display = this.value === 'custom' ? 'block' : 'none';
    });
    
    // Input sanitization for search fields
    document.getElementById('user-search').addEventListener('input', function() {
        this.value = this.value.replace(/[<>'"]/g, '');
    });
    
    document.getElementById('leaver-search').addEventListener('input', function() {
        this.value = this.value.replace(/[<>'"]/g, '');
    });
});
</script>
</body>
</html>