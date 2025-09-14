<?php
// NHS Security Headers
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Content-Security-Policy: default-src \'self\'; script-src \'self\' \'unsafe-inline\'; style-src \'self\' \'unsafe-inline\'; img-src \'self\' data:;');

// NHS Session Management
session_start();
session_regenerate_id(true);

// Set session timeout
$timeout_minutes = 30;
if (isset($_SESSION['last_activity'])) {
    $inactive_time = time() - $_SESSION['last_activity'];
    if ($inactive_time > ($timeout_minutes * 60)) {
        session_destroy();
        // Redirect to prevent session fixation
        header("Location: " . $_SERVER['PHP_SELF']);
        exit;
    }
}
$_SESSION['last_activity'] = time();

// Basic audit logging for landing page access
function logPageAccess() {
    $log_entry = [
        'timestamp' => date('Y-m-d H:i:s'),
        'ip_address' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown',
        'page' => 'landing_page',
        'action' => 'page_access'
    ];
    
    // Log to file (ensure this directory exists and is writable)
    $log_file = '/var/log/nhs_timesheet/access.log';
    if (is_writable(dirname($log_file))) {
        file_put_contents($log_file, json_encode($log_entry) . "\n", FILE_APPEND | LOCK_EX);
    }
}

// Log the page access
logPageAccess();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NHS Timesheet System - Login</title>
    <meta name="description" content="NHS Timesheet Management System - Secure employee timesheet submission and approval platform">
    <meta name="robots" content="noindex, nofollow">
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
            background-color: #f8f9fa;
        }
        .header {
            background-color: #005eb8;
            color: white;
            padding: 20px;
            text-align: center;
        }
        .security-badge {
            display: inline-block;
            background: rgba(255,255,255,0.2);
            padding: 5px 10px;
            border-radius: 15px;
            font-size: 12px;
            margin-top: 10px;
        }
        .container {
            max-width: 1400px;
            margin: 50px auto;
            padding: 30px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .login-section {
            display: flex;
            gap: 30px;
            margin-top: 30px;
        }
        .login-card {
            flex: 1;
            padding: 30px;
            background: #f0f4f8;
            border-radius: 8px;
            text-align: center;
            border: 2px solid #e1e5e9;
            transition: all 0.3s;
            position: relative;
        }
        .login-card:hover {
            border-color: #005eb8;
            transform: translateY(-5px);
        }
        .login-card.admin {
            background: #fff5f5;
            border-color: #dc3545;
        }
        .login-card.admin:hover {
            border-color: #c82333;
        }
        .login-btn {
            background-color: #005eb8;
            color: white;
            padding: 15px 30px;
            border: none;
            border-radius: 5px;
            font-size: 16px;
            cursor: pointer;
            text-decoration: none;
            display: inline-block;
            margin-top: 15px;
            transition: background-color 0.3s;
        }
        .login-btn:hover {
            background-color: #004494;
        }
        .login-btn.admin {
            background-color: #dc3545;
        }
        .login-btn.admin:hover {
            background-color: #c82333;
        }
        .security-notice {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 5px;
            padding: 15px;
            margin-top: 30px;
            text-align: center;
            color: #856404;
        }
        .compliance-notice {
            background: #e8f4fd;
            border: 1px solid #bee5eb;
            border-radius: 5px;
            padding: 15px;
            margin-top: 20px;
            text-align: center;
            color: #0c5460;
        }
        .session-info {
            position: fixed;
            top: 10px;
            right: 10px;
            background: rgba(0,0,0,0.8);
            color: white;
            padding: 8px 12px;
            border-radius: 5px;
            font-size: 12px;
            z-index: 1000;
        }
        .security-features {
            margin-top: 20px;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 5px;
            border-left: 4px solid #005eb8;
        }
        .security-features h4 {
            margin-top: 0;
            color: #005eb8;
        }
        .security-features ul {
            margin: 10px 0;
            padding-left: 20px;
        }
        .security-features li {
            margin: 5px 0;
            font-size: 14px;
        }
        @media (max-width: 1200px) {
            .login-section {
                display: grid;
                grid-template-columns: repeat(2, 1fr);
                gap: 20px;
            }
        }
        @media (max-width: 768px) {
            .login-section {
                grid-template-columns: 1fr;
            }
            .container {
                max-width: 90%;
                padding: 20px;
            }
            .session-info {
                position: static;
                margin-bottom: 20px;
                text-align: center;
            }
        }
    </style>
</head>
<body>
    <!-- Session timeout indicator -->
    <div class="session-info" id="sessionInfo">
        Session timeout: <?php echo $timeout_minutes; ?> minutes
    </div>

    <div class="header">
        <h1>NHS Timesheet Management System</h1>
        <p>Secure timesheet submission and approval platform</p>
        <div class="security-badge">
            🔒 NHS Data Protection Compliant
        </div>
    </div>
    
    <div class="container">
        <h2>Welcome to the NHS Timesheet System</h2>
        <p>Please select your login type to access the appropriate timesheet management tools.</p>
        
        <div class="login-section">
            <div class="login-card">
                <h3>Employee Access</h3>
                <p>Submit your timesheets, view submission history, and track approval status.</p>
                <a href="employee.html" class="login-btn">Employee Login</a>
                <div style="margin-top: 10px; font-size: 12px; color: #666;">
                    Access: Personal timesheet data only
                </div>
            </div>
            
            <div class="login-card">
                <h3>Manager Access</h3>
                <p>Review and approve employee timesheets, generate reports, and manage approvals.</p>
                <a href="manager.html" class="login-btn">Manager Login</a>
                <div style="margin-top: 10px; font-size: 12px; color: #666;">
                    Access: Team timesheet approval
                </div>
            </div>
            
            <div class="login-card">
                <h3>Absence Management</h3>
                <p>Manage absence tracking for your department and update employee absence records.</p>
                <a href="absence.html" class="login-btn">Absence Login</a>
                <div style="margin-top: 10px; font-size: 12px; color: #666;">
                    Access: Departmental absence data
                </div>
            </div>
            
            <div class="login-card admin">
                <h3>Admin Access</h3>
                <p>System administration, user management, and approval hierarchy configuration.</p>
                <a href="admin_portal.html" class="login-btn admin">Admin Login</a>
                <div style="margin-top: 10px; font-size: 12px; color: #666;">
                    Access: Full system administration
                </div>
            </div>
        </div>
        
        <div class="security-notice">
            <strong>Security Notice:</strong> All access is logged and monitored. Use only the portal appropriate for your role. 
            Sessions automatically expire after <?php echo $timeout_minutes; ?> minutes of inactivity. Contact IT support if you need access to multiple portals.
        </div>

        <div class="compliance-notice">
            <strong>NHS Data Protection:</strong> This system complies with NHS data protection requirements. 
            All personal data access is logged and audited. Users are responsible for protecting their login credentials.
        </div>

        <div class="security-features">
            <h4>Security Features</h4>
            <ul>
                <li>🔐 Role-based access control with pay grade filtering</li>
                <li>📊 Comprehensive audit logging of all data access</li>
                <li>⏱️ Automatic session timeout (<?php echo $timeout_minutes; ?> minutes)</li>
                <li>🛡️ Security headers protecting against common attacks</li>
                <li>🔒 Personal data isolation - users only see authorized data</li>
                <li>📝 Complete modification tracking and approval workflows</li>
                <li>🔍 Account lockout protection against brute force attacks</li>
                <li>📋 NHS compliance audit trail for all activities</li>
            </ul>
        </div>
    </div>

    <script>
        // Session timeout warning
        let sessionTimeout = <?php echo $timeout_minutes * 60; ?>; // Convert to seconds
        let warningTime = sessionTimeout - 300; // Warn 5 minutes before timeout
        let lastActivity = Date.now();

        function updateActivity() {
            lastActivity = Date.now();
        }

        function checkSession() {
            let elapsed = (Date.now() - lastActivity) / 1000;
            let remaining = sessionTimeout - elapsed;
            
            if (remaining <= 0) {
                alert('Your session has expired for security reasons. Please refresh the page to continue.');
                window.location.reload();
                return;
            }
            
            if (remaining <= 300 && remaining > 0) { // Last 5 minutes
                let minutes = Math.floor(remaining / 60);
                let seconds = Math.floor(remaining % 60);
                document.getElementById('sessionInfo').innerHTML = 
                    `⚠️ Session expires in ${minutes}:${seconds.toString().padStart(2, '0')}`;
                document.getElementById('sessionInfo').style.background = 'rgba(220, 53, 69, 0.9)';
            }
        }

        // Track user activity
        ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart', 'click'].forEach(function(event) {
            document.addEventListener(event, updateActivity, true);
        });

        // Check session every 30 seconds
        setInterval(checkSession, 30000);
        
        // Prevent right-click context menu for security
        document.addEventListener('contextmenu', function(e) {
            e.preventDefault();
        });
        
        // Clear sensitive data on page unload
        window.addEventListener('beforeunload', function() {
            // Clear any sensitive data from memory
            if (typeof sessionStorage !== 'undefined') {
                sessionStorage.clear();
            }
        });
    </script>
</body>
</html>