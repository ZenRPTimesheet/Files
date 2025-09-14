<?php
// NHS Security Headers
header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Content-Security-Policy: default-src \'self\'; script-src \'self\' \'unsafe-inline\'; style-src \'self\' \'unsafe-inline\';');

// NHS Session Management
session_start();
session_regenerate_id(true);
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NHS Absence Management Portal</title>
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
    
    /* Password Reset */
    .forgot-password {text-align:center;margin-top:15px;}
    .forgot-password a {color:#007bff;text-decoration:none;font-size:14px;}
    .forgot-password a:hover {text-decoration:underline;}
    .reset-form {background:white;padding:30px;border-radius:15px;max-width:400px;width:90%;box-shadow:0 20px 40px rgba(0,0,0,0.3);}
    .success {color:#28a745;margin-bottom:10px;text-align:center;padding:10px;background:#d4edda;border-radius:5px;}
    
    /* Navigation Tabs */
    .nav-tabs {
        background: #f8f9fa;
        padding: 0 30px;
        border-bottom: 1px solid #dee2e6;
    }
    .nav-tabs ul {
        list-style: none;
        display: flex;
        margin: 0;
        padding: 0;
    }
    .nav-tabs li {
        margin-right: 2px;
    }
    .nav-tabs button {
        background: none;
        border: none;
        padding: 15px 25px;
        cursor: pointer;
        font-weight: 600;
        color: #6c757d;
        border-bottom: 3px solid transparent;
        transition: all 0.3s;
    }
    .nav-tabs button.active {
        color: #007bff;
        border-bottom-color: #007bff;
        background: white;
    }
    .nav-tabs button:hover {
        color: #0056b3;
        background: #f8f9fa;
    }
    
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
    .filter-group select, .filter-group input {
        padding: 8px 12px;
        border: 2px solid #dee2e6;
        border-radius: 6px;
        background: white;
        font-size: 14px;
        color: #495057;
        cursor: pointer;
    }
    .filter-group select:focus, .filter-group input:focus {
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
    
    /* Summary Cards */
    .summary-section {
        padding: 20px 30px;
        background: #f8f9fa;
        border-bottom: 1px solid #dee2e6;
    }
    .summary-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 20px;
    }
    .summary-card {
        background: white;
        padding: 20px;
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        text-align: center;
        border-top: 4px solid #007bff;
    }
    .summary-card.sick { border-top-color: #dc3545; }
    .summary-card.maternity { border-top-color: #28a745; }
    .summary-card.bereavement { border-top-color: #6c757d; }
    .summary-card.study { border-top-color: #fd7e14; }
    .summary-card.unpaid { border-top-color: #e83e8c; }
    .summary-card h3 {
        font-size: 24px;
        font-weight: bold;
        color: #2c3e50;
        margin-bottom: 5px;
    }
    .summary-card p {
        color: #6c757d;
        font-size: 14px;
        margin: 0;
    }
    
    /* Tables */
    .main-table { width:100%; border-collapse: collapse; margin-top:20px; font-size: 14px; }
    .main-table th, .main-table td { border:1px solid #e9ecef; padding:12px; text-align:center; }
    .main-table th { background:#343a40; color:white; font-weight: 600; }
    .main-table tr:hover { background:#f8f9fa; }
    
    /* Mobile Card Layout */
    .absence-card {
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
    
    /* Status and other elements */
    .absence-badge { 
        padding: 4px 12px; 
        border-radius: 20px; 
        font-size: 12px; 
        font-weight: 600; 
        text-transform: uppercase; 
        letter-spacing: 0.5px;
    }
    .absence-sick { background: #ffebee; color: #c62828; }
    .absence-maternity { background: #e8f5e8; color: #2e7d32; }
    .absence-bereavement { background: #f5f5f5; color: #424242; }
    .absence-study { background: #fff3e0; color: #f57c00; }
    .absence-unpaid { background: #fce4ec; color: #ad1457; }
    .absence-other { background: #e3f2fd; color: #1976d2; }
    
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
    .btn-export { background:#fd7e14; color:white; }
    .btn-export:hover { background:#e56b00; }
    
    /* Layout */
    .content-section { padding: 20px 30px; }
    .section-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
    .section-title { font-size: 24px; font-weight: 600; color: #2c3e50; }
    
    /* Table container */
    .table-container { overflow-x: auto; margin: 0 -30px; padding: 0 30px; }
    
    .hidden { display: none !important; }
    .tab-content { display: none; }
    .tab-content.active { display: block; }
    
    /* Charts placeholder */
    .chart-container {
        background: white;
        border-radius: 8px;
        padding: 20px;
        margin: 20px 0;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        min-height: 300px;
        display: flex;
        align-items: center;
        justify-content: center;
        color: #6c757d;
        font-style: italic;
    }
    
    /* Mobile Responsive Styles */
    @media (max-width: 768px) {
        body { padding: 10px; }
        
        .header { 
            padding: 15px 20px; 
            flex-direction: column;
            gap: 10px;
        }
        .header h1 { font-size: 20px; }
        
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
        
        .section-header {
            flex-direction: column;
            gap: 15px;
            text-align: center;
        }
        
        .section-title { font-size: 18px; }
        
        .summary-grid {
            grid-template-columns: 1fr;
            gap: 15px;
        }
        
        /* Hide desktop tables on mobile */
        .main-table { display: none; }
        
        /* Show mobile cards */
        .absence-card { display: block; }
        
        /* Navigation tabs */
        .nav-tabs ul {
            flex-wrap: wrap;
        }
        .nav-tabs button {
            flex: 1;
            min-width: 120px;
            padding: 12px 15px;
            font-size: 14px;
        }
        
        .login-form {
            padding: 30px 20px;
        }
        
        .login-form input {
            font-size: 16px;
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
        
        .summary-card {
            padding: 15px;
        }
    }
</style>
</head>
<body>

<!-- Login Modal -->
<div id="login-modal" class="login-modal">
    <div class="login-form">
        <h2>NHS Absence Management Login</h2>
        <div id="login-error" class="error" style="display:none;"></div>
        <input type="text" id="username" placeholder="Username" required>
        <input type="password" id="password" placeholder="Password" required>
        <button onclick="loginUser()">Sign In</button>
        <div class="forgot-password">
            <a href="#" onclick="showPasswordReset()">Forgot Password?</a>
        </div>
    </div>
</div>

<!-- Password Reset Modal -->
<div id="reset-modal" class="login-modal" style="display:none;">
    <div class="reset-form">
        <h2>Reset Password</h2>
        <div id="reset-error" class="error" style="display:none;"></div>
        <div id="reset-success" class="success" style="display:none;"></div>
        <input type="email" id="reset-email" placeholder="Enter your email address" required>
        <button onclick="sendPasswordReset()">Send Reset Link</button>
        <div style="text-align:center;margin-top:15px;">
            <a href="#" onclick="showLogin()">Back to Login</a>
        </div>
    </div>
</div>

<!-- Main Container -->
<div class="container" id="main-container" style="display:none;">
    <div class="header">
        <h1>NHS Absence Management Portal</h1>
        <button id="logout-btn" class="btn-back" onclick="logout()" style="display: none;">Logout</button>
    </div>

    <!-- Navigation Tabs -->
    <div class="nav-tabs">
        <ul>
            <li><button class="active" onclick="showTab('overview')">Overview</button></li>
            <li><button onclick="showTab('absences')">Current Absences</button></li>
            <li><button onclick="showTab('reports')">Reports</button></li>
            <li><button onclick="showTab('trends')">Trends</button></li>
        </ul>
    </div>

    <!-- Overview Tab -->
    <div id="overview-tab" class="tab-content active">
        <!-- Summary Cards -->
        <div class="summary-section">
            <div class="summary-grid">
                <div class="summary-card sick">
                    <h3 id="sickCount">0</h3>
                    <p>Sick Leave</p>
                </div>
                <div class="summary-card maternity">
                    <h3 id="maternityCount">0</h3>
                    <p>Maternity/Paternity</p>
                </div>
                <div class="summary-card bereavement">
                    <h3 id="bereavementCount">0</h3>
                    <p>Bereavement</p>
                </div>
                <div class="summary-card study">
                    <h3 id="studyCount">0</h3>
                    <p>Study Leave</p>
                </div>
                <div class="summary-card unpaid">
                    <h3 id="unpaidCount">0</h3>
                    <p>Unpaid Leave</p>
                </div>
                <div class="summary-card">
                    <h3 id="totalAbsenceHours">0</h3>
                    <p>Total Hours</p>
                </div>
            </div>
        </div>

        <!-- Filter Section -->
        <div class="filter-section">
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
                    <label for="absenceTypeFilter">Absence Type:</label>
                    <select id="absenceTypeFilter">
                        <option value="">All Types</option>
                        <option value="Sick Leave">Sick Leave</option>
                        <option value="Maternity Leave">Maternity Leave</option>
                        <option value="Paternity Leave">Paternity Leave</option>
                        <option value="Bereavement Leave">Bereavement Leave</option>
                        <option value="Study Leave">Study Leave</option>
                        <option value="Unpaid Leave">Unpaid Leave</option>
                    </select>
                </div>
                <div class="filter-group">
                    <label for="dateFromFilter">From Date:</label>
                    <input type="date" id="dateFromFilter">
                </div>
                <div class="filter-group">
                    <label for="dateToFilter">To Date:</label>
                    <input type="date" id="dateToFilter">
                </div>
                <div class="filter-actions">
                    <button class="btn-filter" onclick="applyFilters()">Apply Filters</button>
                    <button class="btn-clear" onclick="clearFilters()">Clear All</button>
                </div>
            </div>
        </div>

        <!-- Recent Absences -->
        <div class="content-section">
            <div class="section-header">
                <h2 class="section-title">Recent Absences</h2>
                <button class="btn-export" onclick="exportData()">Export Data</button>
            </div>
            <div class="table-container">
                <!-- Desktop Table -->
                <table class="main-table">
                    <thead>
                        <tr>
                            <th>Employee ID</th>
                            <th>Employee Name</th>
                            <th>Date</th>
                            <th>Absence Type</th>
                            <th>Hours</th>
                            <th>Department</th>
                            <th>Team</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody id="absenceList"></tbody>
                </table>
                
                <!-- Mobile Cards Container -->
                <div id="mobileAbsenceCards"></div>
            </div>
        </div>
    </div>

    <!-- Current Absences Tab -->
    <div id="absences-tab" class="tab-content">
        <div class="content-section">
            <div class="section-header">
                <h2 class="section-title">Current Absences</h2>
                <button class="btn-export" onclick="exportCurrentAbsences()">Export Current</button>
            </div>
            <div class="table-container">
                <!-- Desktop Table -->
                <table class="main-table">
                    <thead>
                        <tr>
                            <th>Employee ID</th>
                            <th>Employee Name</th>
                            <th>Absence Type</th>
                            <th>Start Date</th>
                            <th>Total Days</th>
                            <th>Total Hours</th>
                            <th>Department</th>
                            <th>Team</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody id="currentAbsenceList"></tbody>
                </table>
                
                <!-- Mobile Cards Container -->
                <div id="mobileCurrentAbsenceCards"></div>
            </div>
        </div>
    </div>

    <!-- Reports Tab -->
    <div id="reports-tab" class="tab-content">
        <div class="content-section">
            <div class="section-header">
                <h2 class="section-title">Absence Reports</h2>
            </div>
            <div class="chart-container">
                <p>Absence trends and analytics charts would appear here</p>
            </div>
        </div>
    </div>

    <!-- Trends Tab -->
    <div id="trends-tab" class="tab-content">
        <div class="content-section">
            <div class="section-header">
                <h2 class="section-title">Absence Trends</h2>
            </div>
            <div class="chart-container">
                <p>Historical absence patterns and forecasting would appear here</p>
            </div>
        </div>
    </div>
</div>

<script>
const API_URL = 'absence_api.php';
let currentUser = null;
let departmentsTeams = {};
let currentAbsenceData = [];

function formatDate(dateStr) {
    const date = new Date(dateStr);
    return date.toLocaleDateString('en-GB');
}

function getAbsenceBadgeClass(absenceType) {
    if (!absenceType) return 'absence-other';
    const type = absenceType.toLowerCase();
    if (type.includes('sick')) return 'absence-sick';
    if (type.includes('maternity') || type.includes('paternity')) return 'absence-maternity';
    if (type.includes('bereavement')) return 'absence-bereavement';
    if (type.includes('study')) return 'absence-study';
    if (type.includes('unpaid')) return 'absence-unpaid';
    return 'absence-other';
}

function showPasswordReset() {
    document.getElementById('login-modal').style.display = 'none';
    document.getElementById('reset-modal').style.display = 'flex';
    document.getElementById('reset-error').style.display = 'none';
    document.getElementById('reset-success').style.display = 'none';
}

function showLogin() {
    document.getElementById('reset-modal').style.display = 'none';
    document.getElementById('login-modal').style.display = 'flex';
    document.getElementById('login-error').style.display = 'none';
}

async function sendPasswordReset() {
    const email = document.getElementById('reset-email').value;
    
    if (!email) {
        document.getElementById('reset-error').style.display = 'block';
        document.getElementById('reset-error').innerText = 'Please enter your email address';
        return;
    }
    
    try {
        const res = await fetch(API_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                action: 'reset_password',
                email: email
            })
        });
        
        const data = await res.json();
        
        if (data.success) {
            document.getElementById('reset-error').style.display = 'none';
            document.getElementById('reset-success').style.display = 'block';
            document.getElementById('reset-success').innerText = 'Password reset link sent to your email';
        } else {
            document.getElementById('reset-success').style.display = 'none';
            document.getElementById('reset-error').style.display = 'block';
            document.getElementById('reset-error').innerText = data.error || 'Failed to send reset email';
        }
    } catch (error) {
        document.getElementById('reset-success').style.display = 'none';
        document.getElementById('reset-error').style.display = 'block';
        document.getElementById('reset-error').innerText = 'Connection error';
    }
}

async function loginUser() {
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
        
        if (data.success) {
            currentUser = data.user;
            document.getElementById('login-modal').style.display = 'none';
            document.getElementById('main-container').style.display = 'block';
            document.getElementById('logout-btn').style.display = 'block';
            
            await loadDepartmentsTeams();
            await loadAbsenceData();
        } else {
            document.getElementById('login-error').style.display = 'block';
            document.getElementById('login-error').innerText = data.error;
        }
    } catch (error) {
        document.getElementById('login-error').style.display = 'block';
        document.getElementById('login-error').innerText = 'Connection error';
    }
}

function logout() {
    currentUser = null;
    document.getElementById('main-container').style.display = 'none';
    document.getElementById('logout-btn').style.display = 'none';
    document.getElementById('login-modal').style.display = 'flex';
    document.getElementById('username').value = '';
    document.getElementById('password').value = '';
    departmentsTeams = {};
    currentAbsenceData = [];
}

async function loadDepartmentsTeams() {
    try {
        const res = await fetch(API_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: 'get_departments_teams' })
        });
        
        const data = await res.json();
        
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

async function loadAbsenceData() {
    if (!currentUser || !currentUser.id) {
        return;
    }
    
    const department = document.getElementById('departmentFilter').value;
    const team = document.getElementById('teamFilter').value;
    const absenceType = document.getElementById('absenceTypeFilter').value;
    const dateFrom = document.getElementById('dateFromFilter').value;
    const dateTo = document.getElementById('dateToFilter').value;
    
    try {
        const res = await fetch(API_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                action: 'get_absences',
                department: department,
                team: team,
                absence_type: absenceType,
                date_from: dateFrom,
                date_to: dateTo,
                manager_id: currentUser.id
            })
        });
        
        const data = await res.json();
        
        if (data.success) {
            currentAbsenceData = data.data || [];
            updateSummaryCards(data.summary || {});
            buildAbsenceTable(currentAbsenceData);
            createMobileAbsenceCards(currentAbsenceData);
            loadCurrentAbsences();
        } else {
            document.getElementById('absenceList').innerHTML = '<tr><td colspan="8" style="text-align: center; color: #dc3545; padding: 40px;">Error: ' + (data.error || 'Unknown error') + '</td></tr>';
        }
    } catch (error) {
        document.getElementById('absenceList').innerHTML = '<tr><td colspan="8" style="text-align: center; color: #dc3545; padding: 40px;">Connection error</td></tr>';
    }
}

async function loadCurrentAbsences() {
    if (!currentUser || !currentUser.id) {
        return;
    }
    
    try {
        const res = await fetch(API_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                action: 'get_current_absences',
                manager_id: currentUser.id
            })
        });
        
        const data = await res.json();
        
        if (data.success) {
            buildCurrentAbsenceTable(data.data || []);
            createMobileCurrentAbsenceCards(data.data || []);
        }
    } catch (error) {
        console.error('Load current absences error:', error);
    }
}

function updateSummaryCards(summary) {
    document.getElementById('sickCount').textContent = summary.sick_count || 0;
    document.getElementById('maternityCount').textContent = summary.maternity_count || 0;
    document.getElementById('bereavementCount').textContent = summary.bereavement_count || 0;
    document.getElementById('studyCount').textContent = summary.study_count || 0;
    document.getElementById('unpaidCount').textContent = summary.unpaid_count || 0;
    document.getElementById('totalAbsenceHours').textContent = summary.total_hours || 0;
}

function buildAbsenceTable(data) {
    const tbody = document.getElementById('absenceList');
    tbody.innerHTML = '';
    
    if (!data || data.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; color: #6c757d; padding: 40px;">No absence records found</td></tr>';
        return;
    }
    
    data.forEach(row => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><strong>${row.employee_id}</strong></td>
            <td>${row.employee_name}</td>
            <td>${formatDate(row.sched_date)}</td>
            <td><span class="absence-badge ${getAbsenceBadgeClass(row.absence_type)}">${row.absence_type}</span></td>
            <td><strong>${row.absence_hours}</strong></td>
            <td><span class="dept-badge">${row.department || 'N/A'}</span></td>
            <td><span class="team-badge">${row.team || 'N/A'}</span></td>
            <td><button class="btn-view" onclick="viewAbsenceDetail('${row.employee_id}', '${row.sched_date}')">View Detail</button></td>
        `;
        tbody.appendChild(tr);
    });
}

function buildCurrentAbsenceTable(data) {
    const tbody = document.getElementById('currentAbsenceList');
    tbody.innerHTML = '';
    
    if (!data || data.length === 0) {
        tbody.innerHTML = '<tr><td colspan="9" style="text-align: center; color: #6c757d; padding: 40px;">No current absences found</td></tr>';
        return;
    }
    
    data.forEach(row => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><strong>${row.employee_id}</strong></td>
            <td>${row.employee_name}</td>
            <td><span class="absence-badge ${getAbsenceBadgeClass(row.absence_type)}">${row.absence_type}</span></td>
            <td>${formatDate(row.start_date)}</td>
            <td><strong>${row.total_days}</strong></td>
            <td><strong>${row.total_hours}</strong></td>
            <td><span class="dept-badge">${row.department || 'N/A'}</span></td>
            <td><span class="team-badge">${row.team || 'N/A'}</span></td>
            <td><button class="btn-view" onclick="viewEmployeeAbsences('${row.employee_id}')">View All</button></td>
        `;
        tbody.appendChild(tr);
    });
}

function createMobileAbsenceCards(data) {
    const container = document.getElementById('mobileAbsenceCards');
    container.innerHTML = '';
    
    if (!data || data.length === 0) {
        return;
    }
    
    data.forEach(row => {
        const card = document.createElement('div');
        card.className = 'absence-card';
        card.innerHTML = `
            <div class="card-header">
                <div class="card-title">Employee ${row.employee_id}</div>
                <span class="absence-badge ${getAbsenceBadgeClass(row.absence_type)}">${row.absence_type}</span>
            </div>
            <div class="card-body">
                <div class="field-row">
                    <span class="field-label">Employee Name:</span>
                    <span class="field-value">${row.employee_name}</span>
                </div>
                <div class="field-row">
                    <span class="field-label">Date:</span>
                    <span class="field-value">${formatDate(row.sched_date)}</span>
                </div>
                <div class="field-row">
                    <span class="field-label">Hours:</span>
                    <span class="field-value"><strong>${row.absence_hours}</strong></span>
                </div>
                <div class="field-row">
                    <span class="field-label">Department:</span>
                    <span class="field-value"><span class="dept-badge">${row.department || 'N/A'}</span></span>
                </div>
                <div class="field-row">
                    <span class="field-label">Team:</span>
                    <span class="field-value"><span class="team-badge">${row.team || 'N/A'}</span></span>
                </div>
                <div style="margin-top: 15px; text-align: center;">
                    <button class="btn-view" onclick="viewAbsenceDetail('${row.employee_id}', '${row.sched_date}')">View Detail</button>
                </div>
            </div>
        `;
        container.appendChild(card);
    });
}

function createMobileCurrentAbsenceCards(data) {
    const container = document.getElementById('mobileCurrentAbsenceCards');
    container.innerHTML = '';
    
    if (!data || data.length === 0) {
        return;
    }
    
    data.forEach(row => {
        const card = document.createElement('div');
        card.className = 'absence-card';
        card.innerHTML = `
            <div class="card-header">
                <div class="card-title">Employee ${row.employee_id}</div>
                <span class="absence-badge ${getAbsenceBadgeClass(row.absence_type)}">${row.absence_type}</span>
            </div>
            <div class="card-body">
                <div class="field-row">
                    <span class="field-label">Employee Name:</span>
                    <span class="field-value">${row.employee_name}</span>
                </div>
                <div class="field-row">
                    <span class="field-label">Start Date:</span>
                    <span class="field-value">${formatDate(row.start_date)}</span>
                </div>
                <div class="field-row">
                    <span class="field-label">Total Days:</span>
                    <span class="field-value"><strong>${row.total_days}</strong></span>
                </div>
                <div class="field-row">
                    <span class="field-label">Total Hours:</span>
                    <span class="field-value"><strong>${row.total_hours}</strong></span>
                </div>
                <div class="field-row">
                    <span class="field-label">Department:</span>
                    <span class="field-value"><span class="dept-badge">${row.department || 'N/A'}</span></span>
                </div>
                <div class="field-row">
                    <span class="field-label">Team:</span>
                    <span class="field-value"><span class="team-badge">${row.team || 'N/A'}</span></span>
                </div>
                <div style="margin-top: 15px; text-align: center;">
                    <button class="btn-view" onclick="viewEmployeeAbsences('${row.employee_id}')">View All Absences</button>
                </div>
            </div>
        `;
        container.appendChild(card);
    });
}

function showTab(tabName) {
    document.querySelectorAll('.tab-content').forEach(tab => {
        tab.classList.remove('active');
    });
    
    document.querySelectorAll('.nav-tabs button').forEach(btn => {
        btn.classList.remove('active');
    });
    
    document.getElementById(tabName + '-tab').classList.add('active');
    event.target.classList.add('active');
    
    if (currentUser && currentUser.id && (tabName === 'absences' || tabName === 'overview')) {
        loadAbsenceData();
    }
}

function applyFilters() {
    loadAbsenceData();
}

function clearFilters() {
    document.getElementById('departmentFilter').value = '';
    document.getElementById('teamFilter').value = '';
    document.getElementById('absenceTypeFilter').value = '';
    document.getElementById('dateFromFilter').value = '';
    document.getElementById('dateToFilter').value = '';
    loadAbsenceData();
}

function viewAbsenceDetail(employeeId, date) {
    alert(`View detailed absence information for Employee ${employeeId} on ${formatDate(date)}`);
}

function viewEmployeeAbsences(employeeId) {
    alert(`View all absences for Employee ${employeeId}`);
}

function exportData() {
    alert('Export absence data to CSV/Excel');
}

function exportCurrentAbsences() {
    alert('Export current absences to CSV/Excel');
}

document.addEventListener('DOMContentLoaded', function() {
    document.getElementById('username').addEventListener('keypress', function(e) {
        if (e.key === 'Enter') loginUser();
    });
    
    document.getElementById('password').addEventListener('keypress', function(e) {
        if (e.key === 'Enter') loginUser();
    });
    
    document.getElementById('reset-email').addEventListener('keypress', function(e) {
        if (e.key === 'Enter') sendPasswordReset();
    });
});
</script>
</body>
</html>