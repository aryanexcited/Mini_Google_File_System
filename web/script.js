const MASTER_URL = 'http://localhost:8000';
const CLIENT_URL = 'http://localhost:8001';
const REFRESH_INTERVAL = 3000;

let currentUser = null;
let currentRole = null;
let currentToken = null;
let refreshTimer = null;

document.addEventListener('DOMContentLoaded', () => {
    initializeApp();
});

function initializeApp() {
    const savedToken = sessionStorage.getItem('gfs_token');
    const savedUser = sessionStorage.getItem('gfs_user');
    const savedRole = sessionStorage.getItem('gfs_role');
    
    if (savedToken && savedUser && savedRole) {
        currentToken = savedToken;
        currentUser = savedUser;
        currentRole = savedRole;
        showDashboard();
    } else {
        showAuth();
    }
    
    setupEventListeners();
}

function setupEventListeners() {
    document.querySelectorAll('.auth-tab').forEach(tab => {
        tab.addEventListener('click', () => switchAuthTab(tab.dataset.tab));
    });
    
    document.getElementById('loginFormSubmit').addEventListener('submit', handleLogin);
    document.getElementById('signupFormSubmit').addEventListener('submit', handleSignup);
    document.getElementById('logoutBtn').addEventListener('click', handleLogout);
    
    const dropZone = document.getElementById('dragDropZone');
    const fileInput = document.getElementById('fileInput');
    
    dropZone.addEventListener('click', () => fileInput.click());
    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('dragover');
    });
    
    dropZone.addEventListener('click', () => fileInput.click());
    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('dragover');
    });
    dropZone.addEventListener('dragleave', () => {
        dropZone.classList.remove('dragover');
    });
    dropZone.addEventListener('drop', handleFileDrop);
    
    fileInput.addEventListener('change', handleFileSelect);
    
    document.getElementById('uploadBtn').addEventListener('click', handleManualUpload);
    
    const addUserBtn = document.getElementById('addUserBtn');
    if (addUserBtn) {
        addUserBtn.addEventListener('click', () => showModal('addUserModal'));
    }
    
    document.getElementById('cancelAddUser').addEventListener('click', () => hideModal('addUserModal'));
    document.getElementById('addUserForm').addEventListener('submit', handleAddUser);
    
    document.querySelectorAll('.close').forEach(el => {
        el.addEventListener('click', (e) => {
            const modal = e.target.closest('.modal');
            if (modal) hideModal(modal.id);
        });
    });
}

// ============ Authentication ============

function switchAuthTab(tab) {
    document.querySelectorAll('.auth-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.auth-form').forEach(f => f.classList.remove('active'));
    
    document.querySelector(`[data-tab="${tab}"]`).classList.add('active');
    document.getElementById(`${tab}Form`).classList.add('active');
    
    document.getElementById('loginError').textContent = '';
    document.getElementById('signupError').textContent = '';
    document.getElementById('signupSuccess').textContent = '';
}

async function handleLogin(e) {
    e.preventDefault();
    console.log('Login attempt started'); 
    
    const username = document.getElementById('loginUsername').value;
    const password = document.getElementById('loginPassword').value;
    const errorEl = document.getElementById('loginError');
    
    console.log('Username:', username);
    
    try {
        console.log('Sending login request to:', `${MASTER_URL}/login`);
        const response = await fetch(`${MASTER_URL}/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        
        console.log('Response status:', response.status);
        console.log('Response ok:', response.ok);
        
        const data = await response.json();
        console.log('Response data:', data);
        
        if (data.success) {
            console.log('Login successful! Role:', data.role);
            currentUser = username;
            currentRole = data.role;
            currentToken = data.token;
            
            sessionStorage.setItem('gfs_token', data.token);
            sessionStorage.setItem('gfs_user', username);
            sessionStorage.setItem('gfs_role', data.role);
            
            console.log('Calling showDashboard...');
            showDashboard();
        } else {
            console.log('Login failed:', data.error);
            errorEl.textContent = data.error || 'Login failed';
        }
    } catch (error) {
        console.error('Login error (exception):', error);
        errorEl.textContent = 'Connection error. Please ensure the system is running.';
        console.error('Login error:', error);
    }
}

async function handleSignup(e) {
    e.preventDefault();
    
    const username = document.getElementById('signupUsername').value;
    const password = document.getElementById('signupPassword').value;
    const passwordConfirm = document.getElementById('signupPasswordConfirm').value;
    const errorEl = document.getElementById('signupError');
    const successEl = document.getElementById('signupSuccess');
    
    errorEl.textContent = '';
    successEl.textContent = '';
    
    if (password !== passwordConfirm) {
        errorEl.textContent = 'Passwords do not match';
        return;
    }
    
    try {
        const response = await fetch(`${MASTER_URL}/signup`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        
        const data = await response.json();
        
        if (data.success) {
            successEl.textContent = 'Account created! You can now login.';
            document.getElementById('signupFormSubmit').reset();
            setTimeout(() => switchAuthTab('login'), 2000);
        } else {
            errorEl.textContent = data.error || 'Signup failed';
        }
    } catch (error) {
        errorEl.textContent = 'Connection error. Please ensure the system is running.';
        console.error('Signup error:', error);
    }
}

async function handleLogout() {
    try {
        await fetch(`${MASTER_URL}/logout`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token: currentToken })
        });
    } catch (error) {
        console.error('Logout error:', error);
    }
    
    currentUser = null;
    currentRole = null;
    currentToken = null;
    sessionStorage.clear();
    
    if (refreshTimer) {
        clearInterval(refreshTimer);
        refreshTimer = null;
    }
    
    showAuth();
}

// ============ Screen Management ============

function showAuth() {
    document.getElementById('authScreen').classList.add('active');
    document.getElementById('dashboardScreen').classList.remove('active');
    document.getElementById('loginFormSubmit').reset();
    document.getElementById('signupFormSubmit').reset();
    document.getElementById('loginError').textContent = '';
    document.getElementById('signupError').textContent = '';
    document.getElementById('signupSuccess').textContent = '';
}

function showDashboard() {
    document.getElementById('authScreen').classList.remove('active');
    document.getElementById('dashboardScreen').classList.add('active');
    
    document.getElementById('userName').textContent = currentUser;
    document.getElementById('userRole').textContent = currentRole;
    
    document.querySelectorAll('.dashboard-content').forEach(el => el.classList.remove('active'));
    
    if (currentRole === 'admin') {
        document.getElementById('adminDashboard').classList.add('active');
        loadAdminDashboard();
    } else if (currentRole === 'manager') {
        document.getElementById('managerDashboard').classList.add('active');
        loadManagerDashboard();
    } else {
        document.getElementById('userDashboard').classList.add('active');
        loadUserDashboard();
    }
    
    if (refreshTimer) clearInterval(refreshTimer);
    refreshTimer = setInterval(refreshDashboard, REFRESH_INTERVAL);
}

function refreshDashboard() {
    if (currentRole === 'admin') {
        loadAdminDashboard();
    } else if (currentRole === 'manager') {
        loadManagerDashboard();
    } else {
        loadUserDashboard();
    }
}

// ============ Admin Dashboard ============

async function loadAdminDashboard() {
    try {
        const [status, users] = await Promise.all([
            fetch(`${MASTER_URL}/status`).then(r => r.json()),
            fetch(`${MASTER_URL}/users`).then(r => r.json())
        ]);
        
        updateAdminStats(status, users);
        updateServersList(status.servers, 'serversList', true);
        updateUsersList(users.users);
        updateFilesList(status.files, 'filesList');
    } catch (error) {
        console.error('Error loading admin dashboard:', error);
    }
}

function updateAdminStats(status, users) {
    const activeCount = Object.values(status.servers).filter(s => s.status === 'active').length;
    const fileCount = Object.keys(status.files).length;
    
    document.getElementById('activeServers').textContent = `${activeCount}/${Object.keys(status.servers).length}`;
    document.getElementById('totalFiles').textContent = fileCount;
    document.getElementById('faultTolerance').textContent = `${status.fault_tolerance}%`;
    document.getElementById('totalUsers').textContent = users.length;
}

function updateUsersList(users) {
    const container = document.getElementById('usersTable');
    
    let html = `
        <div class="user-row">
            <div>Username</div>
            <div>Role</div>
            <div>Created By</div>
            <div>Actions</div>
        </div>
    `;
    
    users.forEach(user => {
        html += `
            <div class="user-row">
                <div>${user.username}</div>
                <div>${user.role}</div>
                <div>${user.created_by}</div>
                <div>
                    ${user.role === 'user' ? `<button class="btn-primary" onclick="promoteUser('${user.username}')">Promote to Manager</button>` : '-'}
                </div>
            </div>
        `;
    });
    
    container.innerHTML = html;
}

async function promoteUser(username) {
    try {
        const response = await fetch(`${MASTER_URL}/promote_user`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username })
        });
        
        const data = await response.json();
        if (data.success) {
            alert(`User ${username} promoted to Manager`);
            loadAdminDashboard();
        } else {
            alert('Failed to promote user');
        }
    } catch (error) {
        console.error('Error promoting user:', error);
        alert('Error promoting user');
    }
}

// ============ Manager Dashboard ============

async function loadManagerDashboard() {
    try {
        const status = await fetch(`${MASTER_URL}/status`).then(r => r.json());
        
        updateManagerStats(status);
        updateServersList(status.servers, 'managerServersList', true);
        updateFilesList(status.files, 'managerFilesList');
    } catch (error) {
        console.error('Error loading manager dashboard:', error);
    }
}

function updateManagerStats(status) {
    const activeCount = Object.values(status.servers).filter(s => s.status === 'active').length;
    const fileCount = Object.keys(status.files).length;
    
    document.getElementById('managerActiveServers').textContent = `${activeCount}/${Object.keys(status.servers).length}`;
    document.getElementById('managerTotalFiles').textContent = fileCount;
    document.getElementById('managerFaultTolerance').textContent = `${status.fault_tolerance}%`;
}

// ============ User Dashboard ============

async function loadUserDashboard() {
    try {
        const status = await fetch(`${MASTER_URL}/status`).then(r => r.json());
        
        updateUserStats(status);
        updateServersList(status.servers, 'userServersList', false);
        updateFilesList(status.files, 'userFilesList');
    } catch (error) {
        console.error('Error loading user dashboard:', error);
    }
}

function updateUserStats(status) {
    const activeCount = Object.values(status.servers).filter(s => s.status === 'active').length;
    const fileCount = Object.keys(status.files).length;
    
    document.getElementById('userActiveServers').textContent = `${activeCount}/${Object.keys(status.servers).length}`;
    document.getElementById('userTotalFiles').textContent = fileCount;
    document.getElementById('userFaultTolerance').textContent = `${status.fault_tolerance}%`;
}

// ============ Common UI Updates ============

function updateServersList(servers, containerId, showActions) {
    const container = document.getElementById(containerId);
    
    if (!servers || Object.keys(servers).length === 0) {
        container.innerHTML = '<div style="text-align: center; padding: 40px; color: #999;">No servers available</div>';
        return;
    }
    
    let html = '';
    
    Object.entries(servers).forEach(([id, info]) => {
        const statusClass = info.status === 'active' ? 'active' : 'failed';
        const lastHeartbeat = new Date(info.last_heartbeat * 1000).toLocaleTimeString();
        
        html += `
            <div class="server-card ${statusClass}">
                <div class="server-header">
                    <div style="font-weight: 600;">${id}</div>
                    <div class="server-status ${statusClass}">${info.status}</div>
                </div>
                <div style="color: #666; font-size: 14px; margin-bottom: 10px;">Host: ${info.host}:${info.port}</div>
                <div style="color: #666; font-size: 14px; margin-bottom: 10px;">Last Heartbeat: ${lastHeartbeat}</div>
                ${showActions && (currentRole === 'admin' || currentRole === 'manager') ? `
                    <div style="margin-top: 15px;">
                        <button class="btn-danger" onclick="simulateFailure('${id}')" ${info.status === 'failed' ? 'disabled' : ''}>
                            Simulate Failure
                        </button>
                    </div>
                ` : ''}
            </div>
        `;
    });
    
    container.innerHTML = html;
}

async function simulateFailure(serverId) {
    if (!confirm(`Are you sure you want to simulate failure of ${serverId}?`)) {
        return;
    }
    
    try {
        const response = await fetch(`${MASTER_URL}/simulate_failure`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ server_id: serverId })
        });
        
        const data = await response.json();
        if (data.success) {
            alert(`Server ${serverId} marked as failed. Re-replication in progress...`);
            refreshDashboard();
        } else {
            alert('Failed to simulate failure');
        }
    } catch (error) {
        console.error('Error simulating failure:', error);
        alert('Error simulating failure');
    }
}

function updateFilesList(files, containerId) {
    const container = document.getElementById(containerId);
    
    if (!files || Object.keys(files).length === 0) {
        container.innerHTML = '<div style="text-align: center; padding: 40px; color: #999;">No files uploaded yet</div>';
        return;
    }
    
    let html = '';
    
    Object.entries(files).forEach(([filename, info]) => {
        html += `
            <div class="file-card">
                <div style="font-weight: 600; margin-bottom: 10px;">📄 ${filename}</div>
                <div style="color: #666; font-size: 14px;">Uploaded: ${new Date(info.upload_time).toLocaleString()}</div>
                <div style="color: #666; font-size: 14px; margin-bottom: 10px;">Chunks: ${info.chunks.length}</div>
                <div style="display: flex; flex-wrap: wrap; gap: 10px;">
                    ${info.chunks.map(chunk => `<span style="background: #667eea; color: white; padding: 5px 10px; border-radius: 4px; font-size: 12px;">${chunk}</span>`).join('')}
                </div>
            </div>
        `;
    });
    
    container.innerHTML = html;
}

// ============ File Upload ============

function handleFileDrop(e) {
    e.preventDefault();
    const dropZone = document.getElementById('dragDropZone');
    dropZone.classList.remove('dragover');
    
    const files = e.dataTransfer.files;
    if (files.length > 0) {
        uploadFiles(files);
    }
}

function handleFileSelect(e) {
    const files = e.target.files;
    if (files.length > 0) {
        uploadFiles(files);
    }
}

async function handleManualUpload() {
    const filename = document.getElementById('fileName').value.trim();
    const content = document.getElementById('fileContent').value;
    
    if (!filename) {
        alert('Please enter a filename');
        return;
    }
    
    if (!content) {
        alert('Please enter file content');
        return;
    }
    
    const encrypt = document.getElementById('encryptionEnabled').checked;
    await uploadFile(filename, content, false, encrypt);
}

async function uploadFiles(files) {
    const encrypt = document.getElementById('encryptionEnabled').checked;
    const progressContainer = document.getElementById('uploadProgress');
    
    progressContainer.innerHTML = '<div class="progress-label loading">Preparing files...</div>';
    
    for (let i = 0; i < files.length; i++) {
        const file = files[i];
        await uploadFile(file.name, file, true, encrypt);
        
        if (i < files.length - 1) {
            await new Promise(resolve => setTimeout(resolve, 1000));
        }
    }
}

async function uploadFile(filename, content, isFile, encrypt) {
    const progressContainer = document.getElementById('uploadProgress');
    progressContainer.innerHTML = `<div class="progress-label loading">Uploading ${filename}...</div>`;
    
    try {
        let payload = {
            filename: filename,
            encrypt: encrypt
        };
        
        if (isFile) {
            const reader = new FileReader();
            const fileContent = await new Promise((resolve, reject) => {
                reader.onload = () => resolve(reader.result.split(',')[1]);
                reader.onerror = reject;
                reader.readAsDataURL(content);
            });
            payload.content_base64 = fileContent;
        } else {
            payload.content = content;
        }
        
        const response = await fetch(`${CLIENT_URL}/upload`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        
        const data = await response.json();
        
        if (data.success) {
            const encryptionStatus = data.encrypted ? ' (Encrypted 🔒)' : '';
            progressContainer.innerHTML = `
                <div style="margin-bottom: 10px;">
                    <div class="progress-label">✓ Upload successful: ${data.filename}${encryptionStatus}</div>
                    <div class="progress-bar">
                        <div class="progress-fill" style="width: 100%"></div>
                    </div>
                </div>
            `;
            
            document.getElementById('fileName').value = '';
            document.getElementById('fileContent').value = '';
            document.getElementById('fileInput').value = '';
            
            setTimeout(() => {
                refreshDashboard();
            }, 2000);
        } else {
            progressContainer.innerHTML = '<div class="progress-label">✗ Upload failed</div>';
        }
    } catch (error) {
        console.error('Upload error:', error);
        progressContainer.innerHTML = '<div class="progress-label">✗ Connection error. Please ensure the client service is running.</div>';
    }
}

// ============ User Management ============

async function handleAddUser(e) {
    e.preventDefault();
    
    const username = document.getElementById('newUsername').value;
    const password = document.getElementById('newPassword').value;
    const role = document.getElementById('newUserRole').value;
    
    try {
        const response = await fetch(`${MASTER_URL}/create_user`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                username,
                password,
                role,
                created_by: currentUser
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            alert(`User ${username} created successfully`);
            hideModal('addUserModal');
            document.getElementById('addUserForm').reset();
            loadAdminDashboard();
        } else {
            alert(data.error || 'Failed to create user');
        }
    } catch (error) {
        console.error('Error creating user:', error);
        alert('Error creating user');
    }
}

function showModal(modalId) {
    document.getElementById(modalId).classList.add('active');
}

function hideModal(modalId) {
    document.getElementById(modalId).classList.remove('active');
}

window.promoteUser = promoteUser;
window.simulateFailure = simulateFailure;