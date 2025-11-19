import React, { useState, useEffect, useRef } from 'react';
import { Upload, Download, Trash2, Search, RefreshCw, CheckCircle, XCircle, Lock } from 'lucide-react';

const MASTER_URL = 'http://localhost:8000';
const CLIENT_URL = 'http://localhost:8001';
const REFRESH_INTERVAL = 3000;

// Main App Component
export default function MiniGFS() {
  const [screen, setScreen] = useState('auth');
  const [authTab, setAuthTab] = useState('login');
  const [currentUser, setCurrentUser] = useState(null);
  const [currentRole, setCurrentRole] = useState(null);
  const [currentToken, setCurrentToken] = useState(null);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  useEffect(() => {
    const savedToken = sessionStorage.getItem('gfs_token');
    const savedUser = sessionStorage.getItem('gfs_user');
    const savedRole = sessionStorage.getItem('gfs_role');
    
    if (savedToken && savedUser && savedRole) {
      setCurrentToken(savedToken);
      setCurrentUser(savedUser);
      setCurrentRole(savedRole);
      setScreen('dashboard');
    }
  }, []);

  const handleLogin = async (username, password) => {
    setError('');
    try {
      const response = await fetch(`${MASTER_URL}/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });
      
      const data = await response.json();
      
      if (data.success) {
        setCurrentUser(username);
        setCurrentRole(data.role);
        setCurrentToken(data.token);
        sessionStorage.setItem('gfs_token', data.token);
        sessionStorage.setItem('gfs_user', username);
        sessionStorage.setItem('gfs_role', data.role);
        setScreen('dashboard');
      } else {
        setError(data.error || 'Login failed');
      }
    } catch (err) {
      setError('Connection error. Please ensure the system is running.');
    }
  };

  const handleSignup = async (username, password) => {
    setError('');
    setSuccess('');
    try {
      const response = await fetch(`${MASTER_URL}/signup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });
      
      const data = await response.json();
      
      if (data.success) {
        setSuccess('Account created! You can now login.');
        setTimeout(() => {
          setAuthTab('login');
          setSuccess('');
        }, 2000);
      } else {
        setError(data.error || 'Signup failed');
      }
    } catch (err) {
      setError('Connection error. Please ensure the backend is running.');
    }
  };

  const handleLogout = async () => {
    try {
      await fetch(`${MASTER_URL}/logout`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: currentToken }),
      });
    } catch (err) {
      console.error('Logout error:', err);
    }
    
    setCurrentUser(null);
    setCurrentRole(null);
    setCurrentToken(null);
    sessionStorage.clear();
    setScreen('auth');
  };

  if (screen === 'auth') {
    return (
      <AuthScreen 
        tab={authTab}
        setTab={setAuthTab}
        onLogin={handleLogin}
        onSignup={handleSignup}
        error={error}
        success={success}
      />
    );
  }

  return (
    <DashboardScreen
      user={currentUser}
      role={currentRole}
      token={currentToken}
      onLogout={handleLogout}
    />
  );
}

// Auth Screen Component
function AuthScreen({ tab, setTab, onLogin, onSignup, error, success }) {
  const [loginData, setLoginData] = useState({ username: '', password: '' });
  const [signupData, setSignupData] = useState({ username: '', password: '', confirmPassword: '' });
  const [localError, setLocalError] = useState('');

  const handleLoginSubmit = (e) => {
    e.preventDefault();
    onLogin(loginData.username, loginData.password);
  };

  const handleSignupSubmit = (e) => {
    e.preventDefault();
    setLocalError('');
    
    if (signupData.password !== signupData.confirmPassword) {
      setLocalError('Passwords do not match');
      return;
    }
    
    onSignup(signupData.username, signupData.password);
  };

  return (
    <div className="screen active" id="authScreen">
      <div className="auth-container">
        <h1>🗄️ Mini GFS</h1>
        <h2>Distributed File System</h2>

        <div className="auth-tabs">
          <div
            className={`auth-tab ${tab === 'login' ? 'active' : ''}`}
            onClick={() => setTab('login')}
          >
            Login
          </div>
          <div
            className={`auth-tab ${tab === 'signup' ? 'active' : ''}`}
            onClick={() => setTab('signup')}
          >
            Sign Up
          </div>
        </div>

        <div className={`auth-form ${tab === 'login' ? 'active' : ''}`} id="loginForm">
          <form onSubmit={handleLoginSubmit}>
            <input
              type="text"
              placeholder="Username"
              value={loginData.username}
              onChange={(e) => setLoginData({ ...loginData, username: e.target.value })}
              required
            />
            <input
              type="password"
              placeholder="Password"
              value={loginData.password}
              onChange={(e) => setLoginData({ ...loginData, password: e.target.value })}
              required
            />
            <button type="submit">Login</button>
            {error && <div className="error">{error}</div>}
          </form>
        </div>

        <div className={`auth-form ${tab === 'signup' ? 'active' : ''}`} id="signupForm">
          <form onSubmit={handleSignupSubmit}>
            <input
              type="text"
              placeholder="Username"
              value={signupData.username}
              onChange={(e) => setSignupData({ ...signupData, username: e.target.value })}
              required
            />
            <input
              type="password"
              placeholder="Password"
              value={signupData.password}
              onChange={(e) => setSignupData({ ...signupData, password: e.target.value })}
              required
            />
            <input
              type="password"
              placeholder="Confirm Password"
              value={signupData.confirmPassword}
              onChange={(e) => setSignupData({ ...signupData, confirmPassword: e.target.value })}
              required
            />
            <button type="submit">Create Account</button>
            {(error || localError) && <div className="error">{error || localError}</div>}
            {success && <div className="success">{success}</div>}
          </form>
        </div>
      </div>
    </div>
  );
}

// Dashboard Screen Component
function DashboardScreen({ user, role, token, onLogout }) {
  const [status, setStatus] = useState({ servers: {}, files: {}, fault_tolerance: 100 });
  const [loading, setLoading] = useState(true);
  const [uploadProgress, setUploadProgress] = useState([]);
  const refreshTimerRef = useRef(null);

  const loadStatus = async () => {
    try {
      const response = await fetch(`${MASTER_URL}/status`);
      const data = await response.json();
      setStatus(data);
      setLoading(false);
    } catch (err) {
      console.error('Error loading status:', err);
    }
  };

  useEffect(() => {
    loadStatus();
    refreshTimerRef.current = setInterval(loadStatus, REFRESH_INTERVAL);
    return () => {
      if (refreshTimerRef.current) clearInterval(refreshTimerRef.current);
    };
  }, []);

  const handleUpload = async (filename, content, isFile, encrypt) => {
    const uploadId = Date.now();
    setUploadProgress(prev => [...prev, { id: uploadId, filename, progress: 0, status: 'uploading' }]);

    try {
      const payload = {
        filename,
        encrypt,
        uploaded_by: user
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

      setUploadProgress(prev => prev.map(p => p.id === uploadId ? { ...p, progress: 50 } : p));

      const response = await fetch(`${CLIENT_URL}/upload`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      const data = await response.json();

      if (data.success) {
        setUploadProgress(prev => prev.map(p => p.id === uploadId ? { ...p, progress: 100, status: 'success' } : p));
        setTimeout(() => {
          setUploadProgress(prev => prev.filter(p => p.id !== uploadId));
          loadStatus();
        }, 2000);
      } else {
        setUploadProgress(prev => prev.map(p => p.id === uploadId ? { ...p, status: 'error' } : p));
      }
    } catch (err) {
      console.error('Upload error:', err);
      setUploadProgress(prev => prev.map(p => p.id === uploadId ? { ...p, status: 'error' } : p));
    }
  };

  const handleDownload = async (filename) => {
    try {
      const response = await fetch(`${MASTER_URL}/download/${filename}`);
      const data = await response.json();
      if (data.error) {
        alert('Download failed: ' + data.error);
        return;
      }
      let fileBlob;
      if (data.is_binary) {
        const binary = Uint8Array.from(atob(data.data), c => c.charCodeAt(0));
        fileBlob = new Blob([binary]);
      } else {
        fileBlob = new Blob([data.data], { type: 'text/plain' });
      }
      const link = document.createElement('a');
      link.href = URL.createObjectURL(fileBlob);
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      setTimeout(() => {
        document.body.removeChild(link);
        URL.revokeObjectURL(link.href);
      }, 150);
    } catch (err) {
      alert('Download failed: ' + err.message);
    }
  };

  const handleDelete = async (filename) => {
    if (!confirm(`Are you sure you want to delete ${filename}?`)) return;
    
    try {
      const response = await fetch(`${MASTER_URL}/delete_file`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ filename }),
      });
      
      const data = await response.json();
      if (data.success) {
        loadStatus();
      } else {
        alert('Delete failed: ' + data.error);
      }
    } catch (err) {
      console.error('Delete error:', err);
      alert('Delete failed: ' + err.message);
    }
  };

  if (loading) {
    return (
      <div className="screen active" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '100vh' }}>
        <div style={{ textAlign: 'center' }}>
          <div className="loading">
            <RefreshCw size={48} style={{ animation: 'spin 1s linear infinite' }} />
          </div>
          <p style={{ marginTop: '16px', color: '#fff' }}>Loading dashboard...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="screen active" id="dashboardScreen">
      <nav className="navbar">
        <div className="nav-left">
          <h1>🗄️ Mini GFS Dashboard</h1>
          <span className="role-badge">{role}</span>
        </div>
        <div className="nav-right">
          <span id="userName">{user}</span>
          <button onClick={onLogout} className="btn-secondary">Logout</button>
        </div>
      </nav>

      <div className="container">
        <div className={`dashboard-content ${role === 'user' ? 'active' : ''}`} id="userDashboard">
          {role === 'user' && (
            <UserDashboard
              status={status}
              user={user}
              onUpload={handleUpload}
              onDownload={handleDownload}
              onDelete={handleDelete}
              uploadProgress={uploadProgress}
            />
          )}
        </div>
        <div className={`dashboard-content ${role === 'manager' ? 'active' : ''}`} id="managerDashboard">
          {role === 'manager' && (
            <ManagerDashboard status={status} onRefresh={loadStatus} />
          )}
        </div>
        <div className={`dashboard-content ${role === 'admin' ? 'active' : ''}`} id="adminDashboard">
          {role === 'admin' && (
            <AdminDashboard status={status} onRefresh={loadStatus} />
          )}
        </div>
      </div>
    </div>
  );
}

// User Dashboard Component
function UserDashboard({ status, user, onUpload, onDownload, onDelete, uploadProgress }) {
  const [filename, setFilename] = useState('');
  const [content, setContent] = useState('');
  const [encrypt, setEncrypt] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [isDragging, setIsDragging] = useState(false);
  const [selectedFiles, setSelectedFiles] = useState([]);
  const fileInputRef = useRef(null);

  const userFiles = Object.entries(status.files).filter(([, info]) => info.uploaded_by === user);
  const filteredFiles = userFiles.filter(([name]) => 
    name.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const activeServers = Object.values(status.servers).filter(s => s.status === 'active').length;
  const totalServers = Object.keys(status.servers).length;

  const handleManualUpload = async () => {
    if (selectedFiles.length > 0) {
      for (const file of selectedFiles) {
        await onUpload(file.name, file, true, encrypt);
      }
      setSelectedFiles([]);
      setContent('');
    } else {
      if (!filename || !content) {
        alert('Please enter filename and content');
        return;
      }
      await onUpload(filename, content, false, encrypt);
      setFilename('');
      setContent('');
    }
  };

  const handleFileSelect = (e) => {
    const files = e.target.files;
    if (files.length > 0) {
      setSelectedFiles(Array.from(files));
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragging(false);
    const files = e.dataTransfer.files;
    if (files.length > 0) {
      setSelectedFiles(Array.from(files));
    }
  };

  return (
    <>
      {/* System Health Stats */}
      <div className="section">
        <h2>System Health</h2>
        <div className="stats-grid">
          <div className="stat-card">
            <h3>Active Servers</h3>
            <div className="stat-value">{activeServers}/{totalServers}</div>
          </div>
          <div className="stat-card">
            <h3>My Files</h3>
            <div className="stat-value">{userFiles.length}</div>
          </div>
          <div className="stat-card">
            <h3>Fault Tolerance</h3>
            <div className="stat-value">{status.fault_tolerance}%</div>
          </div>
        </div>
      </div>

      {/* Upload Section */}
      <div className="section">
        <h2>Upload File</h2>
        <div className="upload-section">
          <div
            className={`drag-drop-zone ${isDragging ? 'dragover' : ''}`}
            onDragOver={(e) => { e.preventDefault(); setIsDragging(true); }}
            onDragLeave={() => setIsDragging(false)}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
          >
            <p>📁 Drag & Drop files here</p>
            <small>or click to browse</small>
            <input
              ref={fileInputRef}
              type="file"
              id="fileInput"
              style={{ display: 'none' }}
              multiple
              onChange={handleFileSelect}
            />
            {selectedFiles.length > 0 && (
              <div style={{ marginTop: '10px', color: '#333' }}>
                <b>Selected files:</b>
                <ul style={{ margin: 0, paddingLeft: 20 }}>
                  {selectedFiles.map((file, idx) => (
                    <li key={idx}>{file.name}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>

          <div style={{ textAlign: 'center', color: '#666', margin: '10px 0' }}>OR</div>

          <input
            type="text"
            id="fileName"
            placeholder="Enter filename (e.g., document.txt)"
            value={filename}
            onChange={(e) => setFilename(e.target.value)}
            className="file-input"
          />
          <textarea
            id="fileContent"
            placeholder="Enter text content..."
            value={content}
            onChange={(e) => setContent(e.target.value)}
            className="file-textarea"
          />

          <div className="encryption-toggle">
            <input
              type="checkbox"
              id="encryptionEnabled"
              checked={encrypt}
              onChange={(e) => setEncrypt(e.target.checked)}
            />
            <label htmlFor="encryptionEnabled">
              <Lock size={16} style={{ verticalAlign: 'middle', marginRight: '5px' }} />
              Enable End-to-End Encryption
            </label>
          </div>

          <button onClick={handleManualUpload} id="uploadBtn" className="btn-primary">
            <Upload size={16} style={{ verticalAlign: 'middle', marginRight: '8px' }} />
            Upload File
          </button>

          {/* Upload Progress */}
          {uploadProgress.length > 0 && (
            <div className="progress-container" id="uploadProgress">
              {uploadProgress.map(upload => (
                <div key={upload.id} style={{ marginBottom: '15px' }}>
                  <div className="progress-label" style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    {upload.status === 'uploading' && <RefreshCw size={16} className="loading" />}
                    {upload.status === 'success' && <CheckCircle size={16} style={{ color: '#2ecc71' }} />}
                    {upload.status === 'error' && <XCircle size={16} style={{ color: '#e74c3c' }} />}
                    <span>{upload.filename}</span>
                  </div>
                  {upload.status === 'uploading' && (
                    <div className="progress-bar">
                      <div className="progress-fill" style={{ width: `${upload.progress}%` }}></div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Chunk Distribution */}
      <div className="section">
        <h2>Chunk Distribution</h2>
        <div className="servers-list">
          {Object.entries(status.servers).map(([id, info]) => (
            <div key={id} className={`server-card ${info.status}`}>
              <div className="server-header">
                <div className="server-name">{id}</div>
                <div className={`server-status ${info.status}`}>{info.status}</div>
              </div>
              <div className="server-info">Host: {info.host}:{info.port}</div>
              <div className="server-info">Last Heartbeat: {new Date(info.last_heartbeat * 1000).toLocaleTimeString()}</div>
            </div>
          ))}
        </div>
      </div>

      {/* My Files */}
      <div className="section">
        <h2>My Files</h2>
        {filteredFiles.length === 0 ? (
          <div className="empty-state">
            <p>No files uploaded yet</p>
          </div>
        ) : (
          <div className="files-list">
            {filteredFiles.map(([filename, info]) => (
              <div key={filename} className="file-card">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div style={{ flex: 1 }}>
                    <div className="file-name">📄 {filename}</div>
                    <div className="server-info">{new Date(info.upload_time).toLocaleString()}</div>
                    <div className="server-info">Uploaded by: {info.uploaded_by}</div>
                    <div className="server-info">Chunks: {info.chunks.length}</div>
                    <div className="file-chunks" style={{ marginTop: '10px' }}>
                      {info.chunks.map((chunk, i) => (
                        <span key={i} className="chunk-badge">{chunk}</span>
                      ))}
                    </div>
                  </div>
                  <div style={{ display: 'flex', gap: '10px' }}>
                    <button
                      onClick={() => onDownload(filename)}
                      className="btn-primary"
                      title="Download"
                    >
                      <Download size={16} />
                    </button>
                    <button
                      onClick={() => onDelete(filename)}
                      className="btn-danger"
                      title="Delete"
                    >
                      <Trash2 size={16} />
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </>
  );
}

// Manager Dashboard Component
function ManagerDashboard({ status, onRefresh }) {
  const activeServers = Object.values(status.servers).filter(s => s.status === 'active').length;
  const totalFiles = Object.keys(status.files).length;

  const simulateFailure = async (serverId) => {
    if (!confirm(`Simulate failure of ${serverId}?`)) return;
    
    try {
      await fetch(`${MASTER_URL}/simulate_failure`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ server_id: serverId }),
      });
    } catch (err) {
      console.error('Error simulating failure:', err);
    }
  };

  return (
    <>
      <div className="section">
        <h2>System Overview</h2>
        <div className="stats-grid">
          <div className="stat-card">
            <h3>Active Servers</h3>
            <div className="stat-value">{activeServers}/{Object.keys(status.servers).length}</div>
          </div>
          <div className="stat-card">
            <h3>Total Files</h3>
            <div className="stat-value">{totalFiles}</div>
          </div>
          <div className="stat-card">
            <h3>Fault Tolerance</h3>
            <div className="stat-value">{status.fault_tolerance}%</div>
          </div>
        </div>
      </div>

      <div className="section">
        <h2>Chunk Servers</h2>
        <div className="servers-list">
          {Object.entries(status.servers).map(([id, info]) => (
            <div key={id} className={`server-card ${info.status}`}>
              <div className="server-header">
                <div className="server-name">{id}</div>
                <div className={`server-status ${info.status}`}>{info.status}</div>
              </div>
              <div className="server-info">Host: {info.host}:{info.port}</div>
              <div className="server-info">Last: {new Date(info.last_heartbeat * 1000).toLocaleTimeString()}</div>
              {info.status === 'active' && (
                <div className="server-actions">
                  <button onClick={() => simulateFailure(id)} className="btn-danger">
                    Simulate Failure
                  </button>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      <div className="section">
        <h2>File Distribution</h2>
        <div className="files-list">
          {Object.entries(status.files).map(([filename, info]) => (
            <div key={filename} className="file-card">
              <div className="file-name">📄 {filename}</div>
              <div className="server-info">Uploaded: {new Date(info.upload_time).toLocaleString()}</div>
              <div className="server-info">Uploaded by: {info.uploaded_by}</div>
              <div className="server-info">Chunks: {info.chunks.length}</div>
              <div className="file-chunks" style={{ marginTop: '10px' }}>
                {info.chunks.map((chunk, i) => (
                  <span key={i} className="chunk-badge">{chunk}</span>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    </>
  );
}

// Admin Dashboard Component
function AdminDashboard({ status, onRefresh }) {
  const [users, setUsers] = useState([]);
  const [showAddUser, setShowAddUser] = useState(false);
  const [newUser, setNewUser] = useState({ username: '', password: '', role: 'user' });
  
  const activeServers = Object.values(status.servers).filter(s => s.status === 'active').length;
  const totalFiles = Object.keys(status.files).length;

  useEffect(() => {
    loadUsers();
  }, []);

  const loadUsers = async () => {
    try {
      const response = await fetch(`${MASTER_URL}/users`);
      const data = await response.json();
      setUsers(data.users || []);
    } catch (err) {
      console.error('Error loading users:', err);
    }
  };

  const handlePromote = async (username) => {
    try {
      const response = await fetch(`${MASTER_URL}/promote_user`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username }),
      });
      const data = await response.json();
      if (data.success) {
        loadUsers();
      }
    } catch (err) {
      console.error('Error promoting user:', err);
    }
  };

  const handleDemote = async (username) => {
    try {
      const response = await fetch(`${MASTER_URL}/demote_user`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username }),
      });
      const data = await response.json();
      if (data.success) {
        loadUsers();
      }
    } catch (err) {
      console.error('Error demoting user:', err);
    }
  };

  const handleAddUser = async (e) => {
    e.preventDefault();
    try {
      const response = await fetch(`${MASTER_URL}/create_user`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...newUser, created_by: 'admin' }),
      });
      const data = await response.json();
      if (data.success) {
        setShowAddUser(false);
        setNewUser({ username: '', password: '', role: 'user' });
        loadUsers();
      }
    } catch (err) {
      console.error('Error adding user:', err);
    }
  };

  const simulateFailure = async (serverId) => {
    if (!confirm(`Simulate failure of ${serverId}?`)) return;
    
    try {
      await fetch(`${MASTER_URL}/simulate_failure`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ server_id: serverId }),
      });
    } catch (err) {
      console.error('Error simulating failure:', err);
    }
  };

  return (
    <>
      <div className="section">
        <h2>System Status</h2>
        <div className="stats-grid">
          <div className="stat-card">
            <h3>Active Servers</h3>
            <div className="stat-value">{activeServers}/{Object.keys(status.servers).length}</div>
          </div>
          <div className="stat-card">
            <h3>Total Files</h3>
            <div className="stat-value">{totalFiles}</div>
          </div>
          <div className="stat-card">
            <h3>Fault Tolerance</h3>
            <div className="stat-value">{status.fault_tolerance}%</div>
          </div>
          <div className="stat-card">
            <h3>Total Users</h3>
            <div className="stat-value">{users.length}</div>
          </div>
        </div>
      </div>

      <div className="section">
        <h2>Chunk Servers</h2>
        <div className="servers-list">
          {Object.entries(status.servers).map(([id, info]) => (
            <div key={id} className={`server-card ${info.status}`}>
              <div className="server-header">
                <div className="server-name">{id}</div>
                <div className={`server-status ${info.status}`}>{info.status}</div>
              </div>
              <div className="server-info">Host: {info.host}:{info.port}</div>
              <div className="server-info">Last: {new Date(info.last_heartbeat * 1000).toLocaleTimeString()}</div>
              {info.status === 'active' && (
                <div className="server-actions">
                  <button onClick={() => simulateFailure(id)} className="btn-danger">
                    Simulate Failure
                  </button>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      <div className="section">
        <h2>User Management</h2>
        <div className="user-actions">
          <button onClick={() => setShowAddUser(true)} id="addUserBtn" className="btn-primary">
            + Add User
          </button>
        </div>

        {showAddUser && (
          <div className="modal active" id="addUserModal">
            <div className="modal-content">
              <span className="close" onClick={() => setShowAddUser(false)}>&times;</span>
              <h2>Add New User</h2>
              <form onSubmit={handleAddUser} id="addUserForm">
                <input
                  type="text"
                  placeholder="Username"
                  value={newUser.username}
                  onChange={(e) => setNewUser({ ...newUser, username: e.target.value })}
                  required
                />
                <input
                  type="password"
                  placeholder="Password"
                  value={newUser.password}
                  onChange={(e) => setNewUser({ ...newUser, password: e.target.value })}
                  required
                />
                <select
                  value={newUser.role}
                  onChange={(e) => setNewUser({ ...newUser, role: e.target.value })}
                >
                  <option value="user">User</option>
                  <option value="manager">Manager</option>
                </select>
                <div className="modal-actions">
                  <button type="submit" className="btn-primary">Create User</button>
                  <button type="button" onClick={() => setShowAddUser(false)} className="btn-secondary">
                    Cancel
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}

        <div className="users-table" id="usersTable">
          <div className="user-row">
            <div>Username</div>
            <div>Role</div>
            <div>Created By</div>
            <div>Actions</div>
          </div>
          {users.map((user) => (
            <div key={user.username} className="user-row">
              <div>{user.username}</div>
              <div>{user.role}</div>
              <div>{user.created_by}</div>
              <div>
                {user.role === 'user' && (
                  <button onClick={() => handlePromote(user.username)} className="btn-primary">
                    Promote to Manager
                  </button>
                )}
                {user.role === 'manager' && (
                  <button onClick={() => handleDemote(user.username)} className="btn-secondary">
                    Demote to User
                  </button>
                )}
                {user.role === 'admin' && <span>-</span>}
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="section">
        <h2>File Distribution</h2>
        <div className="files-list" id="filesList">
          {Object.keys(status.files).length === 0 ? (
            <div className="empty-state">
              <p>No files uploaded yet</p>
            </div>
          ) : (
            Object.entries(status.files).map(([filename, info]) => (
              <div key={filename} className="file-card">
                <div className="file-name">📄 {filename}</div>
                <div className="server-info">Uploaded: {new Date(info.upload_time).toLocaleString()}</div>
                <div className="server-info">Uploaded by: {info.uploaded_by}</div>
                <div className="server-info">Chunks: {info.chunks.length}</div>
                <div className="file-chunks" style={{ marginTop: '10px' }}>
                  {info.chunks.map((chunk, i) => (
                    <span key={i} className="chunk-badge">{chunk}</span>
                  ))}
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </>
  );
}
