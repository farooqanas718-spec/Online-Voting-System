// DOM Elements
const views = {
    login: document.getElementById('view-login'),
    dashboard: document.getElementById('view-dashboard'),
    admin: document.getElementById('view-admin')
};

const modal = {
    overlay: document.getElementById('modal-overlay'),
    title: document.getElementById('modal-title'),
    body: document.getElementById('modal-body'),
    confirm: document.getElementById('btn-modal-confirm'),
    close: document.getElementById('btn-modal-close')
};

// State
let session = {
    user_id: null,
    is_admin: 0,
    cnic: null
};

// View Navigation
function switchView(viewName) {
    Object.values(views).forEach(v => {
        v.classList.remove('active-view');
        v.classList.add('hidden-view');
    });
    views[viewName].classList.remove('hidden-view');
    views[viewName].classList.add('active-view');
}

// Modal Control
function openModal(title, contentHTML, onConfirm) {
    modal.title.textContent = title;
    modal.body.innerHTML = contentHTML;
    modal.overlay.classList.add('active-view');
    
    modal.confirm.onclick = async () => {
        const btn = modal.confirm;
        btn.disabled = true;
        try {
            await onConfirm();
            closeModal();
        } catch(e) {
            console.error(e);
        } finally {
            btn.disabled = false;
        }
    };
}

function closeModal() {
    modal.overlay.classList.remove('active-view');
}
modal.close.onclick = closeModal;

// Authentication
document.getElementById('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const cnic = document.getElementById('cnic').value;
    const password = document.getElementById('password').value;
    
    const btn = e.target.querySelector('button');
    btn.disabled = true;
    
    try {
        const res = await API.post('/api/auth/login', { cnic, password });
        session.user_id = res.user_id;
        session.is_admin = res.is_admin;
        session.cnic = cnic;
        
        Toast.show('Authentication successful.', 'success');
        
        if (session.is_admin) {
            switchView('admin');
            loadAdminData();
        } else {
            switchView('dashboard');
            document.getElementById('nav-user-cnic').textContent = cnic;
            loadVoterData();
        }
    } catch (e) {
        // Error already handled by Toast in utils.js
    } finally {
        btn.disabled = false;
    }
});

// Admin Features
function loadAdminData() {
    // Demo implementation
    const adminPanel = document.getElementById('admin-data-view');
    adminPanel.innerHTML = '<h4>System status: Active</h4><p>Use the administrative controls on the left to manage the NextGen Voting system.</p>';
}

document.getElementById('btn-create-voter').addEventListener('click', () => {
    openModal('Register New Voter', `
        <div class="input-group">
            <label>Voter CNIC</label>
            <input type="text" id="new-voter-cnic" placeholder="0000000000000">
        </div>
        <div class="input-group">
            <label>Name</label>
            <input type="text" id="new-voter-name" placeholder="John Doe">
        </div>
        <div class="input-group">
            <label>Email</label>
            <input type="email" id="new-voter-email" placeholder="john@example.com">
        </div>
        <div class="input-group">
            <label>Initial Password</label>
            <input type="text" id="new-voter-pass" placeholder="GeneratedPass123">
        </div>
    `, async () => {
        const cnic = document.getElementById('new-voter-cnic').value;
        const name = document.getElementById('new-voter-name').value;
        const email = document.getElementById('new-voter-email').value;
        const password = document.getElementById('new-voter-pass').value;
        
        await API.post('/api/admin/users/create', { cnic, name, email, password });
        Toast.show('Voter registered successfully.', 'success');
    });
});

// Logout handlers
document.getElementById('btn-logout').addEventListener('click', () => { session = {}; switchView('login'); });
document.getElementById('btn-admin-logout').addEventListener('click', () => { session = {}; switchView('login'); });
