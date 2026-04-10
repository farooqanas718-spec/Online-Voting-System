# NextGen Voting System (C Language & Vanilla JS SPA)

A completely bespoke, blisteringly fast, and architecturally strict voting management system built from scratch without Python or external high-level web frameworks.

## 🚀 Architectural Paradigm
- **Backend Core**: Written purely in C99.
- **Web Server**: `mongoose.c` (Embedded C Web Server) for asynchronous HTTP routing.
- **Database**: `sqlite3.c` native database wrapper without relying on third-party ORMs.
- **Cryptography**: Locally compiled SHA-256 for secure password encryption mappings.
- **Frontend Core**: A Single Page Application (SPA) driven entirely by Vanilla JavaScript (`fetch` API) and CSS3 animations (Glassmorphism), without Jinja2 or React overhead.

## 🛠 Prerequisites for Windows
- A Windows computer
- Admin privileges to run `.bat` files for compiler setup.

## ⚡ Installation & Execution
This system contains fully automated deployment scripts:
1. **Double-click `install_and_run.bat`**
   - Automatically downloads/installs the GCC C-Compiler (`w64devkit`) via Windows Package Manager.
   - Compiles the 5000+ lines of C codes into a `server.exe`.
   - Starts the local instance on `http://127.0.0.1:5000`

## ⚙️ Administration Toolkit
The codebase relies on executable batch scripts for database control rather than python command-line scripts:
- **`update_admin.bat <cnic> <email> <newpassword>`**: Natively hooks into the C process to bypass standard API rules and reset Administrator entries in SQLite.
- **`clear_voters.bat`**: Sweeps the database tables of non-admin personnel, candidate applications, and logged votes.
- **`clear_elections.bat`**: Recursively removes active campaigns and their associated candidates.
- **`reset_db.bat`**: Thermonuclear wipe of the entire database.

## 🛡️ Security Characteristics
- **Immutable Voting Validation**: The C SQL wrapper locks vote execution inside strict Unique Constraints (`user_id, election_id`) to ensure no double-submissions.
- **Dynamic Access Governance**: Elections inherently block access from the JS APIs unless the Admin backend flags a voter as explicitly "Eligible" for that election bridge pool.
