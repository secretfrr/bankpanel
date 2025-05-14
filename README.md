# Flux Panel - Modern PM2 Process Manager

A modern, web-based process manager for PM2. It provides an elegant and user-friendly interface to manage your PM2 processes, monitor system resources, and handle user access control.

## 🚀 Features

- 🎯 Modern and intuitive UI with dark theme
- 👥 Multi-user support with role-based access control
- 📊 Real-time process monitoring
  - CPU and memory usage tracking
  - Process uptime monitoring
  - Restart count tracking
  - Status monitoring
- 💻 System resource statistics
  - CPU usage
  - Memory usage
  - Disk usage
  - Network stats
  - System information
- 🔄 Process Management
  - Start/Stop/Restart processes
  - Delete processes
  - Custom process naming
  - Command line arguments support
  - Process logs viewer
- 🔍 Search and filtering capabilities
- 💾 Process dump/save functionality
- 📱 Responsive design for all devices

## 📋 Requirements

- Node.js (v12 or higher)
- PM2 installed globally (`npm install -g pm2`)
- Modern web browser

## 🔧 Installation

1. Clone the repository:
```bash
https://github.com/SterTheStar/fluxpanel.git
cd fluxpanel
```

2. Install dependencies:
```bash
npm install
```

3. Create a `.env` file in the root directory:
```env
PORT=3001
SESSION_SECRET=your_secret_key_here
SESSION_AGE=600000  # 10 minutes in milliseconds
```

4. Start the application:
```bash
node fluxmain.js
```

The panel will be available at `http://localhost:3001`

## 🔒 First Time Setup

When you first access the panel, you'll be prompted to create an admin user. This is a one-time setup process.

## 🛠️ Configuration Options

The following environment variables can be configured:

- `PORT`: The port number for the web interface (default: 3001)
- `SESSION_SECRET`: Secret key for session management
- `SESSION_AGE`: Session duration in milliseconds (default: 10 minutes)

## 👥 User Management

### Roles and Permissions

#### Admin
- Full access to all features
- Create/Edit/Delete users
- Manage processes
- Access system settings
- View system statistics

#### User
- View processes
- Start/Stop/Restart processes
- View process logs
- View system statistics

## 🔌 API Endpoints

### Authentication
- `POST /loginCheck` - User authentication
- `GET /logout` - User logout
- `GET /api/current-user` - Get current user info

### Process Management
- `GET /getProccess` - List all processes
- `POST /addProccess` - Add new process with optional name
- `GET /restart` - Restart a process
- `GET /start` - Start a process
- `GET /stop` - Stop a process
- `GET /delete` - Delete a process
- `GET /dump` - Save current process list
- `GET /log` - View process logs

### User Management
- `GET /api/users` - List all users (Admin only)
- `POST /api/users` - Create new user (Admin only)
- `PUT /api/users/:username` - Update user (Admin only)
- `DELETE /api/users/:username` - Delete user (Admin only)

### System Information
- `GET /system-stats` - Get CPU and memory usage
- `GET /api/system-info` - Get detailed system information

## 🔐 Security Features

- Session-based authentication
- Password hashing using bcrypt
- Role-based access control
- Session timeout management
- Secure API endpoints
- XSS protection

## 🌐 Browser Compatibility

- Chrome (recommended)
- Firefox
- Safari
- Edge

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 🙌 Acknowledgements

This project was inspired by and partially based on the work of [4xmen/pm2panel](https://github.com/4xmen/pm2panel).  
Special thanks to the original creators for their excellent work, which served as a foundation and reference for several parts of this panel.

Please consider visiting their repository and supporting their project!


## 📄 License

This project is licensed under the GNU General Public v3.0 License

---

Made with ❤️ by Esther (Vênus)
