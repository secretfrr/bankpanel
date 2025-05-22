require('dotenv').config();

const PORT = process.env.PORT || 3001;
const SESSION_SECRET = process.env.SESSION_SECRET || 'default_secret';
const SESSION_AGE = parseInt(process.env.SESSION_AGE) || 10 * 60000; // 10 minutes

const path = require('path');
const express = require('express');
const app = express();
const exec = require("child_process").exec;
const fs = require('fs');
const os = require('os');
const util = require('util');
const execPromise = util.promisify(exec);
const osUtils = require('os-utils');
const bcrypt = require('bcryptjs');
const low = require('lowdb');
const FileSync = require('lowdb/adapters/FileSync');
const si = require('systeminformation');

// Database setup
const adapter = new FileSync('data/users.json');
const db = low(adapter);

// Set defaults without admin user
db.defaults({
    users: []
}).write();

// Check if setup is needed (no users exist)
const requiresSetup = () => {
    return db.get('users').size().value() === 0;
};

// Middleware for setup check
const checkSetup = (req, res, next) => {
    if (requiresSetup() && !req.path.startsWith('/setup')) {
        res.redirect('/setup');
    } else {
        next();
    }
};

// Add setup check middleware before other middleware
app.use(checkSetup);

// Cache para throttling
let processCache = null;
let lastUpdate = 0;
const CACHE_DURATION = 800;

var session = require('express-session');

// Use the session middleware with required options
app.use(session({
    secret: SESSION_SECRET,
    cookie: { maxAge: SESSION_AGE },
    resave: false,
    saveUninitialized: false
}));

// Middleware de autenticação
const requireAuth = (req, res, next) => {
    if (req.session.islogin) {
        next();
    } else {
        res.redirect('/login');
    }
};

const requireAdmin = (req, res, next) => {
    if (req.session.islogin && req.session.userRole === 'admin') {
        next();
    } else {
        res.status(403).json({ error: 'Admin access required' });
    }
};

// Helper functions for user management
const findUser = (username) => {
    return db.get('users').find({ username }).value();
};

const validatePassword = async (password, hash) => {
    return await bcrypt.compare(password, hash);
};

const hashPassword = async (password) => {
    return await bcrypt.hash(password, 10);
};

// caminho do src path
app.use('/src', express.static(path.join(__dirname, 'src')));

// for parse post
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.get('/', requireAuth, function (req, res) {
    res.sendFile(path.join(__dirname, 'pages/index.html'));
});

app.get('/login', function (req, res) {
    if (req.session.islogin) {
        res.redirect('/');
        return;
    }
    res.sendFile(path.join(__dirname, 'pages/login.html'));
});

app.post('/loginCheck', async function (req, res) {
    const { username, password } = req.body;
    const user = findUser(username);

    if (user && await validatePassword(password, user.password)) {
        req.session.islogin = true;
        req.session.userRole = user.role;
        req.session.username = username;
        res.redirect('/');
    } else {
        res.redirect('/login?err=invalid_credentials');
    }
});

// Setup routes
app.get('/setup', (req, res) => {
    if (!requiresSetup()) {
        return res.redirect('/');
    }
    res.sendFile(path.join(__dirname, 'pages/setup.html'));
});

app.post('/setup', async (req, res) => {
    if (!requiresSetup()) {
        return res.redirect('/');
    }

    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }

    const hashedPassword = await hashPassword(password);
    
    db.get('users')
        .push({ username, password: hashedPassword, role: 'admin' })
        .write();

    res.redirect('/login');
});

// Proteger todas as rotas com autenticação
app.get('/getProccess', requireAuth, async function (req, res) {
    const now = Date.now();
    
    // Se temos cache válido, retorna ele
    if (processCache && (now - lastUpdate) < CACHE_DURATION) {
        return res.json(processCache);
    }

    try {
        // First get the list of processes
        const { stdout: listOutput } = await execPromise("pm2 jlist");
        
        try {
            const processes = JSON.parse(listOutput.trim());
            
            if (!Array.isArray(processes)) {
                throw new Error('Invalid process list format');
            }

            // Safely map the processes with default values for undefined properties
            const enhancedProcesses = processes.map(process => ({
                pm_id: process.pm_id || 0,
                name: process.name || 'Unknown',
                pid: process.pid || 0,
                pm2_env: {
                    status: (process.pm2_env && process.pm2_env.status) || 'unknown',
                    restart_time: (process.pm2_env && process.pm2_env.restart_time) || 0,
                    pm_uptime: (process.pm2_env && process.pm2_env.pm_uptime) || Date.now()
                },
                monit: {
                    cpu: (process.monit && typeof process.monit.cpu === 'number') ? process.monit.cpu : 0,
                    memory: (process.monit && typeof process.monit.memory === 'number') ? process.monit.memory : 0
                }
            }));

            // Atualiza o cache
            processCache = enhancedProcesses;
            lastUpdate = now;

            res.json(enhancedProcesses);
        } catch (parseError) {
            console.error('Parse Error:', parseError);
            console.error('Raw output:', listOutput);
            res.status(500).json({ 
                error: 'Failed to parse process list',
                details: parseError.message
            });
        }
    } catch (error) {
        console.error('Execution Error:', error);
        res.status(500).json({ 
            error: 'Failed to execute PM2 command',
            details: error.message
        });
    }
});

// Limpar cache quando houver alterações nos processos
function clearProcessCache() {
    processCache = null;
    lastUpdate = 0;
}

// Limpar cache nas operações que modificam processos
app.post('/addProccess', requireAuth, function (req, res) {
    clearProcessCache();

    req.session.islogin = true;

    if (!req.body.path) {
        return res.status(400).json({
            success: false,
            message: 'Process path is required'
        });
    }

    if (!fs.existsSync(req.body.path)) {
        return res.status(400).json({
            success: false,
            message: 'File does not exist'
        });
    }

    const command = `pm2 start "${req.body.path}"${req.body.name ? ` --name "${req.body.name}"` : ''}${req.body.args ? ' -- ' + req.body.args : ''}`;
    
    exec(command, (error, stdout, stderr) => {
        if (error) {
            req.session.notication = `Error: ${error.message}`;
            return res.status(500).json({
                success: false,
                message: error.message
            });
        }
        
        req.session.notication = `Process ${req.body.name || req.body.path} started successfully`;
        res.json({
            success: true,
            message: 'Process started successfully'
        });
    });
});

app.get('/restart', requireAuth, function (req, res) {
    clearProcessCache();

    // check id exists
    if (req.query.id) {
        // restart the process
        exec("pm2 restart " + req.query.id, (error, stdout, stderr) => {
            if (error != null) {
                req.session.notication = error + stderr;
            } else {
                req.session.notication = 'Process by id: ' + req.query.id + ' restarted successfully';
            }
            res.redirect('/');
        });
    } else {
        req.session.notication = 'No process ID provided.';
        res.redirect('/');
    }
});

app.get('/start', requireAuth, function (req, res) {
    clearProcessCache();

    // send json header
    if (!req.session.islogin) {
        res.writeHead(302, {
            'Location': '/login'
        });
        res.end();

    } else {
        // check id exits
        if (req.query.id) {
            // start the process
            exec("pm2 start " + req.query.id, (error, stdout, stderr) => {
                res.writeHead(302, {
                    'Location': '/'
                });
                // req.session.notication = error + '\n--------\n' + stdout + '\n--------\n' + stderr;
                if (error != null) {
                    req.session.notication = error + stderr;
                } else {
                    req.session.notication = 'Process by id :' + req.query.id + ' started successfully';
                }
                res.end();
            });

        }

    }
});

app.get('/stop', requireAuth, function (req, res) {
    clearProcessCache();

    // check id exits
    if (req.query.id) {
            // stop the process
            exec("pm2 stop " + req.query.id, (error, stdout, stderr) => {
                res.writeHead(302, {
                    'Location': '/'
                });
                // req.session.notication = error + '\n--------\n' + stdout + '\n--------\n' + stderr;
                if (error != null) {
                    req.session.notication = error + stderr;
                } else {
                    req.session.notication = 'Process by id :' + req.query.id + ' stopped successfully';
                }
                res.end();
            });

        }
});

app.get('/delete', requireAuth, function (req, res) {
    clearProcessCache();

    // check id exits
    if (req.query.id) {
            // delete the process
            exec("pm2 delete " + req.query.id, (error, stdout, stderr) => {
                res.writeHead(302, {
                    'Location': '/'
                });
                // req.session.notication = error + '\n--------\n' + stdout + '\n--------\n' + stderr;
                if (error != null) {
                    req.session.notication = error + stderr;
                } else {
                    req.session.notication = 'Process by id :' + req.query.id + ' deleted successfully';
                }
                res.end();
            });

        }
});

app.get('/dump', requireAuth, function (req, res) {
        // save process
        exec("pm2 save", (error, stdout, stderr) => {
            res.writeHead(302, {
                'Location': '/'
            });
            //req.session.notication = error + '\n--------\n' + stdout + '\n--------\n' + stderr;
            if (error != null) {
                req.session.notication = error + stderr;
            } else {
                req.session.notication = 'current procceses dumped ( saved ) successfully';
            }
            res.end();
        });
});

app.get('/notification', requireAuth, function (req, res) {
    if (!req.session.notication) {
            res.write('-');
        } else {
            var message = req.session.notication;
            delete req.session.notication;
            res.write(message);
        }
        res.end();
});

app.get('/logout', function (req, res) {
    req.session.destroy();
    res.redirect('/login');
});

app.get('/log', requireAuth, function (req, res) {
    if (req.query.id) {
        const proc = require('child_process').spawn("pm2", ['log', req.query.id, '--lines', '100']);
        let logs = '';

        proc.stdout.on('data', (data) => {
            logs += data;
        });

        proc.stderr.on('data', (data) => {
            logs += data;
        });

        proc.on('close', () => {
            res.send(logs);
        });
    } else {
        res.status(400).send('Process ID required');
    }
});

app.get('/system-stats', requireAuth, async function (req, res) {
    try {
        // Get total memory info
        const totalMem = os.totalmem();
        const freeMem = os.freemem();
        const usedMem = totalMem - freeMem;
        const memoryUsage = ((usedMem / totalMem) * 100).toFixed(1);
        
        // Use os-utils para obter o uso real do CPU
        const getCPUUsage = () => {
            return new Promise((resolve) => {
                osUtils.cpuUsage((value) => {
                    resolve((value * 100).toFixed(1));
                });
            });
        };

        const cpuUsage = await getCPUUsage();
        
        res.json({
            cpu: cpuUsage,
            memory: `${memoryUsage}% (${(usedMem / (1024 * 1024 * 1024)).toFixed(1)} GB)`
        });
    } catch (error) {
        console.error('Error getting system stats:', error);
        res.status(500).json({
            cpu: '0.0',
            memory: 'N/A'
        });
    }
});

app.get('/api/system-info', requireAuth, async function(req, res) {
    try {
        const [cpu, mem, osInfo, fsSize, time, networkStats, cpuInfo] = await Promise.all([
            si.cpu(),
            si.mem(),
            si.osInfo(),
            si.fsSize(),
            si.time(),
            si.networkStats(),
            si.currentLoad()
        ]);

        // Get the root filesystem or first available filesystem
        const systemDrive = fsSize[0];
        const diskUsedPercentage = systemDrive ? ((systemDrive.used / systemDrive.size) * 100).toFixed(1) : '0.0';
        const diskTotal = systemDrive ? (systemDrive.size / (1024 * 1024 * 1024)).toFixed(1) : '0.0';
        const diskUsed = systemDrive ? (systemDrive.used / (1024 * 1024 * 1024)).toFixed(1) : '0.0';
        const diskFree = systemDrive ? ((systemDrive.size - systemDrive.used) / (1024 * 1024 * 1024)).toFixed(1) : '0.0';

        // Format memory values to GB
        const totalMemGB = (mem.total / (1024 * 1024 * 1024)).toFixed(1);
        const usedMemGB = ((mem.total - mem.available) / (1024 * 1024 * 1024)).toFixed(1);
        const memPercentage = ((1 - mem.available / mem.total) * 100).toFixed(1);

        // Calculate network throughput
        const networkIn = networkStats.reduce((sum, stat) => sum + (stat.rx_sec || 0), 0);
        const networkOut = networkStats.reduce((sum, stat) => sum + (stat.tx_sec || 0), 0);

        // Format uptime
        const uptime = time.uptime;
        const days = Math.floor(uptime / (24 * 3600));
        const hours = Math.floor((uptime % (24 * 3600)) / 3600);
        const minutes = Math.floor((uptime % 3600) / 60);

        const response = {
            cpu: {
                model: cpu.manufacturer + ' ' + cpu.brand,
                cores: `${cpu.physicalCores} Physical / ${cpu.cores} Logical`,
                speed: `${cpu.speed} GHz`,
                utilization: `${cpuInfo.currentLoad ? cpuInfo.currentLoad.toFixed(1) : '0.0'}%`
            },
            memory: {
                total: `${totalMemGB} GB`,
                used: `${usedMemGB} GB (${memPercentage}%)`,
                free: `${(mem.available / (1024 * 1024 * 1024)).toFixed(1)} GB`
            },
            os: {
                platform: osInfo.platform,
                distro: osInfo.distro,
                release: osInfo.release,
                arch: osInfo.arch,
                hostname: os.hostname()
            },
            storage: {
                drive: systemDrive ? systemDrive.mount : '/',
                total: `${diskTotal} GB`,
                used: `${diskUsed} GB`,
                free: `${diskFree} GB`,
                usage: `${diskUsedPercentage}%`
            },
            network: {
                input: `${(networkIn / (1024 * 1024)).toFixed(2)} MB/s`,
                output: `${(networkOut / (1024 * 1024)).toFixed(2)} MB/s`
            },
            uptime: days ? `${days}d ${hours}h ${minutes}m` : hours ? `${hours}h ${minutes}m` : `${minutes}m`
        };

        res.json(response);
    } catch (error) {
        console.error('Error getting system info:', error);
        res.status(500).json({ error: 'Failed to retrieve system information' });
    }
});

app.get('/api/users', requireAdmin, (req, res) => {
    const users = db.get('users')
        .map(user => ({ username: user.username, role: user.role }))
        .value();
    res.json(users);
});

app.post('/api/users', requireAdmin, async (req, res) => {
    const { username, password, role } = req.body;
    
    if (!username || !password || !role || !['admin', 'user'].includes(role)) {
        return res.status(400).json({ error: 'Invalid user data' });
    }

    const existingUser = findUser(username);
    if (existingUser) {
        return res.status(409).json({ error: 'Username already exists' });
    }

    const hashedPassword = await hashPassword(password);
    
    db.get('users')
        .push({ username, password: hashedPassword, role })
        .write();

    res.json({ success: true, message: 'User created successfully' });
});

app.delete('/api/users/:username', requireAdmin, (req, res) => {
    const { username } = req.params;
    
    if (username === 'admin') {
        return res.status(403).json({ error: 'Cannot delete admin user' });
    }

    const user = findUser(username);
    if (!user) {
        return res.status(404).json({ error: 'User not found' });
    }

    db.get('users')
        .remove({ username })
        .write();

    res.json({ success: true, message: 'User deleted successfully' });
});

app.put('/api/users/:username', requireAdmin, async (req, res) => {
    const { username } = req.params;
    const { password, role } = req.body;
    
    if (username === 'admin' && role !== 'admin') {
        return res.status(403).json({ error: 'Cannot change admin role' });
    }

    const user = findUser(username);
    if (!user) {
        return res.status(404).json({ error: 'User not found' });
    }

    const updates = {};
    if (password) {
        updates.password = await hashPassword(password);
    }
    if (role && ['admin', 'user'].includes(role)) {
        updates.role = role;
    }

    db.get('users')
        .find({ username })
        .assign(updates)
        .write();

    res.json({ success: true, message: 'User updated successfully' });
});

app.get('/api/current-user', requireAuth, (req, res) => {
    const username = req.session.username;
    const role = req.session.userRole;
    res.json({ username, role });
});

app.listen(PORT, () => {
    console.log(`
  🚀 Bank Panel is running on:
     ➤ Local:   http://localhost:${PORT}
     ➤ PM2:     Listening on port ${PORT}
    `);
});
