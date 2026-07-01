require('dotenv').config();

const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs/promises');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const DATA_FILE = path.join(__dirname, 'data', 'db.json');

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

if (process.env.TRUST_PROXY === '1') {
  app.set('trust proxy', 1);
}

app.use(session({
  secret: process.env.SESSION_SECRET || 'change-this-secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: false,
    maxAge: 1000 * 60 * 60 * 12
  }
}));

let db = { users: [], projects: [], tasks: [], notes: [] };
let writeQueue = Promise.resolve();

const id = () => crypto.randomUUID();
const now = () => new Date().toISOString();

async function loadDb() {
  try {
    db = JSON.parse(await fs.readFile(DATA_FILE, 'utf8'));
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
    await saveDb();
  }
  await migrateDb();
}

function ensureProjectDefaults(project) {
  project.status ??= 'planning';
  project.priority ??= 'medium';
  project.ownerId ??= project.createdBy || '';
  project.assigneeId ??= project.createdBy || '';
  project.labels = Array.isArray(project.labels) ? project.labels : [];
  project.startDate ??= '';
  project.dueDate ??= '';
  project.milestone ??= '';
  project.estimatePoints ??= '';
  project.progress ??= 0;
  project.blockedReason ??= '';
  project.updatedAt ??= project.createdAt || now();
}

function ensureTaskDefaults(task) {
  task.priority ??= 'medium';
  task.assigneeId ??= '';
  task.labels = Array.isArray(task.labels) ? task.labels : [];
  task.estimatePoints ??= '';
  task.updatedAt ??= task.createdAt || now();
}

async function migrateDb() {
  db.users ||= [];
  db.projects ||= [];
  db.tasks ||= [];
  db.notes ||= [];

  let changed = false;

  db.users.forEach((user, index) => {
    if (!user.role) {
      user.role = index === 0 ? 'admin' : 'member';
      changed = true;
    }
    if (typeof user.disabled !== 'boolean') {
      user.disabled = false;
      changed = true;
    }
  });

  const activeUserIds = db.users.filter(user => !user.disabled).map(user => user.id);

  db.projects.forEach(project => {
    const before = JSON.stringify(project);
    ensureProjectDefaults(project);
    project.members = [...activeUserIds];
    if (JSON.stringify(project) !== before) {
      changed = true;
    }
  });

  db.tasks.forEach(task => {
    const before = JSON.stringify(task);
    ensureTaskDefaults(task);
    if (JSON.stringify(task) !== before) {
      changed = true;
    }
  });

  if (changed) {
    await saveDb();
  }
}

function saveDb() {
  writeQueue = writeQueue.then(async () => {
    await fs.mkdir(path.dirname(DATA_FILE), { recursive: true });
    const tempFile = `${DATA_FILE}.tmp`;
    await fs.writeFile(tempFile, JSON.stringify(db, null, 2), 'utf8');
    await fs.rename(tempFile, DATA_FILE);
  });
  return writeQueue;
}

const currentUser = req => db.users.find(user => user.id === req.session.userId) || null;
const isAdmin = user => user?.role === 'admin' && !user.disabled;
const activeUsers = () => db.users.filter(user => !user.disabled);

function requireAuth(req, res, next) {
  const user = currentUser(req);
  if (!user) return res.redirect('/login');
  if (user.disabled) {
    return req.session.destroy(() => res.status(403).render('login', {
      error: 'This account is disabled. Contact the admin.'
    }));
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!isAdmin(currentUser(req))) {
    return res.status(403).send('Admin access required');
  }
  next();
}

function projectForUser(projectId, user) {
  if (!user || user.disabled) return null;
  return db.projects.find(project => project.id === projectId) || null;
}

function syncProjectMembers() {
  const userIds = activeUsers().map(user => user.id);
  db.projects.forEach(project => {
    project.members = [...userIds];
  });
}

function getUserName(userId) {
  return db.users.find(user => user.id === userId)?.name || 'Unassigned';
}

function enrichProject(project) {
  const taskCount = db.tasks.filter(task => task.projectId === project.id).length;
  const openCount = db.tasks.filter(task => task.projectId === project.id && task.status !== 'done').length;
  return {
    ...project,
    taskCount,
    openCount,
    ownerName: getUserName(project.ownerId),
    assigneeName: getUserName(project.assigneeId)
  };
}

function enrichTask(task) {
  return {
    ...task,
    author: getUserName(task.createdBy),
    assigneeName: getUserName(task.assigneeId)
  };
}

app.use((req, res, next) => {
  res.locals.user = currentUser(req);
  res.locals.isAdmin = isAdmin(res.locals.user);
  res.locals.error = null;
  next();
});

app.get('/', (req, res) => {
  res.redirect(req.session.userId ? '/projects' : '/login');
});

app.get('/login', (req, res) => {
  res.render('login');
});

app.post('/login', async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const user = db.users.find(item => item.email === email);

  if (!user || user.disabled || !(await bcrypt.compare(password, user.passwordHash))) {
    return res.status(401).render('login', {
      error: 'Invalid email or password, or the account is disabled.'
    });
  }

  req.session.userId = user.id;
  res.redirect('/projects');
});

app.get('/register', (req, res) => {
  res.render('register', {
    error: process.env.ALLOW_SELF_REGISTRATION === '1'
      ? null
      : 'Registration is admin-controlled. Ask the admin to create your account.'
  });
});

app.post('/register', async (req, res) => {
  if (process.env.ALLOW_SELF_REGISTRATION !== '1') {
    return res.status(403).render('register', {
      error: 'Registration is admin-controlled. Ask the admin to create your account.'
    });
  }

  const name = String(req.body.name || '').trim();
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const inviteCode = String(req.body.inviteCode || '');

  if (inviteCode !== process.env.INVITE_CODE) {
    return res.status(403).render('register', { error: 'Invalid invite code.' });
  }

  if (!name || !email || password.length < 8) {
    return res.status(400).render('register', {
      error: 'Name, valid email, and an 8+ character password are required.'
    });
  }

  if (db.users.some(user => user.email === email)) {
    return res.status(409).render('register', {
      error: 'This email is already registered.'
    });
  }

  const newUser = {
    id: id(),
    name,
    email,
    role: 'member',
    disabled: false,
    passwordHash: await bcrypt.hash(password, 12),
    createdAt: now()
  };

  db.users.push(newUser);
  syncProjectMembers();
  await saveDb();
  req.session.userId = newUser.id;
  res.redirect('/projects');
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

app.get('/admin/users', requireAuth, requireAdmin, (req, res) => {
  res.render('admin-users', { users: db.users });
});

app.post('/admin/users', requireAuth, requireAdmin, async (req, res) => {
  const name = String(req.body.name || '').trim();
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const role = req.body.role === 'admin' ? 'admin' : 'member';

  if (!name || !email || password.length < 8) {
    return res.status(400).render('admin-users', {
      users: db.users,
      error: 'Name, valid email, and an 8+ character password are required.'
    });
  }

  if (db.users.some(user => user.email === email)) {
    return res.status(409).render('admin-users', {
      users: db.users,
      error: 'This email is already registered.'
    });
  }

  db.users.push({
    id: id(),
    name,
    email,
    role,
    disabled: false,
    passwordHash: await bcrypt.hash(password, 12),
    createdAt: now()
  });

  syncProjectMembers();
  await saveDb();
  res.redirect('/admin/users');
});

app.post('/admin/users/:userId/role', requireAuth, requireAdmin, async (req, res) => {
  const user = db.users.find(item => item.id === req.params.userId);
  if (!user) return res.status(404).send('User not found');
  user.role = req.body.role === 'admin' ? 'admin' : 'member';
  user.updatedAt = now();
  await saveDb();
  res.redirect('/admin/users');
});

app.post('/admin/users/:userId/toggle', requireAuth, requireAdmin, async (req, res) => {
  const user = db.users.find(item => item.id === req.params.userId);
  if (!user) return res.status(404).send('User not found');
  if (user.id === req.session.userId) {
    return res.status(400).send('You cannot disable your own admin account.');
  }
  user.disabled = !user.disabled;
  user.updatedAt = now();
  syncProjectMembers();
  await saveDb();
  res.redirect('/admin/users');
});

app.get('/projects', requireAuth, (req, res) => {
  res.render('projects', {
    projects: db.projects.map(enrichProject)
  });
});

app.post('/projects', requireAuth, requireAdmin, async (req, res) => {
  const name = String(req.body.name || '').trim();
  const description = String(req.body.description || '').trim();

  if (!name) {
    return res.redirect('/projects');
  }

  db.projects.push({
    id: id(),
    name,
    description,
    status: 'planning',
    priority: 'medium',
    ownerId: req.session.userId,
    assigneeId: req.session.userId,
    labels: [],
    startDate: '',
    dueDate: '',
    milestone: '',
    estimatePoints: '',
    progress: 0,
    blockedReason: '',
    members: activeUsers().map(user => user.id),
    createdBy: req.session.userId,
    createdAt: now(),
    updatedAt: now()
  });

  await saveDb();
  res.redirect('/projects');
});

app.get('/projects/:projectId', requireAuth, (req, res) => {
  const project = projectForUser(req.params.projectId, currentUser(req));
  if (!project) return res.status(404).send('Project not found');

  const tasks = db.tasks
    .filter(task => task.projectId === project.id)
    .map(enrichTask);

  const notes = db.notes
    .filter(note => note.projectId === project.id)
    .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
    .map(note => ({ ...note, author: getUserName(note.createdBy) }));

  res.render('project', {
    project: enrichProject(project),
    tasks,
    notes,
    users: activeUsers()
  });
});

app.post('/projects/:projectId/update', requireAuth, requireAdmin, async (req, res) => {
  const project = db.projects.find(item => item.id === req.params.projectId);
  if (!project) return res.status(404).send('Project not found');

  project.name = String(req.body.name || '').trim() || project.name;
  project.description = String(req.body.description || '').trim();
  project.status = String(req.body.status || project.status || 'planning');
  project.priority = String(req.body.priority || project.priority || 'medium');
  project.ownerId = String(req.body.ownerId || project.ownerId || '');
  project.assigneeId = String(req.body.assigneeId || project.assigneeId || '');
  project.labels = String(req.body.labels || '')
    .split(',')
    .map(item => item.trim())
    .filter(Boolean);
  project.startDate = String(req.body.startDate || '');
  project.dueDate = String(req.body.dueDate || '');
  project.milestone = String(req.body.milestone || '');
  project.estimatePoints = String(req.body.estimatePoints || '');
  project.progress = Math.max(0, Math.min(100, Number(req.body.progress || 0) || 0));
  project.blockedReason = String(req.body.blockedReason || '').trim();
  project.updatedAt = now();

  await saveDb();
  res.redirect(`/projects/${project.id}`);
});

app.post('/projects/:projectId/delete', requireAuth, requireAdmin, async (req, res) => {
  const project = db.projects.find(item => item.id === req.params.projectId);
  if (!project) return res.status(404).send('Project not found');

  db.projects = db.projects.filter(item => item.id !== project.id);
  db.tasks = db.tasks.filter(task => task.projectId !== project.id);
  db.notes = db.notes.filter(note => note.projectId !== project.id);

  await saveDb();
  res.redirect('/projects');
});

app.post('/projects/:projectId/tasks', requireAuth, async (req, res) => {
  const project = projectForUser(req.params.projectId, currentUser(req));
  if (!project) return res.status(404).send('Project not found');

  const title = String(req.body.title || '').trim();
  const description = String(req.body.description || '').trim();

  if (title) {
    db.tasks.push({
      id: id(),
      projectId: project.id,
      title,
      description,
      status: 'backlog',
      priority: String(req.body.priority || 'medium'),
      assigneeId: String(req.body.assigneeId || ''),
      labels: String(req.body.labels || '')
        .split(',')
        .map(item => item.trim())
        .filter(Boolean),
      estimatePoints: String(req.body.estimatePoints || ''),
      createdBy: req.session.userId,
      createdAt: now(),
      updatedAt: now()
    });
    await saveDb();
  }

  res.redirect(`/projects/${project.id}`);
});

app.post('/tasks/:taskId/status', requireAuth, async (req, res) => {
  const task = db.tasks.find(item => item.id === req.params.taskId);
  if (!task || !projectForUser(task.projectId, currentUser(req))) {
    return res.status(404).send('Task not found');
  }

  if (['backlog', 'progress', 'done'].includes(req.body.status)) {
    task.status = req.body.status;
    task.updatedAt = now();
    await saveDb();
  }

  res.redirect(`/projects/${task.projectId}`);
});

app.post('/tasks/:taskId/delete', requireAuth, async (req, res) => {
  const task = db.tasks.find(item => item.id === req.params.taskId);
  if (!task || !projectForUser(task.projectId, currentUser(req))) {
    return res.status(404).send('Task not found');
  }

  db.tasks = db.tasks.filter(item => item.id !== task.id);
  await saveDb();
  res.redirect(`/projects/${task.projectId}`);
});

app.post('/projects/:projectId/notes', requireAuth, async (req, res) => {
  const project = projectForUser(req.params.projectId, currentUser(req));
  if (!project) return res.status(404).send('Project not found');

  const body = String(req.body.body || '').trim();
  if (body) {
    db.notes.push({
      id: id(),
      projectId: project.id,
      body,
      createdBy: req.session.userId,
      createdAt: now()
    });
    await saveDb();
  }

  res.redirect(`/projects/${project.id}#notes`);
});

app.post('/notes/:noteId/delete', requireAuth, async (req, res) => {
  const note = db.notes.find(item => item.id === req.params.noteId);
  if (!note || !projectForUser(note.projectId, currentUser(req))) {
    return res.status(404).send('Note not found');
  }

  db.notes = db.notes.filter(item => item.id !== note.id);
  await saveDb();
  res.redirect(`/projects/${note.projectId}#notes`);
});

async function bootstrapAdmin() {
  if (db.users.length > 0) return;

  const email = String(process.env.ADMIN_EMAIL || '').trim().toLowerCase();
  const password = String(process.env.ADMIN_PASSWORD || '');
  const name = String(process.env.ADMIN_NAME || 'Admin').trim();

  if (!email || password.length < 8) {
    console.warn('No admin created. Set ADMIN_EMAIL and ADMIN_PASSWORD in .env.');
    return;
  }

  db.users.push({
    id: id(),
    name,
    email,
    role: 'admin',
    disabled: false,
    passwordHash: await bcrypt.hash(password, 12),
    createdAt: now()
  });

  await saveDb();
  console.log(`Bootstrap admin created: ${email}`);
}

loadDb()
  .then(bootstrapAdmin)
  .then(() => app.listen(PORT, '127.0.0.1', () => {
    console.log(`Team Notes Board running at http://127.0.0.1:${PORT}`);
  }))
  .catch(error => {
    console.error(error);
    process.exit(1);
  });
