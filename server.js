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

let db = { users: [], teams: [], projects: [], tasks: [], notes: [], timeLogs: [] };
let writeQueue = Promise.resolve();

const id = () => crypto.randomUUID();
const now = () => new Date().toISOString();
const asArray = value => Array.isArray(value) ? value : value ? [value] : [];
const unique = items => [...new Set(items.filter(Boolean))];

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
  project.teamIds = Array.isArray(project.teamIds) ? project.teamIds : [];
  project.memberIds = Array.isArray(project.memberIds)
    ? project.memberIds
    : Array.isArray(project.members) ? project.members : [];
  project.updatedAt ??= project.createdAt || now();
}

function ensureTaskDefaults(task) {
  task.priority ??= 'medium';
  task.assigneeId ??= '';
  task.labels = Array.isArray(task.labels) ? task.labels : [];
  task.estimatePoints ??= '';
  task.timeSpentMinutes ??= 0;
  task.updatedAt ??= task.createdAt || now();
}

function ensureTeamDefaults(team) {
  team.description ??= '';
  team.leadId ??= '';
  team.memberIds = Array.isArray(team.memberIds) ? team.memberIds : [];
  team.createdAt ??= now();
  team.updatedAt ??= team.createdAt;
}

async function migrateDb() {
  db.users ||= [];
  db.teams ||= [];
  db.projects ||= [];
  db.tasks ||= [];
  db.notes ||= [];
  db.timeLogs ||= [];

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
    user.title ??= '';
    user.department ??= '';
    user.contactNumber ??= '';
  });

  db.teams.forEach(team => {
    const before = JSON.stringify(team);
    ensureTeamDefaults(team);
    team.memberIds = unique(team.memberIds.filter(userId => db.users.some(user => user.id === userId)));
    if (team.leadId && !db.users.some(user => user.id === team.leadId)) team.leadId = '';
    if (JSON.stringify(team) !== before) changed = true;
  });

  const activeUserIds = db.users.filter(user => !user.disabled).map(user => user.id);

  db.projects.forEach(project => {
    const before = JSON.stringify(project);
    ensureProjectDefaults(project);
    project.memberIds = unique(project.memberIds.filter(userId => db.users.some(user => user.id === userId)));
    project.teamIds = unique(project.teamIds.filter(teamId => db.teams.some(team => team.id === teamId)));
    if (!project.memberIds.length && !project.teamIds.length) {
      project.memberIds = [...activeUserIds];
    }
    if (!project.memberIds.includes(project.ownerId) && project.ownerId) project.memberIds.push(project.ownerId);
    if (!project.memberIds.includes(project.assigneeId) && project.assigneeId) project.memberIds.push(project.assigneeId);
    project.members = project.memberIds;
    if (JSON.stringify(project) !== before) changed = true;
  });

  db.tasks.forEach(task => {
    const before = JSON.stringify(task);
    ensureTaskDefaults(task);
    if (JSON.stringify(task) !== before) changed = true;
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
const activeTeams = () => db.teams;

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

function userTeamIds(userId) {
  return db.teams.filter(team => team.memberIds.includes(userId)).map(team => team.id);
}

function canAccessProject(project, user) {
  if (!project || !user || user.disabled) return false;
  if (isAdmin(user)) return true;
  const teams = userTeamIds(user.id);
  return project.memberIds?.includes(user.id)
    || project.ownerId === user.id
    || project.assigneeId === user.id
    || project.teamIds?.some(teamId => teams.includes(teamId));
}

function projectForUser(projectId, user) {
  const project = db.projects.find(item => item.id === projectId) || null;
  return canAccessProject(project, user) ? project : null;
}

function visibleProjects(user) {
  return db.projects.filter(project => canAccessProject(project, user));
}

function getUserName(userId) {
  return db.users.find(user => user.id === userId)?.name || 'Unassigned';
}

function getTeamName(teamId) {
  return db.teams.find(team => team.id === teamId)?.name || 'Unknown team';
}

function getProjectUsers(project) {
  const teamMemberIds = db.teams
    .filter(team => project.teamIds.includes(team.id))
    .flatMap(team => team.memberIds);
  const ids = unique([
    ...(project.memberIds || []),
    ...teamMemberIds,
    project.ownerId,
    project.assigneeId
  ]);
  return activeUsers().filter(user => ids.includes(user.id));
}

function completionRate(projectId) {
  const tasks = db.tasks.filter(task => task.projectId === projectId);
  if (!tasks.length) return 0;
  return Math.round((tasks.filter(task => task.status === 'done').length / tasks.length) * 100);
}

function enrichProject(project) {
  const tasks = db.tasks.filter(task => task.projectId === project.id);
  const openCount = tasks.filter(task => task.status !== 'done').length;
  const loggedMinutes = db.timeLogs
    .filter(log => log.projectId === project.id)
    .reduce((total, log) => total + Number(log.minutes || 0), 0);
  return {
    ...project,
    taskCount: tasks.length,
    openCount,
    doneCount: tasks.length - openCount,
    completionRate: completionRate(project.id),
    loggedMinutes,
    ownerName: getUserName(project.ownerId),
    assigneeName: getUserName(project.assigneeId),
    teamNames: (project.teamIds || []).map(getTeamName),
    memberNames: (project.memberIds || []).map(getUserName)
  };
}

function enrichTask(task) {
  return {
    ...task,
    author: getUserName(task.createdBy),
    assigneeName: getUserName(task.assigneeId),
    timeLogs: db.timeLogs
      .filter(log => log.taskId === task.id)
      .map(log => ({ ...log, author: getUserName(log.createdBy) }))
  };
}

function parseLabels(labels) {
  return String(labels || '')
    .split(',')
    .map(item => item.trim())
    .filter(Boolean);
}

function pickValidUserIds(values) {
  const validIds = activeUsers().map(user => user.id);
  return unique(asArray(values).filter(userId => validIds.includes(userId)));
}

function pickValidTeamIds(values) {
  const validIds = activeTeams().map(team => team.id);
  return unique(asArray(values).filter(teamId => validIds.includes(teamId)));
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
    title: '',
    department: '',
    disabled: false,
    passwordHash: await bcrypt.hash(password, 12),
    createdAt: now()
  };

  db.users.push(newUser);
  await saveDb();
  req.session.userId = newUser.id;
  res.redirect('/projects');
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});


app.get('/account', requireAuth, (req, res) => {
  res.render('account', { account: currentUser(req), success: null });
});

app.post('/account', requireAuth, async (req, res) => {
  const user = currentUser(req);
  if (!user) return res.redirect('/login');

  const email = String(req.body.email || '').trim().toLowerCase();
  const contactNumber = String(req.body.contactNumber || '').trim();
  const currentPassword = String(req.body.currentPassword || '');
  const newPassword = String(req.body.newPassword || '');
  const confirmPassword = String(req.body.confirmPassword || '');

  if (!email) {
    return res.status(400).render('account', { account: user, success: null, error: 'Email is required.' });
  }

  if (db.users.some(item => item.id !== user.id && item.email === email)) {
    return res.status(409).render('account', { account: user, success: null, error: 'Another account already uses this email.' });
  }

  if (newPassword || confirmPassword) {
    if (!currentPassword || !(await bcrypt.compare(currentPassword, user.passwordHash))) {
      return res.status(400).render('account', { account: user, success: null, error: 'Current password is required to change password.' });
    }
    if (newPassword.length < 8) {
      return res.status(400).render('account', { account: user, success: null, error: 'New password must be at least 8 characters.' });
    }
    if (newPassword !== confirmPassword) {
      return res.status(400).render('account', { account: user, success: null, error: 'New password and confirmation do not match.' });
    }
    user.passwordHash = await bcrypt.hash(newPassword, 12);
  }

  user.email = email;
  user.contactNumber = contactNumber;
  user.updatedAt = now();
  await saveDb();
  res.render('account', { account: user, success: 'Account updated.' });
});

app.get('/admin/users', requireAuth, requireAdmin, (req, res) => {
  res.render('admin-users', { users: db.users, teams: db.teams });
});

app.post('/admin/users', requireAuth, requireAdmin, async (req, res) => {
  const name = String(req.body.name || '').trim();
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const role = req.body.role === 'admin' ? 'admin' : 'member';
  const title = String(req.body.title || '').trim();
  const department = String(req.body.department || '').trim();
  const contactNumber = String(req.body.contactNumber || '').trim();

  if (!name || !email || password.length < 8) {
    return res.status(400).render('admin-users', {
      users: db.users,
      teams: db.teams,
      error: 'Name, valid email, and an 8+ character password are required.'
    });
  }

  if (db.users.some(user => user.email === email)) {
    return res.status(409).render('admin-users', {
      users: db.users,
      teams: db.teams,
      error: 'This email is already registered.'
    });
  }

  db.users.push({
    id: id(),
    name,
    email,
    role,
    title,
    department,
    contactNumber,
    disabled: false,
    passwordHash: await bcrypt.hash(password, 12),
    createdAt: now()
  });

  await saveDb();
  res.redirect('/admin/users');
});

app.post('/admin/users/:userId/role', requireAuth, requireAdmin, async (req, res) => {
  const user = db.users.find(item => item.id === req.params.userId);
  if (!user) return res.status(404).send('User not found');
  user.role = req.body.role === 'admin' ? 'admin' : 'member';
  user.title = String(req.body.title || '').trim();
  user.department = String(req.body.department || '').trim();
  user.contactNumber = String(req.body.contactNumber || '').trim();
  user.updatedAt = now();
  await saveDb();
  res.redirect('/admin/users');
});

app.post('/admin/users/:userId/update', requireAuth, requireAdmin, async (req, res) => {
  const user = db.users.find(item => item.id === req.params.userId);
  if (!user) return res.status(404).send('User not found');

  const name = String(req.body.name || '').trim();
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');

  if (!name || !email) {
    return res.status(400).render('admin-users', {
      users: db.users,
      teams: db.teams,
      error: 'Name and email are required.'
    });
  }

  if (db.users.some(item => item.id !== user.id && item.email === email)) {
    return res.status(409).render('admin-users', {
      users: db.users,
      teams: db.teams,
      error: 'Another user already uses this email.'
    });
  }

  if (user.id === req.session.userId && req.body.disabled === '1') {
    return res.status(400).render('admin-users', {
      users: db.users,
      teams: db.teams,
      error: 'You cannot disable your own admin account.'
    });
  }

  user.name = name;
  user.email = email;
  user.role = req.body.role === 'admin' ? 'admin' : 'member';
  user.title = String(req.body.title || '').trim();
  user.department = String(req.body.department || '').trim();
  user.contactNumber = String(req.body.contactNumber || '').trim();
  user.disabled = req.body.disabled === '1';
  if (password) {
    if (password.length < 8) {
      return res.status(400).render('admin-users', {
        users: db.users,
        teams: db.teams,
        error: 'New password must be at least 8 characters.'
      });
    }
    user.passwordHash = await bcrypt.hash(password, 12);
  }
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
  await saveDb();
  res.redirect('/admin/users');
});

app.get('/admin/teams', requireAuth, requireAdmin, (req, res) => {
  const teams = db.teams.map(team => ({
    ...team,
    leadName: getUserName(team.leadId),
    members: activeUsers().filter(user => team.memberIds.includes(user.id)),
    projectCount: db.projects.filter(project => project.teamIds.includes(team.id)).length
  }));
  res.render('admin-teams', { teams, users: activeUsers() });
});

app.post('/admin/teams', requireAuth, requireAdmin, async (req, res) => {
  const name = String(req.body.name || '').trim();
  const description = String(req.body.description || '').trim();
  const leadId = String(req.body.leadId || '');
  const memberIds = pickValidUserIds(req.body.memberIds);

  if (!name) {
    const teams = db.teams.map(team => ({ ...team, leadName: getUserName(team.leadId), members: [], projectCount: 0 }));
    return res.status(400).render('admin-teams', { teams, users: activeUsers(), error: 'Team name is required.' });
  }

  db.teams.push({
    id: id(),
    name,
    description,
    leadId: activeUsers().some(user => user.id === leadId) ? leadId : '',
    memberIds,
    createdAt: now(),
    updatedAt: now()
  });

  await saveDb();
  res.redirect('/admin/teams');
});

app.post('/admin/teams/:teamId/update', requireAuth, requireAdmin, async (req, res) => {
  const team = db.teams.find(item => item.id === req.params.teamId);
  if (!team) return res.status(404).send('Team not found');

  team.name = String(req.body.name || '').trim() || team.name;
  team.description = String(req.body.description || '').trim();
  const leadId = String(req.body.leadId || '');
  team.leadId = activeUsers().some(user => user.id === leadId) ? leadId : '';
  team.memberIds = pickValidUserIds(req.body.memberIds);
  team.updatedAt = now();

  await saveDb();
  res.redirect('/admin/teams');
});

app.post('/admin/teams/:teamId/delete', requireAuth, requireAdmin, async (req, res) => {
  const team = db.teams.find(item => item.id === req.params.teamId);
  if (!team) return res.status(404).send('Team not found');
  db.teams = db.teams.filter(item => item.id !== team.id);
  db.projects.forEach(project => {
    project.teamIds = (project.teamIds || []).filter(teamId => teamId !== team.id);
    project.updatedAt = now();
  });
  await saveDb();
  res.redirect('/admin/teams');
});

app.get('/projects', requireAuth, (req, res) => {
  const user = currentUser(req);
  const projects = visibleProjects(user).map(enrichProject);
  const totalTasks = projects.reduce((total, project) => total + project.taskCount, 0);
  const openTasks = projects.reduce((total, project) => total + project.openCount, 0);
  res.render('projects', {
    projects,
    users: activeUsers(),
    teams: activeTeams(),
    stats: {
      projects: projects.length,
      totalTasks,
      openTasks,
      completedTasks: totalTasks - openTasks
    }
  });
});

app.post('/projects', requireAuth, requireAdmin, async (req, res) => {
  const name = String(req.body.name || '').trim();
  const description = String(req.body.description || '').trim();

  if (!name) {
    return res.redirect('/projects');
  }

  const teamIds = pickValidTeamIds(req.body.teamIds);
  const memberIds = pickValidUserIds(req.body.memberIds);
  const ownerId = String(req.body.ownerId || req.session.userId);
  const assigneeId = String(req.body.assigneeId || req.session.userId);

  db.projects.push({
    id: id(),
    name,
    description,
    status: 'planning',
    priority: String(req.body.priority || 'medium'),
    ownerId: activeUsers().some(user => user.id === ownerId) ? ownerId : req.session.userId,
    assigneeId: activeUsers().some(user => user.id === assigneeId) ? assigneeId : req.session.userId,
    labels: parseLabels(req.body.labels),
    startDate: String(req.body.startDate || ''),
    dueDate: String(req.body.dueDate || ''),
    milestone: String(req.body.milestone || ''),
    estimatePoints: String(req.body.estimatePoints || ''),
    progress: 0,
    blockedReason: '',
    teamIds,
    memberIds: unique([...memberIds, ownerId, assigneeId].filter(Boolean)),
    members: unique([...memberIds, ownerId, assigneeId].filter(Boolean)),
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
    users: getProjectUsers(project),
    allUsers: activeUsers(),
    teams: activeTeams()
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
  project.labels = parseLabels(req.body.labels);
  project.startDate = String(req.body.startDate || '');
  project.dueDate = String(req.body.dueDate || '');
  project.milestone = String(req.body.milestone || '');
  project.estimatePoints = String(req.body.estimatePoints || '');
  project.progress = Math.max(0, Math.min(100, Number(req.body.progress || 0) || 0));
  project.blockedReason = String(req.body.blockedReason || '').trim();
  project.teamIds = pickValidTeamIds(req.body.teamIds);
  project.memberIds = unique([...pickValidUserIds(req.body.memberIds), project.ownerId, project.assigneeId].filter(Boolean));
  project.members = project.memberIds;
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
  db.timeLogs = db.timeLogs.filter(log => log.projectId !== project.id);

  await saveDb();
  res.redirect('/projects');
});

app.post('/projects/:projectId/tasks', requireAuth, async (req, res) => {
  const project = projectForUser(req.params.projectId, currentUser(req));
  if (!project) return res.status(404).send('Project not found');

  const title = String(req.body.title || '').trim();
  const description = String(req.body.description || '').trim();
  const validAssignees = getProjectUsers(project).map(user => user.id);
  const assigneeId = String(req.body.assigneeId || '');

  if (title) {
    db.tasks.push({
      id: id(),
      projectId: project.id,
      title,
      description,
      status: 'backlog',
      priority: String(req.body.priority || 'medium'),
      assigneeId: validAssignees.includes(assigneeId) ? assigneeId : '',
      labels: parseLabels(req.body.labels),
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

  if (['backlog', 'progress', 'review', 'done'].includes(req.body.status)) {
    task.status = req.body.status;
    task.updatedAt = now();
    await saveDb();
  }

  res.redirect(`/projects/${task.projectId}`);
});

app.post('/tasks/:taskId/update', requireAuth, async (req, res) => {
  const task = db.tasks.find(item => item.id === req.params.taskId);
  const project = task ? projectForUser(task.projectId, currentUser(req)) : null;
  if (!task || !project) {
    return res.status(404).send('Task not found');
  }

  const nextAssigneeId = String(req.body.assigneeId || '');
  const validAssignees = getProjectUsers(project).map(user => user.id);
  if (nextAssigneeId && !validAssignees.includes(nextAssigneeId)) {
    return res.status(400).send('Invalid assignee');
  }

  task.title = String(req.body.title || '').trim() || task.title;
  task.description = String(req.body.description || '').trim();
  task.status = ['backlog', 'progress', 'review', 'done'].includes(req.body.status) ? req.body.status : task.status;
  task.priority = ['low', 'medium', 'high', 'critical'].includes(req.body.priority) ? req.body.priority : task.priority;
  task.assigneeId = nextAssigneeId;
  task.labels = parseLabels(req.body.labels);
  task.estimatePoints = String(req.body.estimatePoints || '');
  task.updatedAt = now();

  await saveDb();
  res.redirect(`/projects/${task.projectId}#task-${task.id}`);
});

app.post('/tasks/:taskId/assignee', requireAuth, async (req, res) => {
  const task = db.tasks.find(item => item.id === req.params.taskId);
  const project = task ? projectForUser(task.projectId, currentUser(req)) : null;
  if (!task || !project) {
    return res.status(404).send('Task not found');
  }

  const nextAssigneeId = String(req.body.assigneeId || '');
  const validAssignees = getProjectUsers(project).map(user => user.id);
  if (nextAssigneeId && !validAssignees.includes(nextAssigneeId)) {
    return res.status(400).send('Invalid assignee');
  }

  task.assigneeId = nextAssigneeId;
  task.updatedAt = now();
  await saveDb();
  res.redirect(`/projects/${task.projectId}#task-${task.id}`);
});

app.post('/tasks/:taskId/time', requireAuth, async (req, res) => {
  const task = db.tasks.find(item => item.id === req.params.taskId);
  if (!task || !projectForUser(task.projectId, currentUser(req))) {
    return res.status(404).send('Task not found');
  }

  const minutes = Math.max(0, Math.round(Number(req.body.minutes || 0) || 0));
  const note = String(req.body.note || '').trim();
  if (minutes > 0) {
    task.timeSpentMinutes = Number(task.timeSpentMinutes || 0) + minutes;
    task.updatedAt = now();
    db.timeLogs.push({
      id: id(),
      taskId: task.id,
      projectId: task.projectId,
      minutes,
      note,
      createdBy: req.session.userId,
      createdAt: now()
    });
    await saveDb();
  }

  res.redirect(`/projects/${task.projectId}#task-${task.id}`);
});

app.post('/tasks/:taskId/delete', requireAuth, async (req, res) => {
  const task = db.tasks.find(item => item.id === req.params.taskId);
  if (!task || !projectForUser(task.projectId, currentUser(req))) {
    return res.status(404).send('Task not found');
  }

  db.tasks = db.tasks.filter(item => item.id !== task.id);
  db.timeLogs = db.timeLogs.filter(log => log.taskId !== task.id);
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
    title: 'Workspace admin',
    department: 'Operations',
    contactNumber: '',
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
