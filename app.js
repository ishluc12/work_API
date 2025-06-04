require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');

const app = express();
const port = process.env.PORT || 3000;

// CORS configuration
app.use(cors({
  origin: ['http://localhost:5173', 'https://your-frontend-domain.com'],
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

// Import database utilities
const { pool, getConnection, isInitialized } = require('./db.js');

// Middleware
app.use(bodyParser.json());

// Add request logging middleware
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});

// Database availability middleware
const checkDatabaseAvailability = (req, res, next) => {
  if (!isInitialized()) {
    return res.status(503).json({ 
      message: 'Database is currently unavailable. Please try again later.',
      status: 'service_unavailable'
    });
  }
  next();
};

// JWT utilities
function generateToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username },
    process.env.JWT_SECRET || 'default_jwt_secret',
    { expiresIn: process.env.JWT_EXPIRY || '1h' }
  );
}

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ message: 'Missing token' });

  try {
    const user = jwt.verify(token, process.env.JWT_SECRET || 'default_jwt_secret');
    req.user = user;
    next();
  } catch (err) {
    return res.status(403).json({ message: 'Invalid or expired token' });
  }
}

// Database health check route
app.get('/health', async (req, res) => {
  try {
    const client = await getConnection();
    const result = await client.query('SELECT NOW() as current_time, version() as pg_version');
    client.release();
    
    res.json({ 
      status: 'healthy', 
      database: 'connected',
      timestamp: new Date().toISOString(),
      server_time: result.rows[0].current_time,
      database_version: result.rows[0].pg_version.split(' ')[0] + ' ' + result.rows[0].pg_version.split(' ')[1]
    });
  } catch (err) {
    console.error('Health check failed:', err);
    res.status(500).json({ 
      status: 'unhealthy', 
      database: 'disconnected',
      error: err.message,
      timestamp: new Date().toISOString()
    });
  }
});

// Welcome route
app.get('/', (req, res) => {
  res.json({ 
    message: 'Welcome to the API. Please register or log in to continue.',
    endpoints: {
      health: '/health',
      signup: 'POST /signup',
      login: 'POST /login',
      users: 'GET /users (requires auth)',
      products: 'GET /products (requires auth)'
    }
  });
});

// Public: Signup
app.post('/signup', checkDatabaseAvailability, async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required' });
  }

  if (password.length < 6) {
    return res.status(400).json({ message: 'Password must be at least 6 characters long' });
  }

  let client;
  try {
    client = await getConnection();
    const hashed = await bcrypt.hash(password, 10);
    const result = await client.query(
      'INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id, username, created_at',
      [username, hashed]
    );
    const token = generateToken(result.rows[0]);
    res.status(201).json({ 
      message: 'User registered successfully', 
      token,
      user: {
        id: result.rows[0].id,
        username: result.rows[0].username,
        created_at: result.rows[0].created_at
      }
    });
  } catch (err) {
    console.error('Signup error:', err);
    if (err.code === '23505') {
      return res.status(409).json({ message: 'Username already exists' });
    }
    res.status(500).json({ message: 'Signup failed', error: err.message });
  } finally {
    if (client) client.release();
  }
});

// Public: Login
app.post('/login', checkDatabaseAvailability, async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required' });
  }

  let client;
  try {
    client = await getConnection();
    const result = await client.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ message: 'Invalid username or password' });
    }

    const token = generateToken(user);
    res.json({ 
      message: 'Login successful', 
      token,
      user: {
        id: user.id,
        username: user.username
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ message: 'Login failed', error: err.message });
  } finally {
    if (client) client.release();
  }
});

// Protected routes
app.get('/users', authenticateToken, checkDatabaseAvailability, async (req, res) => {
  let client;
  try {
    client = await getConnection();
    const result = await client.query('SELECT id, username, created_at FROM users ORDER BY created_at DESC');
    res.status(200).json(result.rows);
  } catch (err) {
    console.error('Get users error:', err);
    res.status(500).json({ message: 'Error fetching users', error: err.message });
  } finally {
    if (client) client.release();
  }
});

app.get('/user/:id', authenticateToken, checkDatabaseAvailability, async (req, res) => {
  const { id } = req.params;
  let client;
  try {
    client = await getConnection();
    const result = await client.query('SELECT id, username, created_at FROM users WHERE id = $1', [id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.status(200).json(result.rows[0]);
  } catch (err) {
    console.error('Get user error:', err);
    res.status(500).json({ message: 'Error fetching user', error: err.message });
  } finally {
    if (client) client.release();
  }
});

// Get all products
app.get('/products', authenticateToken, checkDatabaseAvailability, async (req, res) => {
  let client;
  try {
    client = await getConnection();
    const result = await client.query('SELECT * FROM product ORDER BY currentstamp DESC');
    res.status(200).json(result.rows);
  } catch (err) {
    console.error('Get products error:', err);
    res.status(500).json({ message: 'Error fetching products', error: err.message });
  } finally {
    if (client) client.release();
  }
});

// Get product by ID
app.get('/product/:id', authenticateToken, checkDatabaseAvailability, async (req, res) => {
  const { id } = req.params;
  let client;
  try {
    client = await getConnection();
    const result = await client.query('SELECT * FROM product WHERE product_id = $1', [id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Product not found' });
    }
    res.status(200).json(result.rows[0]);
  } catch (err) {
    console.error('Get product error:', err);
    res.status(500).json({ message: 'Error fetching product', error: err.message });
  } finally {
    if (client) client.release();
  }
});

// Create new products
app.post('/products', authenticateToken, checkDatabaseAvailability, async (req, res) => {
  const productsToCreate = req.body;
  if (!Array.isArray(productsToCreate)) {
    return res.status(400).json({ message: 'Request body must be an array of products' });
  }

  let client;
  try {
    client = await getConnection();
    await client.query('BEGIN');
    
    const results = [];
    for (const product of productsToCreate) {
      const { product_name, description, quantity, price } = product;
      
      if (!product_name || quantity === undefined || price === undefined) {
        throw new Error('Missing required fields: product_name, quantity, price');
      }
      
      const result = await client.query(
        'INSERT INTO product (product_name, description, quantity, price) VALUES ($1, $2, $3, $4) RETURNING *',
        [product_name, description || '', quantity, price]
      );
      results.push(result.rows[0]);
    }
    
    await client.query('COMMIT');
    res.status(201).json(results);
  } catch (err) {
    if (client) await client.query('ROLLBACK');
    console.error('Create products error:', err);
    res.status(500).json({ message: 'Error creating products', error: err.message });
  } finally {
    if (client) client.release();
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ message: 'Internal server error', error: err.message });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ message: 'Route not found' });
});

// Start server
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
  console.log(`Health check available at http://localhost:${port}/health`);
  console.log(`API documentation at http://localhost:${port}/`);
});