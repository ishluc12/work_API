require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');

const app = express();
const port = process.env.PORT || 3000;

// Import database utilities
const { pool, getConnection, isInitialized } = require('./db.js');

// Enhanced CORS configuration
const corsOptions = {
  origin: function (origin, callback) {
    console.log('CORS Origin:', origin); // Debug logging

    // Allow requests with no origin (like mobile apps, Postman, curl requests)
    if (!origin) {
      console.log('No origin - allowing request');
      return callback(null, true);
    }

    // Development environment - allow all localhost and 127.0.0.1 origins
    if (process.env.NODE_ENV !== 'production') {
      if (origin.match(/^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/)) {
        console.log('Development localhost origin allowed:', origin);
        return callback(null, true);
      }
    }

    // Production allowed origins
    const productionOrigins = [
      'https://your-frontend-domain.com',
      'https://your-flutter-web-domain.com',
      'https://work-api-hkoq.onrender.com' // Add your deployed frontend URL here
    ];

    // Development allowed origins (specific ports if needed)
    const developmentOrigins = [
      'http://localhost:3000',
      'http://localhost:5173',
      'http://localhost:7293',
      'http://localhost:8080',
      'http://localhost:9111', // Flutter web default
      'http://127.0.0.1:3000',
      'http://127.0.0.1:5173',
      'http://127.0.0.1:7293',
      'http://127.0.0.1:8080',
      'http://127.0.0.1:9111'
    ];

    const allowedOrigins = process.env.NODE_ENV === 'production'
      ? productionOrigins
      : [...productionOrigins, ...developmentOrigins];

    if (allowedOrigins.includes(origin)) {
      console.log('Origin allowed:', origin);
      callback(null, true);
    } else {
      console.log('Origin blocked:', origin);
      // In development, be more permissive
      if (process.env.NODE_ENV !== 'production') {
        console.log('Development mode - allowing origin anyway');
        callback(null, true);
      } else {
        callback(new Error(`Origin ${origin} not allowed by CORS policy`));
      }
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'],
  allowedHeaders: [
    'Origin',
    'X-Requested-With',
    'Content-Type',
    'Accept',
    'Authorization',
    'Cache-Control',
    'Pragma'
  ],
  exposedHeaders: ['Authorization'],
  credentials: true,
  optionsSuccessStatus: 200, // Some legacy browsers (IE11, various SmartTVs) choke on 204
  maxAge: 86400 // 24 hours
};

// Apply CORS middleware
app.use(cors(corsOptions));

// Handle preflight requests explicitly
app.options('*', cors(corsOptions));

// Additional CORS headers middleware (fallback)
app.use((req, res, next) => {
  const origin = req.headers.origin;

  // Set CORS headers manually as fallback
  if (origin) {
    res.header('Access-Control-Allow-Origin', origin);
  }
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,PATCH,OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization, Cache-Control, Pragma');
  res.header('Access-Control-Max-Age', '86400');

  // Handle preflight
  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  next();
});

// Body parser middleware
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));

// Request logging middleware
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path} - Origin: ${req.headers.origin || 'No Origin'}`);
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
    { expiresIn: process.env.JWT_EXPIRY || '24h' }
  );
}

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({
      message: 'Access token required',
      error: 'MISSING_TOKEN'
    });
  }

  try {
    const user = jwt.verify(token, process.env.JWT_SECRET || 'default_jwt_secret');
    req.user = user;
    next();
  } catch (err) {
    console.error('Token verification failed:', err.message);
    return res.status(403).json({
      message: 'Invalid or expired token',
      error: 'INVALID_TOKEN'
    });
  }
}

// Error handling middleware for CORS
app.use((err, req, res, next) => {
  if (err.message && err.message.includes('CORS')) {
    console.error('CORS Error:', err.message);
    return res.status(403).json({
      message: 'CORS policy violation',
      error: err.message,
      origin: req.headers.origin
    });
  }
  next(err);
});

// Routes

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
      database_version: result.rows[0].pg_version.split(' ')[0] + ' ' + result.rows[0].pg_version.split(' ')[1],
      cors: 'enabled',
      environment: process.env.NODE_ENV || 'development'
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
    version: '1.0.0',
    environment: process.env.NODE_ENV || 'development',
    cors: 'enabled',
    endpoints: {
      health: 'GET /health',
      signup: 'POST /signup',
      login: 'POST /login',
      users: 'GET /users (requires auth)',
      user: 'GET /user/:id (requires auth)',
      products: 'GET /products (requires auth)',
      product: 'GET /product/:id (requires auth)',
      createProducts: 'POST /products (requires auth)'
    }
  });
});

// Public: Signup
app.post('/signup', checkDatabaseAvailability, async (req, res) => {
  console.log('Signup request received:', { username: req.body.username });

  const { username, password, email } = req.body;

  if (!username || !password) {
    return res.status(400).json({
      message: 'Username and password are required',
      error: 'MISSING_FIELDS'
    });
  }

  if (password.length < 6) {
    return res.status(400).json({
      message: 'Password must be at least 6 characters long',
      error: 'WEAK_PASSWORD'
    });
  }

  let client;
  try {
    client = await getConnection();
    const hashed = await bcrypt.hash(password, 12);

    const result = await client.query(
      'INSERT INTO users (username, password, email) VALUES ($1, $2, $3) RETURNING id, username, email, created_at',
      [username, hashed, email || null]
    );

    const user = result.rows[0];
    const token = generateToken(user);

    console.log('User registered successfully:', user.username);

    res.status(201).json({
      message: 'User registered successfully',
      success: true,
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        created_at: user.created_at
      }
    });
  } catch (err) {
    console.error('Signup error:', err);

    if (err.code === '23505') {
      return res.status(409).json({
        message: 'Username already exists',
        error: 'DUPLICATE_USERNAME'
      });
    }

    res.status(500).json({
      message: 'Registration failed. Please try again.',
      error: 'SIGNUP_FAILED'
    });
  } finally {
    if (client) client.release();
  }
});

// Public: Login
app.post('/login', checkDatabaseAvailability, async (req, res) => {
  console.log('Login request received:', { username: req.body.username });

  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({
      message: 'Username and password are required',
      error: 'MISSING_FIELDS'
    });
  }

  let client;
  try {
    client = await getConnection();
    const result = await client.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = result.rows[0];

    if (!user) {
      return res.status(401).json({
        message: 'Invalid username or password',
        error: 'INVALID_CREDENTIALS'
      });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({
        message: 'Invalid username or password',
        error: 'INVALID_CREDENTIALS'
      });
    }

    const token = generateToken(user);

    console.log('User logged in successfully:', user.username);

    res.json({
      message: 'Login successful',
      success: true,
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({
      message: 'Login failed. Please try again.',
      error: 'LOGIN_FAILED'
    });
  } finally {
    if (client) client.release();
  }
});

// Protected routes

// Get all users
app.get('/users', authenticateToken, checkDatabaseAvailability, async (req, res) => {
  let client;
  try {
    client = await getConnection();
    const result = await client.query('SELECT id, username, email, created_at FROM users ORDER BY created_at DESC');
    res.status(200).json(result.rows);
  } catch (err) {
    console.error('Get users error:', err);
    res.status(500).json({
      message: 'Error fetching users',
      error: 'FETCH_USERS_FAILED'
    });
  } finally {
    if (client) client.release();
  }
});

// Get user by ID
app.get('/user/:id', authenticateToken, checkDatabaseAvailability, async (req, res) => {
  const { id } = req.params;
  let client;
  try {
    client = await getConnection();
    const result = await client.query('SELECT id, username, email, created_at FROM users WHERE id = $1', [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({
        message: 'User not found',
        error: 'USER_NOT_FOUND'
      });
    }

    res.status(200).json(result.rows[0]);
  } catch (err) {
    console.error('Get user error:', err);
    res.status(500).json({
      message: 'Error fetching user',
      error: 'FETCH_USER_FAILED'
    });
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
    res.status(500).json({
      message: 'Error fetching products',
      error: 'FETCH_PRODUCTS_FAILED'
    });
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
      return res.status(404).json({
        message: 'Product not found',
        error: 'PRODUCT_NOT_FOUND'
      });
    }

    res.status(200).json(result.rows[0]);
  } catch (err) {
    console.error('Get product error:', err);
    res.status(500).json({
      message: 'Error fetching product',
      error: 'FETCH_PRODUCT_FAILED'
    });
  } finally {
    if (client) client.release();
  }
});
// Create new products
app.post('/products', authenticateToken, checkDatabaseAvailability, async (req, res) => {
  const productsToCreate = req.body;

  if (!Array.isArray(productsToCreate)) {
    return res.status(400).json({
      message: 'Request body must be an array of products',
      error: 'INVALID_FORMAT'
    });
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
    console.log(`Created ${results.length} products successfully`);

    res.status(201).json({
      message: `Successfully created ${results.length} products`,
      success: true,
      data: results
    });
  } catch (err) {
    if (client) await client.query('ROLLBACK');
    console.error('Create products error:', err);
    res.status(500).json({
      message: 'Error creating products',
      error: 'CREATE_PRODUCTS_FAILED',
      details: err.message
    });
  } finally {
    if (client) client.release();
  }
});

// Update product by ID
app.put('/product/:id', authenticateToken, checkDatabaseAvailability, async (req, res) => {
  const { id } = req.params;
  const { product_name, description, quantity, price } = req.body;

  let client;
  try {
    client = await getConnection();

    // Check if product exists
    const checkResult = await client.query('SELECT * FROM product WHERE product_id = $1', [id]);
    if (checkResult.rows.length === 0) {
      return res.status(404).json({
        message: 'Product not found',
        error: 'PRODUCT_NOT_FOUND'
      });
    }

    const result = await client.query(
      'UPDATE product SET product_name = $1, description = $2, quantity = $3, price = $4, currentstamp = CURRENT_TIMESTAMP WHERE product_id = $5 RETURNING *',
      [product_name, description, quantity, price, id]
    );

    console.log(`Product ${id} updated successfully`);

    res.status(200).json({
      message: 'Product updated successfully',
      success: true,
      data: result.rows[0]
    });
  } catch (err) {
    console.error('Update product error:', err);
    res.status(500).json({
      message: 'Error updating product',
      error: 'UPDATE_PRODUCT_FAILED'
    });
  } finally {
    if (client) client.release();
  }
});

// Delete product by ID
app.delete('/product/:id', authenticateToken, checkDatabaseAvailability, async (req, res) => {
  const { id } = req.params;

  let client;
  try {
    client = await getConnection();

    // Check if product exists
    const checkResult = await client.query('SELECT * FROM product WHERE product_id = $1', [id]);
    if (checkResult.rows.length === 0) {
      return res.status(404).json({
        message: 'Product not found',
        error: 'PRODUCT_NOT_FOUND'
      });
    }

    const result = await client.query('DELETE FROM product WHERE product_id = $1 RETURNING *', [id]);

    console.log(`Product ${id} deleted successfully`);

    res.status(200).json({
      message: 'Product deleted successfully',
      success: true,
      data: result.rows[0]
    });
  } catch (err) {
    console.error('Delete product error:', err);
    res.status(500).json({
      message: 'Error deleting product',
      error: 'DELETE_PRODUCT_FAILED'
    });
  } finally {
    if (client) client.release();
  }
});

// Global error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);

  // CORS errors
  if (err.message && err.message.includes('CORS')) {
    return res.status(403).json({
      message: 'CORS policy violation',
      error: err.message,
      origin: req.headers.origin
    });
  }

  // JWT errors
  if (err.name === 'JsonWebTokenError') {
    return res.status(401).json({
      message: 'Invalid token',
      error: 'INVALID_TOKEN'
    });
  }

  if (err.name === 'TokenExpiredError') {
    return res.status(401).json({
      message: 'Token expired',
      error: 'TOKEN_EXPIRED'
    });
  }

  // Database errors
  if (err.code && err.code.startsWith('23')) {
    return res.status(400).json({
      message: 'Database constraint violation',
      error: 'DATABASE_CONSTRAINT_ERROR'
    });
  }

  // Generic server error
  res.status(500).json({
    message: 'Internal server error',
    error: 'INTERNAL_SERVER_ERROR',
    ...(process.env.NODE_ENV === 'development' && { details: err.message })
  });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    message: `Route ${req.method} ${req.originalUrl} not found`,
    error: 'ROUTE_NOT_FOUND',
    availableEndpoints: {
      health: 'GET /health',
      home: 'GET /',
      signup: 'POST /signup',
      login: 'POST /login',
      users: 'GET /users',
      user: 'GET /user/:id',
      products: 'GET /products',
      product: 'GET /product/:id',
      createProducts: 'POST /products',
      updateProduct: 'PUT /product/:id',
      deleteProduct: 'DELETE /product/:id'
    }
  });
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down gracefully');
  process.exit(0);
});

// Start server
const server = app.listen(port, () => {
  console.log(`🚀 Server running at http://localhost:${port}`);
  console.log(`📊 Health check available at http://localhost:${port}/health`);
  console.log(`📚 API documentation at http://localhost:${port}/`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔒 CORS: Enabled for development origins`);
  console.log(`⏰ JWT Expiry: ${process.env.JWT_EXPIRY || '24h'}`);
});

// Handle server errors
server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`❌ Port ${port} is already in use`);
    process.exit(1);
  } else {
    console.error('❌ Server error:', err);
  }
});

module.exports = app;
