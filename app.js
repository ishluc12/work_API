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

// CORS Configuration
const corsOptions = {
  origin: [
    'http://localhost:10641', // Your Flutter development origin (if using mobile/desktop emulator)
    'http://localhost',       // Additional possible origins
    'http://localhost:7745',  // Previous Flutter web app development origin
    'http://localhost:9730',  // <--- NEW: Your Flutter web app development origin from screenshot
    'https://your-app.com'    // Production origin
  ],
  methods: 'GET,PUT,POST,DELETE,PATCH,OPTIONS',
  allowedHeaders: 'Origin,X-Requested-With,Content-Type,Accept,Authorization',
  credentials: true,
  optionsSuccessStatus: 200
};

app.use(cors(corsOptions));

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
const JWT_SECRET = process.env.JWT_SECRET || 'default_jwt_secret_change_in_production';
const JWT_EXPIRY = process.env.JWT_EXPIRY || '24h';

function generateToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRY }
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
    const user = jwt.verify(token, JWT_SECRET);
    req.user = user;
    next();
  } catch (err) {
    console.error('Token verification failed:', err.message);
    const errorType = err.name === 'TokenExpiredError' ? 'TOKEN_EXPIRED' : 'INVALID_TOKEN';
    return res.status(403).json({
      message: err.name === 'TokenExpiredError' ? 'Token expired' : 'Invalid token',
      error: errorType
    });
  }
}

// Utility function for database operations
async function executeQuery(queryText, params = [], operation = 'query') {
  let client;
  try {
    client = await getConnection();
    const result = await client.query(queryText, params);
    return result;
  } catch (error) {
    console.error(`Database ${operation} error:`, error);
    throw error;
  } finally {
    if (client) client.release();
  }
}

// Routes

// Health check route
app.get('/health', async (req, res) => {
  try {
    const result = await executeQuery('SELECT NOW() as current_time, version() as pg_version');

    res.json({
      status: 'healthy',
      database: 'connected',
      timestamp: new Date().toISOString(),
      server_time: result.rows[0].current_time,
      database_version: result.rows[0].pg_version.split(' ').slice(0, 2).join(' '),
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
      createProducts: 'POST /products (requires auth)',
      updateProduct: 'PUT /product/:id (requires auth)',
      deleteProduct: 'DELETE /product/:id (requires auth)'
    }
  });
});

// Authentication Routes

// Signup
app.post('/signup', checkDatabaseAvailability, async (req, res) => {
  console.log('Signup request received:', { username: req.body.username });

  // Removed email from destructuring
  const { username, password } = req.body;

  // Input validation
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

  try {
    const hashed = await bcrypt.hash(password, 12);

    // Updated INSERT query to only use username and password
    const result = await executeQuery(
      'INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id, username, created_at',
      [username, hashed],
      'signup'
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
  }
});

// Login
app.post('/login', checkDatabaseAvailability, async (req, res) => {
  console.log('Login request received:', { username: req.body.username });

  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({
      message: 'Username and password are required',
      error: 'MISSING_FIELDS'
    });
  }

  try {
    const result = await executeQuery(
      'SELECT * FROM users WHERE username = $1',
      [username],
      'login'
    );

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
        email: user.email // Keep email here for login, as it might be present in existing users
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({
      message: 'Login failed. Please try again.',
      error: 'LOGIN_FAILED'
    });
  }
});

// User Routes

// Get all users
app.get('/users', authenticateToken, checkDatabaseAvailability, async (req, res) => {
  try {
    const result = await executeQuery(
      'SELECT id, username, email, created_at FROM users ORDER BY created_at DESC',
      [],
      'get_users'
    );
    res.status(200).json(result.rows);
  } catch (err) {
    console.error('Get users error:', err);
    res.status(500).json({
      message: 'Error fetching users',
      error: 'FETCH_USERS_FAILED'
    });
  }
});

// Get user by ID
app.get('/user/:id', authenticateToken, checkDatabaseAvailability, async (req, res) => {
  const { id } = req.params;

  try {
    const result = await executeQuery(
      'SELECT id, username, email, created_at FROM users WHERE id = $1',
      [id],
      'get_user'
    );

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
  }
});

// Product Routes

// Get all products
app.get('/products', authenticateToken, checkDatabaseAvailability, async (req, res) => {
  try {
    const result = await executeQuery(
      'SELECT * FROM product ORDER BY currentstamp DESC',
      [],
      'get_products'
    );
    res.status(200).json(result.rows);
  } catch (err) {
    console.error('Get products error:', err);
    res.status(500).json({
      message: 'Error fetching products',
      error: 'FETCH_PRODUCTS_FAILED'
    });
  }
});

// Get product by ID
app.get('/product/:id', authenticateToken, checkDatabaseAvailability, async (req, res) => {
  const { id } = req.params;

  try {
    const result = await executeQuery(
      'SELECT * FROM product WHERE product_id = $1',
      [id],
      'get_product'
    );

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

// Error Handling Middleware

// Global error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);

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
const gracefulShutdown = (signal) => {
  console.log(`${signal} received, shutting down gracefully`);
  server.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Start server
const server = app.listen(port, () => {
  console.log(`🚀 Server running at http://localhost:${port}`);
  console.log(`📊 Health check available at http://localhost:${port}/health`);
  console.log(`📚 API documentation at http://localhost:${port}/`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔒 CORS: Configured with allowed origins`);
  console.log(`⏰ JWT Expiry: ${JWT_EXPIRY}`);
});

module.exports = app;
