require('dotenv').config();
const { Pool } = require('pg');
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors'); // Added CORS dependency

const app = express();
const port = process.env.PORT || 3000;

// CORS configuration
app.use(cors({
  origin: ['http://localhost:5173', 'https://your-frontend-domain.com'], // Add your frontend domains
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

// Log environment variables (for debugging only - remove in production)
console.log("Database Host:", process.env.DB_HOST);
console.log("Database User:", process.env.DB_USER);
console.log("Database Name:", process.env.DB_DATABASE);
// Don't log passwords in production!
console.log("Database Port:", process.env.DB_PORT || 5432);

// Middleware
app.use(bodyParser.json());

// PostgreSQL connection with improved error handling for Render.com hosted database
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_DATABASE,
  password: process.env.DB_PASSWORD,
  port: parseInt(process.env.DB_PORT) || 5432,
  // SSL is required for Render.com PostgreSQL databases
  ssl: { rejectUnauthorized: false },
  // Add connection timeout - increased for cloud hosted DB
  connectionTimeoutMillis: 10000,
  // Add retry logic
  max: 10, // max clients in pool
  idleTimeoutMillis: 30000, // how long a client is allowed to remain idle before being closed
});

// Test database connection on startup
pool.connect((err, client, done) => {
  if (err) {
    console.error('Database connection error:', err.message);
    console.error('Please check if the database server is accessible and credentials are correct');
    // Don't exit the process, let the server start anyway
  } else {
    console.log('Successfully connected to PostgreSQL database on Render.com');
    done(); // release the client back to the pool
  }
});

// JWT utilities
function generateToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username },
    process.env.JWT_SECRET || 'default_jwt_secret', // Fallback for testing only
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

// Welcome route
app.get('/', (req, res) => {
  res.json({ message: 'Welcome to the API. Please register or log in to continue.' });
});

// Public: Signup
app.post('/signup', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required' });
  }

  try {
    const hashed = await bcrypt.hash(password, 10);
    const result = await pool.query(
      'INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id, username',
      [username, hashed]
    );
    const token = generateToken(result.rows[0]);
    res.status(201).json({ message: 'User registered successfully', token });
  } catch (err) {
    console.error(err);
    // Better error handling for duplicate usernames
    if (err.code === '23505') { // PostgreSQL unique constraint violation
      return res.status(409).json({ message: 'Username already exists' });
    }
    res.status(500).json({ message: 'Signup failed', error: err.message });
  }
});

// Public: Login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required' });
  }

  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ message: 'Invalid username or password' });
    }

    const token = generateToken(user);
    res.json({ message: 'Login successful', token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Login failed', error: err.message });
  }
});

// Authenticated routes
app.use('/products', authenticateToken);
app.use('/product', authenticateToken);

// Get all products
app.get('/products', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM product');
    res.status(200).json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error fetching products', error: err.message });
  }
});

// Get product by ID
app.get('/product/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query('SELECT * FROM product WHERE product_id = $1', [id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Product not found' });
    }
    res.status(200).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error fetching product', error: err.message });
  }
});

// Create new products (array input)
app.post('/products', async (req, res) => {
  const productsToCreate = req.body;
  if (!Array.isArray(productsToCreate)) {
    return res.status(400).json({ message: 'Request body must be an array of products' });
  }

  try {
    const results = [];
    for (const product of productsToCreate) {
      const { product_name, description, quantity, price } = product;
      const result = await pool.query(
        'INSERT INTO product (product_name, description, quantity, price) VALUES ($1, $2, $3, $4) RETURNING *',
        [product_name, description, quantity, price]
      );
      results.push(result.rows[0]);
    }
    res.status(201).json(results);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error creating products', error: err.message });
  }
});

// Update single product (PUT)
app.put('/product/:id', async (req, res) => {
  const { id } = req.params;
  const { product_name, description, quantity, price } = req.body;

  try {
    const result = await pool.query(
      'UPDATE product SET product_name = $1, description = $2, quantity = $3, price = $4, currentstamp = CURRENT_TIMESTAMP WHERE product_id = $5 RETURNING *',
      [product_name, description, quantity, price, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Product not found' });
    }

    res.status(200).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error updating product', error: err.message });
  }
});

// Partially update single product (PATCH)
app.patch('/product/:id', async (req, res) => {
  const { id } = req.params;
  const updates = req.body;

  try {
    const product = await pool.query('SELECT * FROM product WHERE product_id = $1', [id]);
    if (product.rows.length === 0) {
      return res.status(404).json({ message: 'Product not found' });
    }

    const setClauses = [];
    const values = [];
    let valueIndex = 1;

    for (const key in updates) {
      if (updates.hasOwnProperty(key) && key !== 'product_id') {
        setClauses.push(`${key} = $${valueIndex}`);
        values.push(updates[key]);
        valueIndex++;
      }
    }

    if (setClauses.length === 0) {
      return res.status(200).json(product.rows[0]);
    }

    const updateQuery = `
      UPDATE product
      SET ${setClauses.join(', ')}, currentstamp = CURRENT_TIMESTAMP
      WHERE product_id = $${valueIndex}
      RETURNING *
    `;
    values.push(id);

    const result = await pool.query(updateQuery, values);

    if (result.rows.length > 0) {
      res.status(200).json(result.rows[0]);
    } else {
      res.status(404).json({ message: 'Product not found' });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error updating product', error: err.message });
  }
});

// Delete product by ID
app.delete('/product/:id', async (req, res) => {
  const { id } = req.params;

  try {
    const result = await pool.query('DELETE FROM product WHERE product_id = $1 RETURNING *', [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Product not found' });
    }

    res.status(200).json({ message: 'Product deleted successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error deleting product', error: err.message });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ message: 'Internal server error', error: err.message });
});

// === ✅ Start Server ===
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});