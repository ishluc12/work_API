require('dotenv').config();
const { Pool } = require('pg');
const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
const port = process.env.PORT || 3000;

// Log environment variables
console.log("Database Host:", process.env.DB_HOST);
console.log("Database User:", process.env.DB_USER);
console.log("Database Name:", process.env.DB_DATABASE);
console.log("Database Password:", process.env.DB_PASSWORD);

// Middleware
app.use(bodyParser.json());

// PostgreSQL connection
const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_DATABASE,
  password: process.env.DB_PASSWORD,
  port: parseInt(process.env.DB_PORT) || 5432,
  ssl: { rejectUnauthorized: false }
});

// JWT utilities
function generateToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRY || '1h' }
  );
}

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ message: 'Missing token' });

  try {
    const user = jwt.verify(token, process.env.JWT_SECRET);
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
    res.status(500).json({ message: 'Signup failed', error: err.message });
  }
});

// Public: Login
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
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
app.use(authenticateToken);

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

// === ✅ BATCH ROUTES BELOW ===

// Delete multiple products
app.delete('/products', async (req, res) => {
  const { ids } = req.body;
  if (!Array.isArray(ids) || ids.length === 0) {
    return res.status(400).json({ message: 'Please provide an array of product IDs to delete.' });
  }

  try {
    const result = await pool.query(
      'DELETE FROM product WHERE product_id = ANY($1::int[]) RETURNING *',
      [ids]
    );

    res.status(200).json({
      message: `${result.rows.length} products deleted successfully.`,
      deleted: result.rows
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error deleting products', error: err.message });
  }
});

// Full update multiple products
app.put('/products', async (req, res) => {
  const updates = req.body;

  if (!Array.isArray(updates) || updates.length === 0) {
    return res.status(400).json({ message: 'Provide an array of products to update.' });
  }

  try {
    const updatedProducts = [];

    for (const product of updates) {
      const { product_id, product_name, description, quantity, price } = product;

      const result = await pool.query(
        `UPDATE product SET 
          product_name = $1, 
          description = $2, 
          quantity = $3, 
          price = $4,
          currentstamp = CURRENT_TIMESTAMP
        WHERE product_id = $5 RETURNING *`,
        [product_name, description, quantity, price, product_id]
      );

      if (result.rows.length > 0) {
        updatedProducts.push(result.rows[0]);
      }
    }

    res.status(200).json({ message: 'Products updated', updated: updatedProducts });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error updating products', error: err.message });
  }
});

// Partially update multiple products
app.patch('/products', async (req, res) => {
  const updates = req.body;

  if (!Array.isArray(updates) || updates.length === 0) {
    return res.status(400).json({ message: 'Provide an array of updates.' });
  }

  try {
    const patchedProducts = [];

    for (const product of updates) {
      const { product_id, ...fields } = product;

      if (!product_id) continue;

      const setClauses = [];
      const values = [];
      let idx = 1;

      for (const key in fields) {
        if (fields.hasOwnProperty(key)) {
          setClauses.push(`${key} = $${idx}`);
          values.push(fields[key]);
          idx++;
        }
      }

      if (setClauses.length === 0) continue;

      values.push(product_id);
      const query = `
        UPDATE product SET ${setClauses.join(', ')}, currentstamp = CURRENT_TIMESTAMP
        WHERE product_id = $${idx}
        RETURNING *`;

      const result = await pool.query(query, values);
      if (result.rows.length > 0) {
        patchedProducts.push(result.rows[0]);
      }
    }

    res.status(200).json({ message: 'Products patched', patched: patchedProducts });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error patching products', error: err.message });
  }
});

// === ✅ Start Server ===
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
