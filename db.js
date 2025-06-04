require('dotenv').config();
const { Pool } = require('pg');

// Database connection state
let isDBInitialized = false;

// Database pool with auto-configuration
const pool = new Pool({
    connectionString: process.env.DATABASE_URI,
    ssl: process.env.DATABASE_URI?.includes('render.com') || process.env.NODE_ENV === 'production'
        ? { rejectUnauthorized: false, sslmode: 'require' }
        : false,
    max: 5,
    connectionTimeoutMillis: 30000,
    idleTimeoutMillis: 30000
});

// Initialize database tables
async function initDB() {
    try {
        await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(255) NOT NULL UNIQUE,
        password TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      
      CREATE TABLE IF NOT EXISTS product (
        product_id SERIAL PRIMARY KEY,
        product_name VARCHAR(255) NOT NULL,
        description TEXT,
        quantity INTEGER NOT NULL DEFAULT 0,
        price DECIMAL(10, 2) NOT NULL,
        currentstamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
        console.log('Database initialized successfully');
        isDBInitialized = true;
    } catch (err) {
        console.error('Database init error:', err.message);
        isDBInitialized = false;
    }
}

// Get database connection from pool
async function getConnection() {
    try {
        return await pool.connect();
    } catch (err) {
        console.error('Connection error:', err.message);
        throw err;
    }
}

// Check if database is initialized
function isInitialized() {
    return isDBInitialized;
}

// Query wrapper
async function query(text, params = []) {
    try {
        return await pool.query(text, params);
    } catch (err) {
        console.error('Query error:', err.message);
        throw err;
    }
}

// Initialize on startup
initDB();

// Graceful shutdown
process.on('SIGTERM', () => pool.end());
process.on('SIGINT', () => pool.end());

module.exports = {
    pool,
    query,
    getConnection,
    isInitialized
};