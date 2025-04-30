require('dotenv').config(); // Load environment variables

const { Pool } = require('pg');

// Debug the environment variables
console.log("✅ ENV values:", {
    DB_USER: process.env.DB_USER,
    DB_PASSWORD: process.env.DB_PASSWORD,
    DB_HOST: process.env.DB_HOST,
    DB_DATABASE: process.env.DB_DATABASE,
    DB_PORT: process.env.DB_PORT,
});

const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_DATABASE,
    password: process.env.DB_PASSWORD, // Make sure this is a valid password string
    port: parseInt(process.env.DB_PORT) || 5432,
});

module.exports = pool;
