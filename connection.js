const mysql = require('mysql2');
const os = require('os');
const connectionLimit = os.cpus().length;
require('dotenv').config();

const db = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: process.env.SQLPASSWORD,
    database: 'quick_attendance',
    waitForConnections: true,
    connectionLimit: connectionLimit,
    queueLimit: 0
});

module.exports = { db };