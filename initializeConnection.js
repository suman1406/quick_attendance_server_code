const mysql = require('mysql2');
require('dotenv').config();

const establishConnection = () => {

    const db = mysql.createConnection({
        host: 'localhost',
        user: process.env.SQLUSER,
        password: process.env.SQLPASSWORD,
        database: 'quick_attendance',
        multipleStatements: true
    });

    db.connect((err) => {
        if (err) {
            console.log("[ERROR]: Failed to connect to MySQL");
            console.log(err);
        }
        else {
            console.log("[MESSAGE]: Connected to MySQL...");
        }
    });

    return [db];

}

module.exports = establishConnection;