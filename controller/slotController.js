const { db } = require('../connection')

const webTokenGenerator = require('../middleware/webTokenGenerator');
const webTokenValidator = require('../middleware/webTokenValidator');
const otpTokenGenerator = require('../middleware/otpTokenGenerator');
const [otpTokenValidator, resetPasswordValidator] = require('../middleware/otpTokenValidator');

const generateOTP = require("../middleware/otpGenerator");

const passwordGenerator = require('secure-random-password');

const crypto = require('crypto');

const mailer = require('../mail/mailer');

const fs = require('fs');
const validator = require('validator');
const tokenValidator = require('../middleware/webTokenValidator');

module.exports = {

    createSlot: [webTokenValidator, async (req, res) => {
        // Create a class slot
        /*
            JSON
            {
                "batchYear": "<batchYear>",
                "Dept": "<Dept>",
                "Section": "<Section>",
                "Semester": "<Semester>",
                "periodNo": "<periodNo>"
            }
        */

        let db_connection;

        try {
            db_connection = await db.promise().getConnection();

            // Lock the necessary tables to prevent concurrent writes
            await db_connection.query('LOCK TABLES Slots WRITE, class READ, USERDATA READ, Department READ');

            const userEmail = req.userEmail;

            if (!userEmail || !validator.isEmail(userEmail)) {
                return res.status(400).json({ error: 'Invalid user email' });
            }

            // Fetch userRole based on the email
            const [userResult] = await db_connection.query(`
            SELECT userRole
            FROM USERDATA
            WHERE email = ? AND isActive = '1'
        `, [userEmail]);

            if (userResult.length === 0) {
                return res.status(404).json({ error: 'User not found or inactive' });
            }

            const cUserRole = userResult[0].userRole;

            if (cUserRole != 0 && cUserRole != 1) {
                // Unlock the tables
                await db_connection.query('UNLOCK TABLES');
                db_connection.release();
                return res.status(403).json({ error: 'Permission denied. Only professors and admins can create class Slots.' });
            }

            // Start a transaction
            await db_connection.query('START TRANSACTION');

            const { batchYear, Dept, Section, Semester, periodNo } = req.body;

            //Check if Dept is available
            const [deptData] = await db_connection.query(`
           SELECT DeptID
           FROM Department
           WHERE DeptName = ? AND isActive = '1'
           `, [Dept]);
            console.log(deptData)
            if (deptData.length === 0) {
                await db_connection.query('ROLLBACK');
                return res.status(404).json({ error: 'Department entered was not found or inactive' });
            }

            //check if class is already present
            const [classData] = await db_connection.query(`
            SELECT classID
            FROM class
            WHERE batchYear = ? AND DeptID = ? AND Section = ? AND Semester = ? AND isActive = '1'
            `, [batchYear, deptData[0].DeptID, Section, Semester]);
            console.log(classData)
            if (classData.length === 0) {
                await db_connection.query('ROLLBACK');
                return res.status(404).json({ error: 'Class entered is not present' });
            }
            const classID = classData[0].classID;

            // Insert slot into Slots table
            const [available] = await db_connection.query('SELECT * FROM Slots WHERE classID = ? AND periodNo = ?', [classID, periodNo]);
            if (available.length > 0) {
                await db_connection.query('ROLLBACK');
                return res.status(500).json({ error: 'Slot already exist' });
            }
            const [result] = await db_connection.query('INSERT INTO Slots (classID, periodNo) VALUES (?, ?)', [classID, periodNo]);

            if (result.affectedRows === 1) {
                // Commit the transaction
                await db_connection.query('COMMIT');
                return res.status(201).json({ message: 'Slot created successfully' });
            } else {
                // Rollback the transaction
                await db_connection.query('ROLLBACK');
                return res.status(500).json({ error: 'Failed to create slot' });
            }
        } catch (error) {
            console.error(error);
            // Rollback the transaction in case of an error
            if (db_connection) {
                await db_connection.query('ROLLBACK');
            }
            const time = new Date();
            fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - createSlots - ${error}\n`);
            res.status(500).json({ error: 'Failed to create slot' });
        } finally {
            // Unlock the tables
            await db_connection.query('UNLOCK TABLES');
            db_connection.release();
        }
    },],

    deleteSlot: [webTokenValidator, async (req, res) => {
        // Delete a class slot
        /*
            JSON
            {
                "batchYear": "<batchYear>",
                "Dept": "<Dept>",
                "Section": "<Section>",
                "Semester": "<Semester>",
                "periodNo": "<periodNo>"
            }
            */
        let db_connection;

        try {
            db_connection = await db.promise().getConnection();

            // Lock the necessary tables to prevent concurrent writes
            await db_connection.query('LOCK TABLES Slots WRITE, class READ, USERDATA READ, Department READ');

            const userEmail = req.userEmail;

            if (!userEmail || !validator.isEmail(userEmail)) {
                return res.status(400).json({ error: 'Invalid user email' });
            }

            // Fetch userRole based on the email
            const [userResult] = await db_connection.query(`
                SELECT userRole
                FROM USERDATA
                WHERE email = ? AND isActive = '1'
                `, [userEmail]);

            if (userResult.length === 0) {
                return res.status(404).json({ error: 'User not found or inactive' });
            }

            const cUserRole = userResult[0].userRole;

            if (cUserRole != 0 && cUserRole != 1) {
                // Unlock the tables
                await db_connection.query('UNLOCK TABLES');
                db_connection.release();
                return res.status(403).json({ error: 'Permission denied. Only professors and admins can create class Slots.' });
            }

            // Start a transaction
            await db_connection.query('START TRANSACTION');

            const { batchYear, Dept, Section, Semester, periodNo } = req.body;

            //Check if Dept is available
            const [deptData] = await db_connection.query(`
                SELECT DeptID
                FROM Department
                WHERE DeptName = ? AND isActive = '1'
                `, [Dept]);
            console.log(deptData)
            if (deptData.length === 0) {
                await db_connection.query('ROLLBACK');
                return res.status(404).json({ error: 'Department entered was not found or inactive' });
            }

            //check if class is already present
            const [classData] = await db_connection.query(`
                SELECT classID
                FROM class
                WHERE batchYear = ? AND DeptID = ? AND Section = ? AND Semester = ? AND isActive = '1'
                `, [batchYear, deptData[0].DeptID, Section, Semester]);
            console.log(classData)
            if (classData.length === 0) {
                await db_connection.query('ROLLBACK');
                return res.status(404).json({ error: 'Class entered is not present' });
            }
            const classID = classData[0].classID;

            // Insert slot into Slots table
            const [available] = await db_connection.query('SELECT * FROM Slots WHERE classID = ? AND periodNo = ?', [classID, periodNo]);
            if (available.length == 0) {
                await db_connection.query('ROLLBACK');
                return res.status(500).json({ error: 'Slot does not exist' });
            }
            const [result] = await db_connection.query('DELETE FROM Slots WHERE classID = ? AND periodNo = ?', [classID, periodNo]);

            if (result.affectedRows === 1) {
                // Commit the transaction
                await db_connection.query('COMMIT');
                return res.status(201).json({ message: 'Slot deleted successfully' });
            } else {
                // Rollback the transaction
                await db_connection.query('ROLLBACK');
                return res.status(500).json({ error: 'Failed to delete slot' });
            }
        } catch (error) {
            console.error(error);
            // Rollback the transaction in case of an error
            if (db_connection) {
                await db_connection.query('ROLLBACK');
            }
            const time = new Date();
            fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - deleteSlot - ${error}\n`);
            res.status(500).json({ error: 'Failed to delete slot' });
        } finally {
            // Unlock the tables
            await db_connection.query('UNLOCK TABLES');
            db_connection.release();
        }
    },],

};