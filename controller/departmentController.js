const { db } = require('../connection')

const webTokenValidator = require('../middleware/webTokenValidator');

const fs = require('fs');

module.exports = {

    createDept: [webTokenValidator, async (req, res) => {
        /*
            JSON
            {
                "deptName": "<deptName>"
            }
        */

        let db_connection;

        try {
            db_connection = await db.promise().getConnection();

            // Lock the necessary tables to prevent concurrent writes
            await db_connection.query('LOCK TABLES Department WRITE, USERDATA READ');

            const userEmail = req.userEmail;

            console.log(userEmail)

            // Fetch userRole based on the email
            const [userData] = await db_connection.query(`
            SELECT userRole
            FROM USERDATA
            WHERE email = ? AND isActive = '1'
        `, [userEmail]);

            if (userData.length === 0) {
                return res.status(404).json({ error: 'User not found or inactive' });
            }

            const userRole = userData[0].userRole;

            if (userRole != 0 && userRole != 1) {
                return res.status(403).json({ error: 'Permission denied. Only professors and admins can create courses.' });
            }

            // Start a transaction
            await db_connection.query('START TRANSACTION');

            const { deptName } = req.body;

            const [active] = await db_connection.query("SELECT * FROM Department WHERE DeptName = ? AND isActive='0'", [deptName])
            if (active.length == 1) {
                const [result] = await db_connection.query('UPDATE Department SET isActive = ? WHERE DeptName = ?', [1, deptName]);
                if (result.affectedRows === 1) {
                    // Commit the transaction
                    await db_connection.query('COMMIT');
                    res.status(201).json({ message: 'Department created successfully' });
                } else {
                    // Rollback the transaction
                    await db_connection.query('ROLLBACK');
                    res.status(500).json({ error: 'Failed to create Department' });
                }
            }
            else {
                const [result] = await db_connection.query('INSERT INTO Department (DeptName, isActive) VALUES (?, ?)', [deptName, 1]);
                if (result.affectedRows === 1) {
                    // Commit the transaction
                    await db_connection.query('COMMIT');
                    res.status(201).json({ message: 'Department created successfully' });
                } else {
                    // Rollback the transaction
                    await db_connection.query('ROLLBACK');
                    res.status(500).json({ error: 'Failed to create Department' });
                }
            }
        } catch (error) {
            console.error(error);
            if (error.code === 'ER_DUP_ENTRY') {
                // Handle the primary key violation error for Department names
                return res.status(400).json({ error: 'Department name already exists' });
            }
            // Rollback the transaction in case of an error
            if (db_connection) {
                await db_connection.query('ROLLBACK');
            }
            const time = new Date();
            fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - createDept - ${error}\n`);
            res.status(500).json({ error: 'Failed to create Department' });
        } finally {
            // Unlock the tables
            await db_connection.query('UNLOCK TABLES');
            db_connection.release();
        }
    },],

    deleteDept: [webTokenValidator, async (req, res) => {
        let db_connection;
        try {
            db_connection = await db.promise().getConnection();

            const userEmail = req.userEmail;
            const deptName = req.body.deptName;

            await db_connection.query('LOCK TABLES Department WRITE, USERDATA READ, class WRITE, studentData WRITE, Slots WRITE, ProfessorClass WRITE, ClassCourse WRITE');

            const [userData] = await db_connection.query(`
                SELECT userRole
                FROM USERDATA
                WHERE email = ? AND isActive = '1'
            `, [userEmail]);

            if (userData.length === 0) {
                return res.status(404).json({ error: 'User not found or inactive' });
            }

            const userRole = userData[0].userRole;

            if (userRole !== '0' && userRole !== '1') {
                return res.status(403).json({ error: 'Permission denied. Only professors and admins can delete Departments.' });
            }

            const [deptData] = await db_connection.query(`
                SELECT DeptID
                FROM Department
                WHERE DeptName = ? AND isActive = '1'
            `, [deptName]);

            if (deptData.length === 0) {
                return res.status(404).json({ error: 'Department not found or inactive' });
            }
            const deptID = deptData[0].DeptID;

            await db_connection.query('START TRANSACTION');

            // Remove entries from attendance related to classes in this Department
            await db_connection.query(`
            DELETE FROM attendance
            WHERE slotID IN (SELECT slotID FROM Slots WHERE classID IN (SELECT classID FROM class WHERE DeptID = ?))
            OR RollNo IN (SELECT RollNo FROM studentData WHERE classID IN (SELECT classID FROM class WHERE DeptID = ?))
            `, [deptID, deptID]);

            // Deactivate students related to classes in this Department
            await db_connection.query(`
                DELETE FROM studentData
                WHERE classID IN (SELECT classID FROM class WHERE DeptID = ?)
            `, [deptID]);

            // Deactivate Slots related to classes in this Department
            await db_connection.query(`
                DELETE FROM Slots
                WHERE classID IN (SELECT classID FROM class WHERE DeptID = ?)
            `, [deptID]);


            // Remove entries from ProfessorClass related to classes in this Department
            await db_connection.query(`
                DELETE FROM ProfessorClass
                WHERE classID IN (SELECT classID FROM class WHERE DeptID = ?)
            `, [deptID]);

            // Remove entries from ClassCourse related to classes in this Department
            await db_connection.query(`
                DELETE FROM ClassCourse
                WHERE classID IN (SELECT classID FROM class WHERE DeptID = ?)
            `, [deptID]);

            // Deactivate classes related to the Department
            await db_connection.query('DELETE FROM class WHERE DeptID = ?', ['0', deptID]);

            // Commit transaction
            await db_connection.query('COMMIT');

            // Deactivate the Department
            await db_connection.query('UPDATE Department SET isActive = ? WHERE DeptID = ?', ['0', deptID]);
            res.json({ message: 'Department and associated data deactivated successfully' });
        } catch (error) {
            console.error(error);
            await db_connection.query('ROLLBACK');
            const time = new Date();
            fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - deleteDept - ${error}\n`);
            res.status(500).json({ error: 'Failed to delete Department and associated data' });
        }
        finally {
            // Unlock the tables
            await db_connection.query('UNLOCK TABLES');
            db_connection.release();
        }
    }],

    allDepts: [webTokenValidator, async (req, res) => {
        let db_connection;

        try {
            db_connection = await db.promise().getConnection();

            // Lock the necessary tables to prevent concurrent writes
            await db_connection.query('LOCK TABLES Department READ');

            const [rows] = await db_connection.query('SELECT DeptName FROM Department WHERE isActive = ?', [1]);
            const deptNames = rows.map(row => row.DeptName);

            res.status(200).json({ depts: deptNames }); // Wrap course names in an object with 'courses' key
        } catch (error) {
            console.error(error);
            const time = new Date();
            fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - api/depts - ${error}\n`);
            res.status(500).json({ error: 'Failed to fetch Departments' });
        } finally {
            // Unlock the tables
            await db_connection.query('UNLOCK TABLES');
            db_connection?.release();
        }
    }],

};