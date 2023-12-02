const { db } = require('../connection')
const webTokenValidator = require('../middleware/webTokenValidator');
const fs = require('fs');
const validator = require('validator');

module.exports = {

    createClass: [webTokenValidator, async (req, res) => {
        // Create a class
        /*
            JSON
            {
                "batchYear": "<batchYear>",
                "Dept": "<Dept>",
                "Section": "<Section>",
                "Semester": "<Semester>",
            }
        */

        let db_connection;

        try {
            db_connection = await db.promise().getConnection();

            // Lock the necessary tables to prevent concurrent writes
            await db_connection.query('LOCK TABLES class WRITE, USERDATA READ, Department READ');

            const isActive = '1'; // Assuming isActive is a CHAR(1) field
            const userEmail = req.userEmail;

            // Find the current user's role based on email
            const [userRoleResult] = await db_connection.query("SELECT * FROM USERDATA WHERE email = ? AND isActive = '1'", [userEmail]);

            if (userRoleResult.length === 0) {
                // Rollback the transaction
                await db_connection.query('ROLLBACK');
                return res.status(400).json({ error: 'User not found' });
            }

            const currentUserRole = userRoleResult[0].userRole;

            if (currentUserRole != 0 && currentUserRole != 1) {
                return res.status(403).json({ error: 'Permission denied. Only professors and admins can create classes.' });
            }

            // Start a transaction
            await db_connection.query('START TRANSACTION');

            const { batchYear, Dept, Section, Semester } = req.body;

            //Check if Dept is available
            const [deptData] = await db_connection.query(`
            SELECT DeptID
            FROM department
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
            if (classData.length === 1) {
                await db_connection.query('ROLLBACK');
                return res.status(404).json({ error: 'Class entered is already present' });
            }
            console.log(currentUserRole)

            // Insert class into class table
            const [classResult] = await db_connection.query(
                'INSERT INTO class (batchYear, DeptID, Section, Semester, isActive) VALUES (?, ?, ?, ?, ?)',
                [batchYear, deptData[0].DeptID, Section, Semester, 1]
            );
            if (classResult.affectedRows === 1) {
                // Commit the transaction
                await db_connection.query('COMMIT');
                res.status(201).json({ message: 'Class created successfully' });
            } else {
                // Rollback the transaction
                await db_connection.query('ROLLBACK');
                res.status(500).json({ error: 'Failed to create class' });
            }
        } catch (error) {
            console.error(error);
            // Rollback the transaction in case of an error
            if (db_connection) {
                await db_connection.query('ROLLBACK');
            }
            const time = new Date();
            fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - createClass - ${error}\n`);
            res.status(500).json({ error: 'Failed to create class' });
        } finally {
            // Unlock the tables
            await db_connection.query('UNLOCK TABLES');
            db_connection.release();
        }
    },],

    myClasses: [webTokenValidator, async (req, res) => {
        // Fetch classes for a professor or admin

        let db_connection;

        try {
            db_connection = await db.promise().getConnection();

            // Lock the necessary tables to prevent concurrent writes
            await db_connection.query('LOCK TABLES USERDATA READ, ProfessorClass pc READ, class c READ, Department d READ');

            const userEmail = req.userEmail;

            console.log(req.userEmail)

            if (!userEmail || !validator.isEmail(userEmail)) {
                return res.status(400).json({ error: 'Invalid current user email' });
            }

            // Fetch user based on the email
            const [userResult] = await db_connection.query('SELECT * FROM USERDATA WHERE email = ?', [userEmail]);

            if (userResult.length === 0) {
                return res.status(404).json({ error: 'User not found' });
            }

            console.log(userResult)

            const cUserRole = userResult[0].userRole;

            console.log(cUserRole)

            if (cUserRole !== '0' && cUserRole !== '1') {
                return res.status(403).json({ error: 'Permission denied. Only professors and admins can access classes.' });
            }

            // Fetch profID based on the email
            const [profData] = await db_connection.query(`
            SELECT * FROM USERDATA WHERE email = ? AND isActive = '1'`, [userEmail]);

            await db_connection.query('UNLOCK TABLES');

            console.log(profData)


            if (profData.length === 0) {
                return res.status(404).json({ error: 'Professor not found or inactive' });
            }

            const profID = profData[0].profID;

            // Fetch classes along with course information
            const [rows] = await db_connection.query(`
            SELECT d.DeptName, c.Section, c.Semester, c.batchYear
            FROM ProfessorClass pc
            JOIN class c ON c.classID = pc.classID
            JOIN department d ON d.DeptID = c.deptID
            WHERE pc.professorID = ? AND c.isActive = '1'
        `, [profID]);

            if (rows.length === 0) {
                return res.status(401).json({ message: 'No classes found' });
            }

            console.log(rows)

            // Unlock the tables
            await db_connection.query('UNLOCK TABLES');

            res.status(200).json(rows);
        } catch (error) {
            console.error(error);
            fs.appendFileSync('logs/errorLogs.txt', `${new Date().toISOString()} - myClasses - ${error}\n`);
            res.status(500).json({ error: 'Failed to fetch classes' });
        } finally {
            // Release the connection
            if (db_connection) {
                db_connection.release();
            }
        }
    },],

    deleteClass: [webTokenValidator, async (req, res) => {
        // Create a class
        /*
            JSON
            {
                "batchYear": "<batchYear>",
                "Dept": "<Dept>",
                "Section": "<Section>",
                "Semester": "<Semester>",
            }
        */

        let db_connection;

        try {
            db_connection = await db.promise().getConnection();

            // Lock the necessary tables to prevent concurrent writes
            await db_connection.query('LOCK TABLES class WRITE, USERDATA READ, Department READ');

            const isActive = '1'; // Assuming isActive is a CHAR(1) field

            const userEmail = req.userEmail;

            // Find the current user's role based on email
            const [userRoleResult] = await db_connection.query("SELECT * FROM USERDATA WHERE email = ? AND isActive = '1'", [userEmail]);

            if (userRoleResult.length === 0) {
                // Rollback the transaction
                await db_connection.query('ROLLBACK');
                return res.status(400).json({ error: 'User not found' });
            }

            const currentUserRole = userRoleResult[0].userRole;

            if (currentUserRole != 0 && currentUserRole != 1) {
                await db_connection.query('ROLLBACK');
                return res.status(403).json({ error: 'Permission denied. Only professors and admins can create classes.' });
            }

            // Start a transaction
            await db_connection.query('START TRANSACTION');

            const { batchYear, Dept, Section, Semester } = req.body;

            //Check if Dept is available
            const [deptData] = await db_connection.query(`
            SELECT DeptID
            FROM department
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
            console.log(currentUserRole)

            // Remove entries from attendance related to classes in this department
            await db_connection.query(`
            DELETE FROM attendance
            WHERE slotID IN (SELECT slotID FROM Slots WHERE classID = ?)
            OR RollNo IN (SELECT RollNo FROM studentData WHERE classID = ?)
            `, [classData[0].classID, classData[0].classID]);

            // Deactivate students related to classes in this department
            await db_connection.query(`
                DELETE FROM studentData
                WHERE classID = ?
            `, [classData[0].classID]);

            // Deactivate slots related to classes in this department
            await db_connection.query(`
                DELETE FROM Slots
                WHERE classID = ?
            `, [classData[0].classID]);

            // Remove entries from ProfessorClass related to classes in this department
            await db_connection.query(`
                DELETE FROM ProfessorClass
                WHERE classID = ?
            `, [classData[0].classID]);

            // Remove entries from ClassCourse related to classes in this department
            await db_connection.query(`
                DELETE FROM ClassCourse
                WHERE classID = ?
            `, [classData[0].classID]);

            // Commit transaction
            await db_connection.query('COMMIT');

            // Delete class from class table
            const [classResult] = await db_connection.query(
                'UPDATE class SET isActive=0 WHERE batchYear = ? AND DeptID = ? AND Section = ? AND Semester = ? AND isActive = ?',
                [batchYear, deptData[0].DeptID, Section, Semester, 1]
            );
            if (classResult.affectedRows === 1) {
                // Commit the transaction
                await db_connection.query('COMMIT');
                res.status(201).json({ message: 'Class deleted successfully' });
            } else {
                // Rollback the transaction
                await db_connection.query('ROLLBACK');
                res.status(500).json({ error: 'Failed to delete class' });
            }
        } catch (error) {
            console.error(error);
            // Rollback the transaction in case of an error
            if (db_connection) {
                await db_connection.query('ROLLBACK');
            }
            const time = new Date();
            fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - deleteClass - ${error}\n`);
            res.status(500).json({ error: 'Failed to delete class' });
        } finally {
            // Unlock the tables
            await db_connection.query('UNLOCK TABLES');
            db_connection.release();
        }
    },],

    allSemesters: [webTokenValidator, async (req, res) => {
        let db_connection;

        try {
            db_connection = await db.promise().getConnection();

            // Lock the necessary tables to prevent concurrent writes
            await db_connection.query('LOCK TABLES class READ');

            const [rows] = await db_connection.query('SELECT DISTINCT Semester FROM class WHERE isActive = ?', [1]);
            const semesters = rows.map(row => row.Semester);

            res.status(200).json({ semesters: semesters }); // Wrap semesters in an object with 'semesters' key
        } catch (error) {
            console.error(error);
            const time = new Date();
            fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - api/semesters - ${error}\n`);
            res.status(500).json({ error: 'Failed to fetch semesters' });
        } finally {
            // Unlock the tables
            await db_connection.query('UNLOCK TABLES');
            db_connection?.release();
        }
    }],

    allBatchYears: [webTokenValidator, async (req, res) => {
        let db_connection;

        try {
            db_connection = await db.promise().getConnection();

            // Lock the necessary tables to prevent concurrent writes
            await db_connection.query('LOCK TABLES class READ');

            const [rows] = await db_connection.query('SELECT DISTINCT batchYear FROM class WHERE isActive = ?', [1]);
            const batchYears = rows.map(row => row.batchYear);

            res.status(200).json({ batchYears }); // Wrap batch years in an object with 'batchYears' key
        } catch (error) {
            console.error(error);
            const time = new Date();
            fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - api/batchYears - ${error}\n`);
            res.status(500).json({ error: 'Failed to fetch batch years' });
        } finally {
            // Unlock the tables
            await db_connection.query('UNLOCK TABLES');
            db_connection?.release();
        }
    }],

    allSections: [webTokenValidator, async (req, res) => {
        let db_connection;

        try {
            db_connection = await db.promise().getConnection();

            // Lock the necessary tables to prevent concurrent writes
            await db_connection.query('LOCK TABLES class READ');

            const [rows] = await db_connection.query('SELECT DISTINCT Section FROM class WHERE isActive = ?', [1]);
            const sectionNames = rows.map(row => row.Section); // Make sure to use the correct case for column name

            res.status(200).json({ sections: sectionNames }); // Wrap section names in an object with 'sections' key
        } catch (error) {
            console.error(error);
            const time = new Date();
            fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - api/sections - ${error}\n`);
            res.status(500).json({ error: 'Failed to fetch sections' });
        } finally {
            // Unlock the tables
            await db_connection.query('UNLOCK TABLES');
            db_connection?.release();
        }
    }],

};