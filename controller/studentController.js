const { db } = require('../connection')

const webTokenValidator = require('../middleware/webTokenValidator');

const fs = require('fs');

module.exports = {
    addStudent: [webTokenValidator, async (req, res) => {

        let db_connection;
        try {
            db_connection = await db.promise().getConnection();
            const { RollNo, StdName, batchYear, Dept, Section, Semester } = req.body;

            // Ensure all required fields are defined
            if (!RollNo || !StdName || !batchYear || !Dept || !Section || !Semester) {
                return res.status(400).json({ error: 'All fields are required' });
            }

            // Validate the RollNo format
            const pattern = /^[A-Z]{2}\.[A-Z]{2}\.[A-Z]{1}[0-9]{1}[A-Z]{3}[0-9]{5}$/;
            if (!pattern.test(RollNo)) {
                return res.status(401).json({ error: 'Invalid roll number format' });
            }

            await db_connection.query('START TRANSACTION');

            // Fetch userRole based on currentUserEmail
            const [currentUser] = await db_connection.query('SELECT userRole FROM USERDATA WHERE email = ?', [req.userEmail]);

            if (currentUser.length === 0) {
                await db_connection.query('ROLLBACK');
                return res.status(402).json({ error: 'Current user not found' });
            }

            const [StudentPresent] = await db_connection.query('SELECT RollNo FROM StudentData WHERE RollNo=?', [RollNo])
            if (StudentPresent.length != 0) {
                await db_connection.query('ROLLBACK');
                return res.status(403).json({ error: 'Student already present' });
            }

            const currentUserRole = currentUser[0].userRole;

            // Fetch DeptID based on Dept
            const [DeptResult] = await db_connection.query('SELECT * FROM Department WHERE DeptName = ?', [Dept]);

            if (DeptResult.length === 0) {
                await db_connection.query('ROLLBACK');
                return res.status(404).send({ "message": "Department not found!" });
            }

            // Insert data into class table
            const [classResult] = await db_connection.query(
                'SELECT classID from class where batchYear = ? AND DeptID = ? AND Section = ? AND Semester = ?',
                [batchYear, DeptResult[0].DeptID, Section, Semester]
            );
            if (classResult.length == 0) {
                await db_connection.query('ROLLBACK');
                return res.status(405).send({ "message": "Class not found!" });
            }
            console.log(classResult)
            // Insert data into studentData table
            const [result] = await db_connection.query(
                'INSERT INTO studentData (RollNo, StdName, classID) VALUES (?, ?, ?)',
                [RollNo, StdName, classResult[0].classID]
            );

            if (result.affectedRows === 1) {
                await db_connection.query('COMMIT');
                return res.status(201).json({ message: 'Student added successfully' });
            } else {
                await db_connection.query('ROLLBACK');
                return res.status(500).json({ error: 'Failed to add student' });
            }
        } catch (error) {
            console.error(error);
            if (db_connection) {
                await db_connection.query('ROLLBACK');
            }

            // Logging and error handling
            const time = new Date();
            fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - addStudent - ${error}\n`);

            res.status(500).json({ error: 'Failed to add student' });
        } finally {
            if (db_connection) {
                db_connection.release();
            }
        }
    }],

    editStudent: [webTokenValidator, async (req, res) => {
        // Edit student details
        /*
            JSON
            {
                "RollNo": "<NewRollNo>",
                "StdName": "<NewStdName>",
                "batchYear": "<NewBatchYear>",
                "Section": "<NewSection>",
                "Dept": "<NewDept>",
                "Semester": "<NewSemester>"
            }
        */
        let db_connection;

        try {
            const { RollNo, StdName, batchYear, Section, Dept, Semester } = req.body;
            const currentUserEmail = req.userEmail;

            db_connection = await db.promise().getConnection();
            console.log(RollNo, StdName, batchYear, Section, Semester)

            // Ensure all required fields are defined
            if (!RollNo || !StdName || !batchYear || !Section || !Dept || !Semester || !currentUserEmail) {
                return res.status(400).json({ error: 'All fields are required' });
            }

            // Lock the necessary tables to prevent concurrent writes
            await db_connection.query('LOCK TABLES studentData WRITE, USERDATA READ, class WRITE, ProfessorClass READ, Department READ');

            // Fetch userRole based on currentUserEmail
            const [currentUser] = await db_connection.query('SELECT userRole FROM USERDATA WHERE email = ?', [currentUserEmail]);
            if (currentUser.length === 0) {
                await db_connection.query('UNLOCK TABLES');
                return res.status(404).json({ error: 'Current user not found' });
            }

            //Checking if Department is found
            const [DeptResult] = await db_connection.query('SELECT * FROM Department WHERE DeptName = ?', [Dept]);
            if (DeptResult.length === 0) {
                await db_connection.query('ROLLBACK');
                return res.status(400).send({ error: "Department not found!" });
            }
            console.log(DeptResult)

            const currentUserRole = currentUser[0].userRole;

            // Get classID based on batchYear, Section, Dept, and Semester
            const [classResult] = await db_connection.query('SELECT classID FROM class WHERE batchYear = ? AND Section = ? AND DeptID = ? AND Semester = ?', [batchYear, Section, DeptResult[0].DeptID, Semester]);
            console.log(classResult)
            if (classResult.length === 0) {
                await db_connection.query('UNLOCK TABLES');
                return res.status(404).json({ error: 'Class not found' });
            }

            const newClassID = classResult[0].classID;

            // Check userRole and proceed accordingly
            if (currentUserRole === "1") {
                // Admin can edit any student
                const [result] = await db_connection.query('UPDATE studentData SET RollNo = ?, StdName = ?, classID = ? WHERE RollNo = ?', [RollNo, StdName, newClassID, RollNo]);

                if (result.affectedRows === 1) {
                    // Commit the transaction
                    await db_connection.query('COMMIT');
                    res.json({ message: 'Student updated successfully' });
                } else {
                    // Rollback the transaction
                    await db_connection.query('ROLLBACK');
                    res.status(404).json({ error: 'Student not found' });
                }
            } else if (currentUserRole === "0") {
                // Faculty can only edit students in their class
                const [result] = await db_connection.query('UPDATE studentData SET RollNo = ?, StdName = ?, classID = ? WHERE RollNo = ? AND classID IN (SELECT classID FROM ProfessorClass WHERE professorID = (SELECT profID FROM USERDATA WHERE email = ?))', [RollNo, StdName, newClassID, RollNo, currentUserEmail]);

                if (result.affectedRows === 1) {
                    // Commit the transaction
                    await db_connection.query('COMMIT');
                    res.json({ message: 'Student updated successfully' });
                } else {
                    // Rollback the transaction
                    await db_connection.query('ROLLBACK');
                    res.status(404).json({ error: 'Student not found or access denied' });
                }
            } else {
                // Other user roles are not allowed to edit students
                await db_connection.query('UNLOCK TABLES');
                res.status(403).json({ error: 'Permission denied. You do not have the required permissions to edit students' });
            }
        } catch (error) {
            console.error(error);
            // Rollback the transaction in case of an error
            if (db_connection) {
                await db_connection.query('ROLLBACK');
            }
            const time = new Date();
            fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - editStudent - ${error}\n`);
            res.status(500).json({ error: 'Failed to update student' });
        } finally {
            // Unlock the tables
            await db_connection.query('UNLOCK TABLES');
            db_connection.release();
        }
    }],

    deleteStudent: [webTokenValidator, async (req, res) => {
        // Deactivate a student
        /*
            JSON
            {
                "RollNo": "<RollNo>"
            }
        */

        let db_connection;

        try {
            const RollNo = req.body.RollNo;
            const currentUserEmail = req.userEmail;

            if (!currentUserEmail) {
                return res.status(400).json({ error: 'currentUserEmail is required' });
            }

            db_connection = await db.promise().getConnection();

            // Lock the necessary tables to prevent concurrent writes
            await db_connection.query('LOCK TABLES studentData WRITE, USERDATA READ');

            // Fetch userRole based on currentUserEmail
            const [currentUser] = await db_connection.query('SELECT userRole FROM USERDATA WHERE email = ? AND isActive = 1', [currentUserEmail]);

            if (currentUser.length === 0) {
                await db_connection.query('UNLOCK TABLES');
                return res.status(404).json({ error: 'Current user not found' });
            }

            const currentUserRole = currentUser[0].userRole;

            // Check userRole and proceed accordingly
            if (currentUserRole === "1" || currentUserRole === "0") {
                // Admin and Faculty can deactivate a student
                const [result] = await db_connection.query('UPDATE studentData SET isActive = ? WHERE RollNo = ?', [0, RollNo]);

                if (result.affectedRows === 1) {
                    // Commit the transaction
                    await db_connection.query('COMMIT');
                    res.json({ message: 'Student deactivated successfully' });
                } else {
                    // Rollback the transaction
                    await db_connection.query('ROLLBACK');
                    res.status(404).json({ error: 'Student not found' });
                }
            } else {
                // Other user roles are not allowed to deactivate students
                await db_connection.query('UNLOCK TABLES');
                res.status(403).json({ error: 'Permission denied. You do not have the required permissions to deactivate students' });
            }
        } catch (error) {
            console.error(error);
            // Rollback the transaction in case of an error
            if (db_connection) {
                await db_connection.query('ROLLBACK');
            }
            const time = new Date();
            fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - deleteStudent - ${error}\n`);
            res.status(500).json({ error: 'Failed to deactivate student' });
        } finally {
            // Unlock the tables
            await db_connection.query('UNLOCK TABLES');
            db_connection.release();
        }
    }],

    activateStudent: [webTokenValidator, async (req, res) => {
        // Activate a student
        /*
            JSON
            {
                "RollNo": "<RollNo>"
            }
        */

        let db_connection;

        try {
            const RollNo = req.body.RollNo;
            const currentUserEmail = req.userEmail;

            if (!currentUserEmail) {
                return res.status(400).json({ error: 'currentUserEmail is required' });
            }

            db_connection = await db.promise().getConnection();

            // Lock the necessary tables to prevent concurrent writes
            await db_connection.query('LOCK TABLES studentData WRITE, USERDATA READ');

            // Fetch userRole based on currentUserEmail
            const [currentUser] = await db_connection.query('SELECT userRole FROM USERDATA WHERE email = ?', [currentUserEmail]);

            if (currentUser.length === 0) {
                await db_connection.query('UNLOCK TABLES');
                return res.status(404).json({ error: 'Current user not found' });
            }

            const currentUserRole = currentUser[0].userRole;

            // Check userRole and proceed accordingly
            if (currentUserRole === "1" || currentUserRole === "0") {
                // Admin and Faculty can activate a student
                const [result] = await db_connection.query('UPDATE studentData SET isActive = ? WHERE RollNo = ?', [1, RollNo]);

                if (result.affectedRows === 1) {
                    // Commit the transaction
                    await db_connection.query('COMMIT');
                    res.json({ message: 'Student activated successfully' });
                } else {
                    // Rollback the transaction
                    await db_connection.query('ROLLBACK');
                    res.status(404).json({ error: 'Student not found' });
                }
            } else {
                // Other user roles are not allowed to activate students
                await db_connection.query('UNLOCK TABLES');
                res.status(403).json({ error: 'Permission denied. You do not have the required permissions to activate students' });
            }
        } catch (error) {
            console.error(error);
            // Rollback the transaction in case of an error
            if (db_connection) {
                await db_connection.query('ROLLBACK');
            }
            const time = new Date();
            fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - activateStudent - ${error}\n`);
            res.status(500).json({ error: 'Failed to activate student' });
        } finally {
            // Unlock the tables
            await db_connection.query('UNLOCK TABLES');
            db_connection.release();
        }
    }],

    allStudents: [webTokenValidator, async (req, res) => {
        /*
          query
          {
              "batchYear": "<batchYear>",
              "dept": "<dept>",
              "section": "<section>",
              "semester": "<semester>",
              "studentName": [],
              "RollNo": []
          }
        */

        let dbConnection;

        try {
            const { batchYear, dept, section, semester } = req.body;

            console.log(batchYear);
            console.log(dept);
            console.log(section);
            console.log(semester);
            console.log('Received Parameters:', req.body);

            // Validate that all required parameters are present
            if (batchYear === undefined || dept === undefined || section === undefined || semester === undefined) {
                console.error('One of the parameters is undefined');
                return res.status(400).json({ error: 'All parameters are required' });
            }

            dbConnection = await db.promise().getConnection();

            await dbConnection.query('LOCK TABLES studentData s READ, class c READ, department d READ');
            const [DeptResult] = await dbConnection.query('SELECT * FROM Department d WHERE d.DeptName = ?', [dept]);
            if (DeptResult.length === 0) {
                return res.status(400).send({ "message": "Department not found!" });
            }

            const [classResult] = await dbConnection.query(
                'SELECT c.classID from class c where c.batchYear = ? AND c.DeptID = ? AND c.Section = ? AND c.Semester = ?',
                [batchYear, DeptResult[0].DeptID, section, semester]
            );
            if (classResult.length == 0) {
                return res.status(400).send({ "message": "Class not found!" });
            }

            // Lock the necessary tables to prevent concurrent writes

            const [rows] = await dbConnection.query(
                'SELECT * FROM studentData s JOIN class c ON s.classID = c.classID WHERE s.isActive = ? AND c.batchYear = ? AND c.DeptID = ? AND c.Section = ? AND c.Semester = ?',
                [1, batchYear, DeptResult[0].DeptID, section, semester]
            );

            console.log(rows);

            res.status(200).json({ students: rows });
        } catch (error) {
            console.error(error);
            const time = new Date();
            await fs.promises.appendFile('logs/errorLogs.txt', `${time.toISOString()} - allStudents - ${error}\n`);
            res.status(500).json({ error: 'Failed to fetch students' });
        } finally {
            // Unlock the tables even if an error occurs
            if (dbConnection) {
                await dbConnection.query('UNLOCK TABLES');
                dbConnection.release();
            }
        }
    }],

    addStudents: [webTokenValidator, async (req, res) => {
        /*
          query
          {
              "batchYear": "<batchYear>",
              "dept": "<dept>",
              "section": "<section>",
              "semester": "<semester>",
              "studentName": [],
              "RollNo": []
          }
        */
        let dbConnection;

        try {
            const { batchYear, dept, section, semester, stuName, RollNo } = req.body;
            console.log(batchYear);
            console.log(dept);
            console.log(section);
            console.log(semester, stuName, RollNo);

            dbConnection = await db.promise().getConnection();

            if (batchYear === undefined || dept === undefined || section === undefined || semester === undefined || stuName === undefined || RollNo === undefined) {
                console.error('One of the parameters is undefined');
                return res.status(400).json({ error: 'All parameters are required' });
            }
            await dbConnection.query('LOCK TABLES studentData s WRITE, class c READ, department d READ');


            await dbConnection.query('START TRANSACTION');

            // Fetch userRole based on currentUserEmail
            const [currentUser] = await dbConnection.query('SELECT userRole FROM USERDATA WHERE email = ?', [req.userEmail]);

            if (currentUser.length === 0) {
                await dbConnection.query('ROLLBACK');
                return res.status(402).json({ error: 'Current user not found' });
            }

            // Fetch DeptID based on Dept
            const [DeptResult] = await dbConnection.query('SELECT * FROM Department WHERE DeptName = ?', [dept]);

            if (DeptResult.length === 0) {
                await dbConnection.query('ROLLBACK');
                return res.status(404).send({ "message": "Department not found!" });
            }

            // Insert data into class table
            const [classResult] = await dbConnection.query(
                'SELECT classID from class where batchYear = ? AND DeptID = ? AND Section = ? AND Semester = ?',
                [batchYear, DeptResult[0].DeptID, section, semester]
            );
            if (classResult.length == 0) {
                await dbConnection.query('ROLLBACK');
                return res.status(405).send({ "message": "Class not found!" });
            }
            const classID = classResult[0].classID
            let addedStudents = 0;
            // Insert data into studentData table
            for (let i = 0; i < stuName.length; i++) {
                const [result] = await dbConnection.query(
                    'INSERT INTO studentData (RollNo, StdName, classID) VALUES (?, ?, ?)',
                    [RollNo[i], stuName[i], classID]
                );
                console.log(`Inserted Student ${stuName[i]} with RollNo ${RollNo[i]} successfully`);
                if (result.affectedRows == 1) {
                    addedStudents += 1;
                }
            }
            if (addedStudents == RollNo.length) {
                // Commit the transaction
                await dbConnection.query('COMMIT');
                res.status(201).json({ message: 'Students added successfully' });
            }
        } catch (error) {
            console.error(error);
            return res.status(403).json("Students already exists")
            // Rollback the transaction in case of an error
            if (dbConnection) {
                await dbConnection.query('ROLLBACK');
            }

            const time = new Date();
            await fs.promises.appendFile('logs/errorLogs.txt', `${time.toISOString()} - addStudents - ${error}\n`);

            res.status(500).json({ error: 'Failed to add students' });
        } finally {
            // Release the database connection
            if (dbConnection) {
                dbConnection.release();
            }
        }
    }],

    fetchStudentData: [webTokenValidator, async (req, res) => {
        let db_connection;

        try {
            const { studentRollNo } = req.query;

            db_connection = await db.promise().getConnection();

            // Lock the necessary tables to prevent concurrent writes
            await db_connection.query('LOCK TABLES studentData s READ, class c READ, Department d READ');

            const [rows] = await db_connection.query(
                'SELECT s.RollNo, s.StdName, c.batchYear, d.DeptName, c.Semester, c.Section ' +
                'FROM (studentData s ' +
                'JOIN class c ON s.classID = c.classID) JOIN Department d ON d.DeptID = c.DeptID ' +
                'WHERE s.RollNo = ?',
                [studentRollNo]
            );

            console.log(rows);

            if (rows.length > 0) {
                const studentData = rows[0];

                res.status(200).json({ student: studentData });
            } else {
                res.status(404).json({ error: 'Student not found' });
            }
        } catch (error) {
            console.error(error);
            res.status(500).json({ error: 'Failed to fetch student data' });
        } finally {
            // Unlock the tables
            try {
                await db_connection.query('UNLOCK TABLES');
            } catch (unlockError) {
                console.error('Error unlocking tables:', unlockError);
            }

            if (db_connection) {
                db_connection.release();
            }
        }
    }],
};