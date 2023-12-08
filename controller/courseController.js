const { db } = require('../connection')

const webTokenValidator = require('../middleware/webTokenValidator');

const fs = require('fs');

module.exports = {
    
    createCourse: [webTokenValidator, async (req, res) => {
        /*
            JSON
            {
                "courseName": "<courseName>"
            }
        */

        let db_connection;

        try {
            db_connection = await db.promise().getConnection();

            // Lock the necessary tables to prevent concurrent writes
            await db_connection.query('LOCK TABLES course WRITE, userdata READ');

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

            const { courseName } = req.body;

            const [active] = await db_connection.query("SELECT * FROM course WHERE courseName = ? AND isActive='0'", [courseName])
            if (active.length == 1) {
                const [result] = await db_connection.query('UPDATE course SET isActive = ? WHERE courseName = ?', [1, courseName]);
                if (result.affectedRows === 1) {
                    // Commit the transaction
                    await db_connection.query('COMMIT');
                    res.status(201).json({ message: 'Course created successfully' });
                } else {
                    // Rollback the transaction
                    await db_connection.query('ROLLBACK');
                    res.status(500).json({ error: 'Failed to create Course' });
                }
            }
            else {
                const [result] = await db_connection.query('INSERT INTO course (courseName, isActive) VALUES (?, ?)', [courseName, 1]);
                if (result.affectedRows === 1) {
                    // Commit the transaction
                    await db_connection.query('COMMIT');
                    res.status(201).json({ message: 'Course created successfully' });
                } else {
                    // Rollback the transaction
                    await db_connection.query('ROLLBACK');
                    res.status(500).json({ error: 'Failed to create course' });
                }
            }
        } catch (error) {
            console.error(error);
            if (error.code === 'ER_DUP_ENTRY') {
                // Handle the primary key violation error for department names
                return res.status(400).json({ error: 'Course name already exists' });
            }
            // Rollback the transaction in case of an error
            if (db_connection) {
                await db_connection.query('ROLLBACK');
            }
            const time = new Date();
            fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - createCourse - ${error}\n`);
            res.status(500).json({ error: 'Failed to create course' });
        } finally {
            // Unlock the tables
            await db_connection.query('UNLOCK TABLES');
            db_connection.release();
        }
    },],

    deleteCourse: [webTokenValidator, async (req, res) => {
        /*
            JSON
            {
                "courseName": "<courseName>"
            }
        */

        let db_connection;

        try {
            db_connection = await db.promise().getConnection();

            const userEmail = req.userEmail;
            const courseName = req.body.courseName;

            await db_connection.query('LOCK TABLES course WRITE, userdata READ, classCourse WRITE, ProfCourse WRITE');

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
                return res.status(403).json({ error: 'Permission denied. Only professors and admins can delete departments.' });
            }

            const [courseData] = await db_connection.query(`
                SELECT courseID
                FROM Course
                WHERE CourseName = ? AND isActive = '1'
            `, [courseName]);

            if (courseData.length === 0) {
                return res.status(404).json({ error: 'Course not found or inactive' });
            }
            const courseID = courseData[0].courseID;

            await db_connection.query('START TRANSACTION');

            // Remove entries from ClassCourse related to this course
            await db_connection.query(`
                DELETE FROM classCourse
                WHERE courseID = ?
            `, [courseID]);

            // Remove entries from ClassCourse related to this course
            await db_connection.query(`
                DELETE FROM ProfCourse
                WHERE courseID = ?
            `, [courseID]);

            // Commit transaction
            await db_connection.query('COMMIT');

            // Deactivate the department
            await db_connection.query('UPDATE Course SET isActive = ? WHERE courseID = ?', ['0', courseID]);
            res.json({ message: 'Course and associated data deactivated successfully' });
        } catch (error) {
            console.error(error);
            await db_connection.query('ROLLBACK');
            const time = new Date();
            fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - deleteCourse - ${error}\n`);
            res.status(500).json({ error: 'Failed to delete course and associated data' });
        }
        finally {
            // Unlock the tables
            await db_connection.query('UNLOCK TABLES');
            db_connection.release();
        }
    },],

    allCourses: [webTokenValidator, async (req, res) => {
        let db_connection;

        try {
            db_connection = await db.promise().getConnection();

            // Lock the necessary tables to prevent concurrent writes
            await db_connection.query('LOCK TABLES course READ');

            const [rows] = await db_connection.query('SELECT courseName FROM course WHERE isActive = ?', [1]);
            const courseNames = rows.map(row => row.courseName);

            res.status(200).json({ courses: courseNames }); // Wrap course names in an object with 'courses' key
        } catch (error) {
            console.error(error);
            const time = new Date();
            fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - api/courses - ${error}\n`);
            res.status(500).json({ error: 'Failed to fetch courses' });
        } finally {
            // Unlock the tables
            await db_connection.query('UNLOCK TABLES');
            db_connection?.release();
        }
    }],

    myCourses: [webTokenValidator, async (req, res) => {

        let db_connection;

        try {
            db_connection = await db.promise().getConnection();

            // Lock the necessary tables to prevent concurrent writes
            await db_connection.query('LOCK TABLES USERDATA READ, course READ');

            const userEmail = req.userEmail;

            console.log(userEmail)

            // Fetch userRole based on the email
            const [userData] = await db_connection.query(`SELECT userRole FROM USERDATA WHERE email = ? AND isActive = '1'`, [userEmail]);

            if (userData.length === 0) {
                return res.status(404).json({ error: 'User not found or inactive' });
            }

            await db_connection.query('UNLOCK TABLES');

            const userRole = userData[0].userRole;

            if (userRole != 0 && userRole != 1) {
                return res.status(403).json({ error: 'Permission denied. Only professors and admins can view courses.' });
            }

            await db_connection.query('LOCK TABLES USERDATA READ, course READ, ProfCourse READ');

            // Fetch courses associated with the user
            const [rows] = await db_connection.query(`SELECT courseName FROM Course WHERE CourseID in (SELECT CourseID FROM ProfCourse WHERE ProfessorID in (SELECT ProfID FROM userdata WHERE email = ? AND isActive = '1'))`, [userEmail]);

            if (rows.length === 0) {
                return res.status(401).json({ message: 'No Courses found' });
            }

            console.log(rows)

            const userCourses = rows.map(row => row.courseName);

            res.status(200).json({ courses: userCourses });
        } catch (error) {
            console.error(error);
            const time = new Date();
            // Log the error to a file
            fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - myCourses - ${error}\n`);
            res.status(500).json({ error: 'Failed to fetch user courses' });
        } finally {
            // Unlock the tables
            await db_connection.query('UNLOCK TABLES');
            db_connection?.release();
        }
    },],

};