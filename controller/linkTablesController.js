const { db } = require('../connection')

const webTokenValidator = require('../middleware/webTokenValidator');

const fs = require('fs');

module.exports = {


    addProfCourse: [webTokenValidator, async (req, res) => {
        /*
            JSON
            {
                "profEmail": "<profemail>"
                "courses": "[<course1>, <course2>]"
            }
        */
        let db_connection;

        try {
            const { profEmail, courses } = req.body;
            db_connection = await db.promise().getConnection();
            console.log(profEmail, courses)
            // Lock the necessary tables to prevent concurrent writes
            await db_connection.query('LOCK TABLES profcourse WRITE, userdata READ, Course READ');

            const userEmail = req.userEmail;
            console.log(userEmail)

            // Fetch userRole based on the email and check if user is active
            const [userData] = await db_connection.query(`
            SELECT userRole
            FROM USERDATA
            WHERE email = ? AND isActive = '1'
            `, [userEmail]);

            if (userData.length === 0) {
                return res.status(404).json({ error: 'User not found or inactive' });
            }

            // Fetch Courses passed as params and check if all are already present or is active
            const placeholders = courses.map(() => '?').join(', '); // Generate placeholders like (?, ?)

            const query = `
                SELECT courseID
                FROM Course
                WHERE courseName IN (${placeholders}) AND isActive = '1'
            `;
            const [courseData] = await db_connection.query(query, courses);

            console.log(courseData)
            if (courseData.length != courses.length) {
                return res.status(404).json({ error: 'Course not found or inactive' });
            }

            // Fetch Prof email passed as param and check if that email is present or is active
            const [profData] = await db_connection.query(`
            SELECT ProfID
            FROM UserData
            WHERE email = ? AND isActive = '1'
            `, [profEmail]);

            console.log(profData)
            if (profData.length === 0) {
                return res.status(404).json({ error: 'Professor email entered was not found or inactive' });
            }

            const userRole = userData[0].userRole;

            if (userRole != 0 && userRole != 1) {
                return res.status(403).json({ error: 'Permission denied. Only professors and admins can access.' });
            }

            await db_connection.query('START TRANSACTION');

            let addedCourses = 0;
            for (i of courseData) {
                const [available] = await db_connection.query('SELECT * FROM ProfCourse WHERE ProfessorID = ? AND CourseID = ?', [profData[0].ProfID, i.courseID]);
                if (available.length === 0) {
                    const [result] = await db_connection.query('INSERT INTO ProfCourse (professorID, CourseID) VALUES (?, ?)', [profData[0].ProfID, i.courseID]);
                    if (result.affectedRows === 1) {
                        addedCourses += 1;
                    } else {
                        // Rollback the transaction
                        await db_connection.query('ROLLBACK');
                        res.status(500).json({ error: 'Failed to create courses' });
                    }
                }
            }
            if (addedCourses <= courseData.length) {
                await db_connection.query('COMMIT');
                res.status(201).json({ message: 'Courses created successfully' });
            }

        } catch (error) {
            if (db_connection) {
                await db_connection.query('ROLLBACK');
            }
            const time = new Date();
            fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - add Prof Course - ${error}\n`);
            res.status(500).json({ error: 'Failed to create Courses for professor' });
        } finally {
            // Unlock the tables
            await db_connection.query('UNLOCK TABLES');
            db_connection.release();
        }
    }],

    deleteProfCourse: [webTokenValidator, async (req, res) => {
        /*
        
        */
        let db_connection;

        try {
            const { profEmail, courses } = req.body;
            db_connection = await db.promise().getConnection();
            console.log(profEmail, courses)
            // Lock the necessary tables to prevent concurrent writes
            await db_connection.query('LOCK TABLES profcourse WRITE, userdata READ, Course READ');

            const userEmail = req.userEmail;
            console.log(userEmail)

            // Fetch userRole based on the email and check if user is active
            const [userData] = await db_connection.query(`
            SELECT userRole
            FROM USERDATA
            WHERE email = ? AND isActive = '1'
            `, [userEmail]);

            if (userData.length === 0) {
                return res.status(404).json({ error: 'User not found or inactive' });
            }

            const placeholders = courses.map(() => '?').join(', '); // Generate placeholders like (?, ?)
            const query = `
                SELECT courseID
                FROM Course
                WHERE courseName IN (${placeholders}) AND isActive = '1'
            `;
            const [courseData] = await db_connection.query(query, courses);

            console.log(courseData)
            if (courseData.length != courses.length) {
                return res.status(404).json({ error: 'Course not found or inactive' });
            }
            const [profData] = await db_connection.query(`
            SELECT ProfID
            FROM UserData
            WHERE email = ? AND isActive = '1'
            `, [profEmail]);

            console.log(profData)
            if (profData.length === 0) {
                return res.status(404).json({ error: 'Professor email entered was not found or inactive' });
            }

            const userRole = userData[0].userRole;

            if (userRole != 0 && userRole != 1) {
                return res.status(403).json({ error: 'Permission denied. Only professors and admins can access.' });
            }

            await db_connection.query('START TRANSACTION');

            let deletedCourses = 0;
            for (i of courseData) {
                const [available] = await db_connection.query('SELECT * FROM ProfCourse WHERE ProfessorID = ? AND CourseID = ?', [profData[0].ProfID, i.courseID]);
                if (available.length === 1) {
                    const [result] = await db_connection.query('DELETE FROM ProfCourse WHERE professorID = ? AND CourseID = ?', [profData[0].ProfID, i.courseID]);
                    if (result.affectedRows === 1) {
                        deletedCourses += 1;
                    } else {
                        // Rollback the transaction
                        await db_connection.query('ROLLBACK');
                        return res.status(500).json({ error: 'Failed to delete courses' });
                    }
                }
            }
            if (deletedCourses <= courseData.length) {
                await db_connection.query('COMMIT');
                return res.status(201).json({ message: 'Courses deleted successfully' });
            }

        } catch (error) {
            if (db_connection) {
                await db_connection.query('ROLLBACK');
            }
            // const time = new Date();
            // fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - add Prof Course - ${error}\n`);
            res.status(500).json({ error: 'Failed to create Courses for professor' });
        } finally {
            // Unlock the tables
            await db_connection.query('UNLOCK TABLES');
            db_connection.release();
        }
    }],

    addClassCourseProf: [webTokenValidator, async (req, res) => {
        /*
            JSON
            {
                "batchYear": "<batchYear>",
                "Dept": "<Dept>",
                "Section": "<Section>",
                "Semester": "<Semester>",
                "courses": "[<course1>,<coourse2>]",
                "profEmails":"[<prof1>,<prof2>]"
            }
        */
        let db_connection;

        try {
            const { batchYear, Dept, Section, Semester, courses, profEmails } = req.body;
            db_connection = await db.promise().getConnection();
            console.log(profEmails, courses)
            // Lock the necessary tables to prevent concurrent writes
            await db_connection.query('LOCK TABLES classcourse WRITE, professorclass WRITE, userdata READ, Course READ, Department READ, class READ');

            const userEmail = req.userEmail;
            console.log(userEmail)

            // Fetch userRole based on the email and check if user is active
            const [userData] = await db_connection.query(`
            SELECT userRole
            FROM USERDATA
            WHERE email = ? AND isActive = '1'
            `, [userEmail]);
            if (userData.length === 0) {
                return res.status(404).json({ error: 'User not found or inactive' });
            }

            // Fetch Courses passed as params and check if all are already present or is active
            let courseData
            if (courses && Array.isArray(courses) && courses.length > 0) {
                const placeholdersc = courses.map(() => '?').join(', ');
                let query = `
                    SELECT courseID
                    FROM Course
                    WHERE courseName IN (${placeholdersc}) AND isActive = '1'
                `;
                [courseData] = await db_connection.query(query, courses);
                console.log(courseData)
                if (courseData.length != courses.length) {
                    return res.status(404).json({ error: 'Course not found or inactive' });
                }
            }

            //Fetch prof and check if all the profs are available or active
            let profData
            if (profEmails && Array.isArray(profEmails) && profEmails.length > 0) {
                const placeholders = profEmails.map(() => '?').join(', ');
                query = `
                    SELECT profID
                    FROM userdata
                    WHERE email IN (${placeholders}) AND isActive = '1'
                `;
                [profData] = await db_connection.query(query, profEmails);
                console.log(profData)
                if (profData.length != profEmails.length) {
                    return res.status(404).json({ error: 'Professor not found or inactive' });
                }
            }


            // Fetch Department passed as param and check if that dept is present or is active
            const [deptData] = await db_connection.query(`
            SELECT DeptID
            FROM department
            WHERE DeptName = ? AND isActive = '1'
            `, [Dept]);
            console.log(deptData)
            if (deptData.length === 0) {
                return res.status(404).json({ error: 'Department entered was not found or inactive' });
            }

            // Fetch Class passed as param and check if that class is present or is active
            const [classData] = await db_connection.query(`
            SELECT classID
            FROM class
            WHERE batchYear = ? AND DeptID = ? AND Section = ? AND Semester = ? AND isActive = '1'
            `, [batchYear, deptData[0].DeptID, Section, Semester]);
            console.log(classData)
            if (classData.length === 0) {
                return res.status(404).json({ error: 'Class entered was not found or inactive' });
            }

            const userRole = userData[0].userRole;

            if (userRole != 0 && userRole != 1) {
                return res.status(403).json({ error: 'Permission denied. Only professors and admins can access.' });
            }

            //To add Courses to class
            let addedCourses = 0;
            if (courses && Array.isArray(courses) && courses.length > 0) {
                await db_connection.query('START TRANSACTION');
                for (i of courseData) {
                    const [available] = await db_connection.query('SELECT * FROM ClassCourse WHERE ClassID = ? AND CourseID = ?', [classData[0].classID, i.courseID]);
                    if (available.length === 0) {
                        const [result] = await db_connection.query('INSERT INTO ClassCourse (classID, CourseID) VALUES (?, ?)', [classData[0].classID, i.courseID]);
                        if (result.affectedRows === 1) {
                            addedCourses += 1;
                        } else {
                            // Rollback the transaction
                            await db_connection.query('ROLLBACK');
                            res.status(500).json({ error: 'Failed to create courses' });
                        }
                    }
                }
                if (addedCourses <= courseData.length) {
                    await db_connection.query('COMMIT');
                }
            }


            //To add Professors to class
            let addedProfs = 0;
            if (profEmails && Array.isArray(profEmails) && profEmails.length > 0) {
                await db_connection.query('START TRANSACTION');
                for (i of profData) {
                    const [available] = await db_connection.query('SELECT * FROM professorClass WHERE ClassID = ? AND professorID = ?', [classData[0].classID, i.profID]);
                    if (available.length === 0) {
                        const [result] = await db_connection.query('INSERT INTO professorClass (classID, professorID) VALUES (?, ?)', [classData[0].classID, i.profID]);
                        if (result.affectedRows === 1) {
                            addedProfs += 1;
                        } else {
                            // Rollback the transaction
                            await db_connection.query('ROLLBACK');
                            res.status(500).json({ error: 'Failed to add Professors' });
                        }
                    }
                }
                if (addedProfs <= profData.length) {
                    await db_connection.query('COMMIT');
                }
            }
            if ((profEmails && Array.isArray(profEmails) && profEmails.length > 0 && addedProfs <= profData.length) || (courses && Array.isArray(courses) && courses.length > 0 && addedCourses <= courseData.length)) {
                await db_connection.query('COMMIT');
                res.status(201).json({ message: 'Professors and Courses added successfully' });
            }

        } catch (error) {
            console.log(error)
            if (db_connection) {
                await db_connection.query('ROLLBACK');
            }
            // const time = new Date();
            // fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - add Class, Course, Prof - ${error}\n`);
            res.status(500).json({ error: 'Failed to create Courses or Professor for Class' });
        } finally {
            // Unlock the tables
            await db_connection.query('UNLOCK TABLES');
            db_connection.release();
        }
    }],

    deleteClassCourseProf: [webTokenValidator, async (req, res) => {
        /*
            JSON
            {
                "batchYear": "<batchYear>",
                "Dept": "<Dept>",
                "Section": "<Section>",
                "Semester": "<Semester>",
                "courses": "[<course1>,<coourse2>]",
                "profEmails":"[<prof1>,<prof2>]"
            }
        */
        let db_connection;

        try {
            const { batchYear, Dept, Section, Semester, courses, profEmails } = req.body;
            db_connection = await db.promise().getConnection();
            console.log(profEmails, courses)
            // Lock the necessary tables to prevent concurrent writes
            await db_connection.query('LOCK TABLES classcourse WRITE, professorclass WRITE, userdata READ, Course READ, Department READ, class READ');

            const userEmail = req.userEmail;
            console.log(userEmail)

            // Fetch userRole based on the email and check if user is active
            const [userData] = await db_connection.query(`
            SELECT userRole
            FROM USERDATA
            WHERE email = ? AND isActive = '1'
            `, [userEmail]);
            if (userData.length === 0) {
                return res.status(404).json({ error: 'User not found or inactive' });
            }

            // Fetch Courses passed as params and check if all are already present or is active
            let courseData
            if (courses && Array.isArray(courses) && courses.length > 0) {
                const placeholdersc = courses.map(() => '?').join(', ');
                let query = `
                    SELECT courseID
                    FROM Course
                    WHERE courseName IN (${placeholdersc}) AND isActive = '1'
                `;
                [courseData] = await db_connection.query(query, courses);
                console.log(courseData)
                if (courseData.length != courses.length) {
                    return res.status(404).json({ error: 'Course not found or inactive' });
                }
            }

            //Fetch prof and check if all the profs are available or active
            let profData
            if (profEmails && Array.isArray(profEmails) && profEmails.length > 0) {
                const placeholders = profEmails.map(() => '?').join(', ');
                query = `
                    SELECT profID
                    FROM userdata
                    WHERE email IN (${placeholders}) AND isActive = '1'
                `;
                [profData] = await db_connection.query(query, profEmails);
                console.log(profData)
                if (profData.length != profEmails.length) {
                    return res.status(404).json({ error: 'Professor not found or inactive' });
                }
            }


            // Fetch Department passed as param and check if that dept is present or is active
            const [deptData] = await db_connection.query(`
            SELECT DeptID
            FROM department
            WHERE DeptName = ? AND isActive = '1'
            `, [Dept]);
            console.log(deptData)
            if (deptData.length === 0) {
                return res.status(404).json({ error: 'Department entered was not found or inactive' });
            }

            // Fetch Class passed as param and check if that class is present or is active
            const [classData] = await db_connection.query(`
            SELECT classID
            FROM class
            WHERE batchYear = ? AND DeptID = ? AND Section = ? AND Semester = ? AND isActive = '1'
            `, [batchYear, deptData[0].DeptID, Section, Semester]);
            console.log(classData)
            if (classData.length === 0) {
                return res.status(404).json({ error: 'Class entered was not found or inactive' });
            }

            const userRole = userData[0].userRole;

            if (userRole != 0 && userRole != 1) {
                return res.status(403).json({ error: 'Permission denied. Only professors and admins can access.' });
            }

            //To delete Courses of class
            let deletedCourses = 0;
            if (courses && Array.isArray(courses) && courses.length > 0) {
                await db_connection.query('START TRANSACTION');
                for (i of courseData) {
                    const [available] = await db_connection.query('SELECT * FROM ClassCourse WHERE ClassID = ? AND CourseID = ?', [classData[0].classID, i.courseID]);
                    if (available.length === 0) {
                        const [result] = await db_connection.query('DELETE FROM ClassCourse WHERE classID = ? AND CourseID = ?', [classData[0].classID, i.courseID]);
                        if (result.affectedRows === 1) {
                            deletedCourses += 1;
                        } else {
                            // Rollback the transaction
                            await db_connection.query('ROLLBACK');
                            return res.status(500).json({ error: 'Failed to delete courses' });
                        }
                    }
                }
                if (deletedCourses <= courseData.length) {
                    await db_connection.query('COMMIT');
                }
            }


            //To delete Professors of class
            let deletedProfs = 0;
            if (profEmails && Array.isArray(profEmails) && profEmails.length > 0) {
                await db_connection.query('START TRANSACTION');
                for (i of profData) {
                    const [available] = await db_connection.query('SELECT * FROM professorClass WHERE ClassID = ? AND professorID = ?', [classData[0].classID, i.profID]);
                    if (available.length === 0) {
                        const [result] = await db_connection.query('DELETE FROM professorClass WHERE classID = ? AND professorID = ?', [classData[0].classID, i.profID]);
                        if (result.affectedRows === 1) {
                            deletedProfs += 1;
                        } else {
                            // Rollback the transaction
                            await db_connection.query('ROLLBACK');
                            return res.status(500).json({ error: 'Failed to delete Professors' });
                        }
                    }
                }
                if (deletedProfs <= profData.length) {
                    await db_connection.query('COMMIT');
                }
            }
            if ((profEmails && Array.isArray(profEmails) && profEmails.length > 0 && deletedProfs <= profData.length) || (courses && Array.isArray(courses) && courses.length > 0 && deletedCourses <= courseData.length)) {
                await db_connection.query('COMMIT');
                return res.status(201).json({ message: 'Professors and Courses deleted successfully' });
            }

        } catch (error) {
            console.log(error)
            if (db_connection) {
                await db_connection.query('ROLLBACK');
            }
            // const time = new Date();
            // fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - add Class, Course, Prof - ${error}\n`);
            return res.status(500).json({ error: 'Failed to delete Courses or Professor for Class' });
        } finally {
            // Unlock the tables
            await db_connection.query('UNLOCK TABLES');
            db_connection.release();
        }
    }],  

};