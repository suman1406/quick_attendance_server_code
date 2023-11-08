const { db } = require('../connection')

const webTokenGenerator = require('../middleware/webTokenGenerator');
const webTokenValidator = require('../middleware/webTokenValidator');
// const otpTokenGenerator = require('../middleware/otpTokenGenerator');
// const [otpTokenValidator, resetPasswordValidator] = require('../middleware/otpTokenValidator');

// const generateOTP = require("../middleware/otpGenerator");
// const passwordGenerator = require('secure-random-password');

const crypto = require('crypto');

// const mailer = require('../mail/mailer');

const fs = require('fs');
const validator = require('validator');

module.exports = {

    test: async (req, res) => {
        return res.status(200).send({ "message": 'Ok' });
    },

    // -------------------Admin Account-------------------------

    addAdmin: async (req, res) => {
        try {
            const currentUserRole = req.userRole;

            if (currentUserRole !== 1) {
                return res.status(403).json({ error: 'Permission denied. Only admins can add admin users.' });
            }

            const { adminName, email, password } = req.body;

            const salt = crypto.randomBytes(16).toString('hex');

            const hashedPassword = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');

            const [result] = await db.promise().execute('INSERT INTO USERDATA (profName, email, password, userRole) VALUES (?, ?, ?, ?)', [adminName, email, hashedPassword, 1]);

            if (result.affectedRows === 1) {
                res.status(201).json({ message: 'Admin user created successfully' });
            } else {
                res.status(500).json({ error: 'Failed to create admin user' });
            }
        } catch (error) {
            console.error(error);
            res.status(500).json({ error: 'Failed to create admin user' });
        }
    },

    editAdmin: async (req, res) => {
        try {
            const currentUserRole = req.userRole;
            const adminID = req.params.id;
            const { adminName, email, password } = req.body;

            if (currentUserRole !== 1) {
                return res.status(403).json({ error: 'Permission denied. Only admins can edit admin profiles.' });
            }

            if (password) {
                const salt = crypto.randomBytes(16).toString('hex');
                const hashedPassword = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');

                const [result] = await db.promise().execute('UPDATE USERDATA SET profName = ?, email = ?, password = ? WHERE profID = ?', [adminName, email, hashedPassword, adminID]);
            } else {
                const [result] = await db.promise().execute('UPDATE USERDATA SET profName = ?, email = ? WHERE profID = ?', [adminName, email, adminID]);
            }

            if (result.affectedRows === 1) {
                res.json({ message: 'Admin member updated successfully' });
            } else {
                res.status(404).json({ error: 'Admin member not found' });
            }
        } catch (error) {
            console.error(error);
            res.status(500).json({ error: 'Failed to update admin member' });
        }
    },

    deleteAdmin: async (req, res) => {
        try {
            const currentUserRole = req.userRole;
            const adminID = req.params.id;

            if (currentUserRole !== 1) {
                return res.status(403).json({ error: 'Permission denied. Only admins can delete admin members.' });
            }

            const [result] = await db.promise().execute('UPDATE USERDATA SET isActive = ? WHERE profID = ?', [0, adminID]);

            if (result.affectedRows === 1) {
                res.json({ message: 'Admin member deleted successfully' });
            } else {
                res.status(404).json({ error: 'Admin member not found' });
            }
        } catch (error) {
            console.error(error);
            res.status(500).json({ error: 'Failed to delete admin member' });
        }
    },

    // -------------------Admin Account-------------------------

    addFaculty: async (req, res) => {
        try {
            const currentUserRole = req.userRole;

            if (currentUserRole !== 1) {
                return res.status(403).json({ error: 'Permission denied. Only admins can add faculty members.' });
            }

            const { profName, email, password } = req.body;

            const salt = crypto.randomBytes(16).toString('hex');

            const hashedPassword = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');

            const [result] = await db.promise().execute('INSERT INTO USERDATA (profName, email, password, userRole) VALUES (?, ?, ?, ?)', [profName, email, hashedPassword, 0]);

            if (result.affectedRows === 1) {
                res.status(201).json({ message: 'Faculty member created successfully' });
            } else {
                res.status(500).json({ error: 'Failed to create faculty member' });
            }
        } catch (error) {
            console.error(error);
            res.status(500).json({ error: 'Failed to create faculty member' });
        }
    },

    editFaculty: async (req, res) => {
        try {
            const currentUserRole = req.userRole;
            const profID = req.params.id;
            const { profName, email, password } = req.body;

            const [faculty] = await db.promise().execute('SELECT userRole FROM USERDATA WHERE profID = ?', [profID]);

            if (faculty.length === 0) {
                return res.status(404).json({ error: 'Faculty member not found' });
            }

            const facultyUserRole = faculty[0].userRole;

            if (currentUserRole === 0) {
                if (facultyUserRole === 1) {
                    return res.status(403).json({ error: 'Permission denied. Professors cannot edit admin profiles.' });
                } else if (profID !== req.userID) {
                    return res.status(403).json({ error: 'Permission denied. Professors can only edit their own faculty profile.' });
                }
            }

            if (password) {
                const salt = crypto.randomBytes(16).toString('hex');

                const hashedPassword = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');

                const [result] = await db.promise().execute('UPDATE USERDATA SET profName = ?, email = ?, password = ? WHERE profID = ?', [profName, email, hashedPassword, profID]);
            } else {
                const [result] = await db.promise().execute('UPDATE USERDATA SET profName = ?, email = ? WHERE profID = ?', [profName, email, profID]);
            }

            if (result.affectedRows === 1) {
                res.json({ message: 'Faculty member updated successfully' });
            } else {
                res.status(404).json({ error: 'Faculty member not found' });
            }
        } catch (error) {
            console.error(error);
            res.status(500).json({ error: 'Failed to update faculty member' });
        }
    },

    deleteFaculty: async (req, res) => {
        try {
            const currentUserRole = req.userRole;

            if (currentUserRole !== 1) {
                return res.status(403).json({ error: 'Permission denied. Only admins can deactivate faculty members.' });
            }

            const profID = req.params.id;

            const [result] = await db.promise().execute('UPDATE USERDATA SET isActive = ? WHERE profID = ?', [0, profID]); // Deactivate faculty member

            if (result.affectedRows === 1) {
                res.json({ message: 'Faculty member deactivated successfully' });
            } else {
                res.status(404).json({ error: 'Faculty member not found' });
            }
        } catch (error) {
            console.error(error);
            res.status(500).json({ error: 'Failed to deactivate faculty member' });
        }
    },

    allFaculty: async (req, res) => {
        try {
            const currentUserRole = req.userRole;

            if (currentUserRole !== 1) {
                return res.status(403).json({ error: 'Permission denied. Only administrators can access faculty members.' });
            }

            const [rows] = await db.promise().execute('SELECT * FROM USERDATA WHERE isActive = ? AND userRole = ?', [1, 0]); // 1 is for Active and 0 for professor

            res.json(rows);
        } catch (error) {
            console.error(error);
            res.status(500).json({ error: 'Failed to fetch faculty members' });
        }
    },

    userLogin: async (req, res) => {
        if (
            req.body.email === null ||
            req.body.email === undefined ||
            req.body.email === "" ||
            !validator.isEmail(req.body.email) ||
            req.body.password === null ||
            req.body.password === undefined ||
            req.body.password === ""
        ) {
            return res.status(400).send({ "message": "Missing details." });
        }

        let db_connection = await db.promise().getConnection();

        try {
            await db_connection.query('LOCK TABLES USERDATA READ');

            let [professor] = await db_connection.query('SELECT * FROM USERDATA WHERE email = ?', [req.body.email]);

            if (professor.length === 0) {
                await db_connection.query('UNLOCK TABLES');
                return res.status(400).send({ "message": "User does not exist." });
            }

            if (professor.length > 0) {
                if (professor[0].isActive === '0') {
                    await db_connection.query('UNLOCK TABLES');
                    return res.status(401).send({ "message": "Your account has been deactivated." });
                }

                const passwordMatch = crypto.timingSafeEqual(Buffer.from(req.body.password), Buffer.from(professor[0].password, 'hex'));

                if (passwordMatch) {
                    const secret_token = await webTokenGenerator({
                        "email": req.body.email,
                        "userRole": professor[0].userRole,
                    });

                    await db_connection.query('UNLOCK TABLES');

                    return res.status(200).send({
                        "message": "Professor logged in!",
                        "SECRET_TOKEN": secret_token,
                        "profName": professor[0].profName,
                        "email": professor[0].email,
                        "userRole": professor[0].userRole,
                        "profID": professor[0].profID,
                        "isActive": professor[0].isActive,
                    });
                } else {
                    await db_connection.query('UNLOCK TABLES');
                    return res.status(401).send({ "message": "Invalid email or password." });
                }
            } else {
                await db_connection.query('UNLOCK TABLES');
                return res.status(400).send({ "message": "Invalid email or password." });
            }
        } catch (err) {
            console.log(err);
            const time = new Date();
            fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - userLogin - ${err}\n`);
            return res.status(500).send({ "message": "Internal Server Error." });
        } finally {
            await db_connection.query('UNLOCK TABLES');
            db_connection.release();
        }
    },

    loginVerify: [
        async (req, res) => {

            let db_connection = await db.promise().getConnection();

            try {
                let [user] = await db_connection.query('SELECT * from USERDATA WHERE email = ?', [req.email]);

                if (user.length === 0) {
                    return res.status(401).send({ "message": "User doesn't exist!" });
                }

                if (user[0].isActive === '0') {
                    return res.status(401).send({ "message": "User's account is deactivated!" });
                }

                const passwordMatch = crypto.timingSafeEqual(Buffer.from(req.password), Buffer.from(user[0].password, 'hex'));

                if (passwordMatch) {
                    const secret_token = await webTokenGenerator({
                        "userEmail": req.email,
                        "userRole": user[0].userRole,
                    });

                    if (user[0].userRole === '0') {
                        return res.status(200).send({
                            "message": "Professor logged in!",
                            "SECRET_TOKEN": secret_token,
                            "profName": user[0].profName,
                            "email": user[0].email,
                            "userRole": user[0].userRole,
                            "profID": user[0].profID,
                            "isActive": user[0].isActive,
                        });
                    } else if (user[0].userRole === '1') {
                        return res.status(200).send({
                            "message": "Admin logged in!",
                            "SECRET_TOKEN": secret_token,
                            "adminName": user[0].adminName,
                            "email": user[0].email,
                            "userRole": user[0].userRole,
                            "adminID": user[0].adminID,
                            "isActive": user[0].isActive,
                        });
                    }
                } else {
                    return res.status(401).send({ "message": "Invalid email or password." });
                }
            } catch (err) {
                console.log(err);
                const time = new Date();
                fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - loginVerify - ${err}\n`);
                return res.status(500).send({ "message": "Internal Server Error." });
            } finally {
                db_connection.release();
            }
        },
    ],

    resetPassword: async (req, res) => {
        try {
            const currentUserRole = req.userRole;
            const stdID = req.params.id;
            const newPassword = req.body.newPassword;

            if (currentUserRole !== 1) {
                return res.status(403).json({ error: 'Permission denied. Only admins can reset passwords.' });
            }

            const salt = crypto.randomBytes(16).toString('hex');
            const hashedPassword = crypto.pbkdf2Sync(newPassword, salt, 10000, 64, 'sha512').toString('hex');

            const [result] = await db.promise().execute('UPDATE studentData SET password = ? WHERE profID = ?', [hashedPassword, stdID]);

            if (result.affectedRows === 1) {
                res.json({ message: 'Student password reset successfully' });
            } else {
                res.status(404).json({ error: 'Student not found' });
            }
        } catch (error) {
            console.error(error);
            res.status(500).json({ error: 'Failed to reset student password' });
        }
    },

    addStudent: async (req, res) => {
        try {
            const { RollNo, StdName, batchYear, Dept, Section } = req.body;

            const [result] = await db.promise().execute('INSERT INTO studentData (RollNo, StdName, batchYear, Dept, Section) VALUES (?, ?, ?, ?, ?)', [RollNo, StdName, batchYear, Dept, Section]);

            if (result.affectedRows === 1) {
                res.status(201).json({ message: 'Student added successfully' });
            } else {
                res.status(500).json({ error: 'Failed to add student' });
            }
        } catch (error) {
            console.error(error);
            res.status(500).json({ error: 'Failed to add student' });
        }
    },

    editStudent: async (req, res) => {
        try {
            const stdID = req.params.id;
            const { RollNo, StdName, batchYear, Dept, Section } = req.body;

            const [result] = await db.promise().execute('UPDATE studentData SET RollNo = ?, StdName = ?, batchYear = ?, Dept = ?, Section = ? WHERE StdID = ?', [RollNo, StdName, batchYear, Dept, Section, stdID]);

            if (result.affectedRows === 1) {
                res.json({ message: 'Student updated successfully' });
            } else {
                res.status(404).json({ error: 'Student not found' });
            }
        } catch (error) {
            console.error(error);
            res.status(500).json({ error: 'Failed to update student' });
        }
    },

    deleteStudent: async (req, res) => {
        try {
            const stdID = req.params.id;

            const [result] = await db.promise().execute('UPDATE studentData SET isActive = ? WHERE StdID = ?', [0, stdID]);

            if (result.affectedRows === 1) {
                res.json({ message: 'Student deactivated successfully' });
            } else {
                res.status(404).json({ error: 'Student not found' });
            }
        } catch (error) {
            console.error(error);
            res.status(500).json({ error: 'Failed to deactivate student' });
        }
    },

    allStudents: async (req, res) => {
        try {
            // Filter students by class where batchYear, Dept, and Section are received as query parameters:
            const { batchYear, Dept, Section } = req.query;
            const [rows] = await db.promise().execute('SELECT * FROM studentData WHERE isActive = ? AND batchYear = ? AND Dept = ? AND Section = ?', [1, batchYear, Dept, Section]);

            res.json(rows);
        } catch (error) {
            console.error(error);
            res.status(500).json({ error: 'Failed to fetch students' });
        }
    },

    addStudents: async (req, res) => {
        try {
            const students = req.body;

            const values = students.map(({ RollNo, StdName, batchYear, Dept, Section }) => [RollNo, StdName, batchYear, Dept, Section]);
            const query = 'INSERT INTO studentData (RollNo, StdName, batchYear, Dept, Section) VALUES ?';

            const [result] = await db.promise().query(query, [values]);

            if (result.affectedRows > 0) {
                res.status(201).json({ message: 'Students added successfully' });
            } else {
                res.status(500).json({ error: 'Failed to add students' });
            }
        } catch (error) {
            console.error(error);
            res.status(500).json({ error: 'Failed to add students' });
        }
    },

    createClass: async (req, res) => {
        try {
            const currentUserRole = req.userRole;

            if (currentUserRole !== 0 && currentUserRole !== 1) {
                return res.status(403).json({ error: 'Permission denied. Only professors and admins can create classes.' });
            }

            const { batchYear, Dept, Section, Semester, profID } = req.body;

            const [result] = await db.promise().execute('INSERT INTO class (batchYear, Dept, Section, Semester, profID) VALUES (?, ?, ?, ?, ?)', [batchYear, Dept, Section, Semester, profID]);

            if (result.affectedRows === 1) {
                res.status(201).json({ message: 'Class created successfully' });
            } else {
                res.status(500).json({ error: 'Failed to create class' });
            }
        } catch (error) {
            console.error(error);
            res.status(500).json({ error: 'Failed to create class' });
        }
    },

    myClasses: async (req, res) => {
        try {
            const currentUserRole = req.userRole;

            if (currentUserRole !== 0 && currentUserRole !== 1) {
                return res.status(403).json({ error: 'Permission denied. Only professors and admins can access classes.' });
            }

            const profID = req.params.id;

            // You can implement the logic to fetch classes taught by the professor based on their profID
            const [rows] = await db.promise().execute('SELECT * FROM class WHERE profID = ?', [profID]);

            res.json(rows);
        } catch (error) {
            console.error(error);
            res.status(500).json({ error: 'Failed to fetch classes' });
        }
    },

    deleteClass: async (req, res) => {
        try {
            const currentUserRole = req.userRole;
            const classID = req.params.id;

            if (currentUserRole !== 0 && currentUserRole !== 1) {
                return res.status(403).json({ error: 'Permission denied. Only professors and admins can delete classes.' });
            }

            const [result] = await db.promise().execute('DELETE FROM class WHERE classID = ?', [classID]);

            if (result.affectedRows === 1) {
                res.json({ message: 'Class deleted successfully' });
            } else {
                res.status(404).json({ error: 'Class not found' });
            }
        } catch (error) {
            console.error(error);
            res.status(500).json({ error: 'Failed to delete class' });
        }
    },

    createSlots: async (req, res) => {
        try {
            const currentUserRole = req.userRole;

            if (currentUserRole !== 0 && currentUserRole !== 1) {
                return res.status(403).json({ error: 'Permission denied. Only professors and admins can create class slots.' });
            }

            const { classID, periodNo } = req.body;

            const [result] = await db.promise().execute('INSERT INTO Slots (classID, periodNo) VALUES (?, ?)', [classID, periodNo]);

            if (result.affectedRows === 1) {
                res.status(201).json({ message: 'Slot created successfully' });
            } else {
                res.status(500).json({ error: 'Failed to create slot' });
            }
        } catch (error) {
            console.error(error);
            res.status(500).json({ error: 'Failed to create slot' });
        }
    },

    deleteSlot: async (req, res) => {
        try {
            const currentUserRole = req.userRole;
            const slotID = req.params.id;

            if (currentUserRole !== 0 && currentUserRole !== 1) {
                return res.status(403).json({ error: 'Permission denied. Only professors and admins can delete slots.' });
            }

            const [result] = await db.promise().execute('DELETE FROM Slots WHERE slotID = ?', [slotID]);

            if (result.affectedRows === 1) {
                res.json({ message: 'Slot deleted successfully' });
            } else {
                res.status(404).json({ error: 'Slot not found' });
            }
        } catch (error) {
            console.error(error);
            res.status(500).json({ error: 'Failed to delete slot' });
        }
    },

}