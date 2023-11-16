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

    test: async (req, res) => {
        console.log("recieved req")
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

            const { profName, email, password, courseID } = req.body;

            const salt = crypto.randomBytes(16).toString('hex');

            const hashedPassword = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');

            const [result] = await db.promise().execute('INSERT INTO USERDATA (profName, email, password, userRole, courseID) VALUES (?, ?, ?, ?, ?)', [profName, email, hashedPassword, 0, courseID]);

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
            const { profName, email, password, courseID } = req.body;

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

            let result;

            if (password) {
                const salt = crypto.randomBytes(16).toString('hex');
                const hashedPassword = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');

                [result] = await db.promise().execute('UPDATE USERDATA SET profName = ?, email = ?, password = ?, courseID = ? WHERE profID = ?', [profName, email, hashedPassword, courseID, profID]);
            } else {
                [result] = await db.promise().execute('UPDATE USERDATA SET profName = ?, email = ?, courseID = ? WHERE profID = ?', [profName, email, courseID, profID]);
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
            const currentUserRole = req.query.userRole;
            console.log(currentUserRole)

            if (currentUserRole != 1) {
                return res.status(403).json({ error: 'Permission denied. Only administrators can access faculty members.' });
            }

            const [rows] = await db.promise().execute('SELECT * FROM USERDATA WHERE isActive = ? AND userRole = ?', [1, 0]);

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

            console.log(professor);

            if (professor.length === 0) {
                await db_connection.query('UNLOCK TABLES');
                return res.status(400).send({ "message": "User does not exist." });
            }

            if (professor.length > 0) {
                if (professor[0].isActive === '0') {
                    await db_connection.query('UNLOCK TABLES');
                    return res.status(401).send({ "message": "Your account has been deactivated." });
                }

                // const passwordMatch = crypto.timingSafeEqual(Buffer.from(req.body.password), Buffer.from(professor[0].password, 'hex'));

                const passwordMatch = (req.body.password === professor[0].password);

                if (passwordMatch) {
                    const secret_token = await webTokenGenerator({
                        "email": req.body.email,
                        "userRole": professor[0].userRole,
                    });

                    await db_connection.query('UNLOCK TABLES');

                    return res.status(200).send({
                        "message": "User logged in!",
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
        otpTokenValidator,
        async (req, res) => {
            let db_connection = await db.promise().getConnection();

            try {
                // Check if the user exists
                let [user] = await db_connection.query('SELECT * from USERDATA WHERE email = ?', [req.email]);

                if (user.length === 0) {
                    return res.status(401).send({ "message": "User doesn't exist!" });
                }

                // Check if the user's account is deactivated
                if (user[0].isActive === '0') {
                    return res.status(401).send({ "message": "User's account is deactivated!" });
                }

                // Check if the OTP is valid
                let [checkOTP] = await db_connection.query(`DELETE from otpTable WHERE email = ? AND otp = ?`, [req.email, req.body.otp]);

                if (checkOTP.affectedRows === 0) {
                    return res.status(400).send({ "message": "Invalid OTP!" });
                }

                // Check if the password provided matches the stored password
                const passwordMatch = crypto.timingSafeEqual(Buffer.from(req.password), Buffer.from(user[0].password, 'hex'));

                if (passwordMatch) {
                    // Generate and send the authentication token
                    const secret_token = await webTokenGenerator({
                        "userEmail": req.email,
                        "userRole": user[0].userRole,
                    });

                    // Return user information based on the role
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

    forgotPassword: async (req, res) => {
        /*
        JSON
        {
            "userEmail": "<email_id>"
        }
        */
        if (
            req.body.userEmail === null ||
            req.body.userEmail === undefined ||
            req.body.userEmail === "" ||
            !validator.isEmail(req.body.userEmail)
        ) {
            return res.status(400).send({ message: "Missing details." });
        }

        let db_connection = await db.promise().getConnection();

        try {
            await db_connection.query(`LOCK TABLES USERDATA READ`);
            let [professor] = await db_connection.query(
                `SELECT profName, isActive FROM USERDATA WHERE email = ?`,
                [req.body.userEmail]
            );

            if (professor.length === 0) {
                await db_connection.query(`UNLOCK TABLES`);
                return res.status(401).send({ message: "Professor doesn't exist!" });
            }

            if (professor[0].isActive === "0") {
                return res.status(401).send({
                    message: "Your Account has been deactivated. Check your email for further instructions.",
                });
            }

            await db_connection.query(`LOCK TABLES USERREGISTER WRITE`);
            let name = professor[0]["profName"];
            let [professor_2] = await db_connection.query(
                `SELECT * from USERREGISTER WHERE email = ?`,
                [req.body.userEmail]
            );

            const otp = generateOTP();

            if (professor_2.length === 0) {
                await db_connection.query(
                    `INSERT INTO USERREGISTER (email, otp, createdAt) VALUES (?, ?, ?)`,
                    [req.body.userEmail, otp, new Date()]
                );
            } else {
                await db_connection.query(
                    `UPDATE USERREGISTER SET otp = ?, createdAt = ? WHERE email = ?`,
                    [otp, new Date(), req.body.userEmail]
                );
            }
            await db_connection.query(`UNLOCK TABLES`);

            const secret_token = await otpTokenGenerator({
                userEmail: req.body.userEmail,
                userRole: userRole,
            });

            mailer.reset_PW_OTP(profName, otp, req.body.userEmail);

            return res.status(200).send({
                message: "OTP sent to email.",
                SECRET_TOKEN: secret_token,
                userEmail: req.body.userEmail,
            });
        } catch (err) {
            console.log(err);
            const time = new Date();
            fs.appendFileSync(
                "logs/errorLogs.txt",
                `${time.toISOString()} - forgotPassword - ${err}\n`
            );
            return res.status(500).send({ message: "Internal Server Error." });
        } finally {
            await db_connection.query(`UNLOCK TABLES`);
            db_connection.release();
        }
    },

    resetPassword: async (req, res) => {
        /*
        JSON
        {
            "userEmail": "<email_id>",
            "newPassword": "<new_password>"
        }
        */
        if (
            req.body.userEmail === null ||
            req.body.userEmail === undefined ||
            req.body.userEmail === "" ||
            !validator.isEmail(req.body.userEmail) ||
            req.body.newPassword === null ||
            req.body.newPassword === undefined ||
            req.body.newPassword === ""
        ) {
            return res.status(400).send({ message: "Missing details." });
        }

        let db_connection = await db.promise().getConnection();

        try {
            await db_connection.query(`LOCK TABLES USERDATA WRITE`);
            let [professor] = await db_connection.query(
                `SELECT profName, isActive FROM USERDATA WHERE email = ?`,
                [req.body.userEmail]
            );

            if (professor.length === 0) {
                await db_connection.query(`UNLOCK TABLES`);
                return res.status(401).send({ message: "Professor doesn't exist!" });
            }

            if (professor[0].isActive === "0") {
                return res.status(401).send({
                    message: "Your Account has been deactivated. Check your email for further instructions.",
                });
            }

            await db_connection.query(
                `UPDATE USERDATA SET password = ? WHERE email = ?`,
                [req.body.newPassword, req.body.userEmail]
            );
            await db_connection.query(`UNLOCK TABLES`);

            return res.status(200).send({ message: "Password reset successful." });
        } catch (err) {
            console.log(err);
            const time = new Date();
            fs.appendFileSync(
                "logs/errorLogs.txt",
                `${time.toISOString()} - resetPassword - ${err}\n`
            );
            return res.status(500).send({ message: "Internal Server Error." });
        } finally {
            await db_connection.query(`UNLOCK TABLES`);
            db_connection.release();
        }
    },

    resetVerify: async (req, res) => {
        /*
        JSON
        {
            "userEmail": "<email_id>",
            "otp": "<otp>"
        }
        */
        if (
            req.body.userEmail === null ||
            req.body.userEmail === undefined ||
            req.body.userEmail === "" ||
            !validator.isEmail(req.body.userEmail) ||
            req.body.otp === null ||
            req.body.otp === undefined ||
            req.body.otp === ""
        ) {
            return res.status(400).send({ message: "Missing details." });
        }

        let db_connection = await db.promise().getConnection();

        try {
            await db_connection.query(`LOCK TABLES USERDATA READ, USERREGISTER READ`);
            let [professor] = await db_connection.query(
                `SELECT profName FROM USERDATA WHERE email = ?`,
                [req.body.userEmail]
            );
            let [userRegister] = await db_connection.query(
                `SELECT otp, createdAt FROM USERREGISTER WHERE email = ?`,
                [req.body.userEmail]
            );

            if (professor.length === 0 || userRegister.length === 0) {
                await db_connection.query(`UNLOCK TABLES`);
                return res.status(401).send({ message: "Invalid professor or OTP." });
            }

            const storedOTP = userRegister[0].otp;
            const otpCreatedAt = new Date(userRegister[0].createdAt);
            const currentTimestamp = new Date();

            const otpValidityWindow = 5 * 60 * 1000;

            if (storedOTP !== req.body.otp || currentTimestamp - otpCreatedAt > otpValidityWindow) {
                await db_connection.query(`UNLOCK TABLES`);
                return res.status(401).send({ message: "Invalid OTP." });
            }

            await db_connection.query(`UNLOCK TABLES`);
            return res.status(200).send({ message: "OTP verification successful." });
        } catch (err) {
            console.log(err);
            const time = new Date();
            fs.appendFileSync(
                "logs/errorLogs.txt",
                `${time.toISOString()} - resetVerify - ${err}\n`
            );
            return res.status(500).send({ message: "Internal Server Error." });
        } finally {
            await db_connection.query(`UNLOCK TABLES`);
            db_connection.release();
        }
    },

    // -------------------Student Account-------------------------

    addStudent: async (req, res) => {
        try {
            // Extract variables from req.body
            const { RollNo, StdName, isActive } = req.body;

            // Validate the presence of required fields
            console.log(req.body);

            // Ensure all required fields are defined
            if (!RollNo || !StdName || !batchYear || !Dept || !Section) {
                return res.status(400).json({ error: 'All fields are required' });
            }

            // Your MySQL query
            const query = 'INSERT INTO studentData (RollNo, StdName) VALUES (?, ?, ?, ?, ?)';

            // Execute the query
            const [result] = await db.promise().execute(query, [RollNo, StdName, batchYear, Dept, Section]);

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
            const { batchYear, dept, section } = req.query;
            const [rows] = await db.promise().execute('SELECT s.* FROM studentData s join class c on s.classID=c.classID WHERE s.isActive = ? AND c.batchYear = ? AND c.Dept = ? AND c.Section = ?', [1, batchYear, dept, section]);
            if (batchYear !== undefined && dept !== undefined && section !== undefined) {
                const [rows] = await db.promise().execute('SELECT s.* FROM studentData s join class c on s.classID=c.classID WHERE c.batchYear = ? AND c.Dept = ? AND c.Section = ?', [batchYear, dept, section]);
            } else {
                // Handle the case where one of the variables is undefined
                console.error('One of the parameters is undefined');
                res.status(500).json({ error: 'Internal Server Error' });
            }

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

    // ------------------------------------------------------------

    createClass: async (req, res) => {
        try {
            const currentUserRole = req.userRole;

            if (currentUserRole !== 0 && currentUserRole !== 1) {
                return res.status(403).json({ error: 'Permission denied. Only professors and admins can create classes.' });
            }

            const { batchYear, Dept, Section, Semester, profID, courseID } = req.body;

            const [result] = await db.promise().execute('INSERT INTO class (batchYear, Dept, Section, Semester, profID, courseID) VALUES (?, ?, ?, ?, ?, ?)', [batchYear, Dept, Section, Semester, profID, courseID]);

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
            const currentUserRole = req.query.userRole;

            if (currentUserRole != 0 && currentUserRole != 1) {
                return res.status(403).json({ error: 'Permission denied. Only professors and admins can access classes.' });
            }

            const profID = req.query.id;
            console.log(profID)

            // Fetch classes along with course information
            const [rows] = await db.promise().execute('SELECT c.Dept,c.Section, c.semester, c.batchYear, co.courseName FROM (class c JOIN userdata on userdata.profID = c.profID ) join course co on co.courseID = userdata.courseID WHERE c.profID = ?', [profID]);
            console.log(rows)

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