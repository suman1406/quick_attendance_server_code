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

    // -------------------Admin Operations Starts-------------------------

    addAdmin: async (req, res) => {
        /* 
        queries {
           userRole:<userRole> 
        }
        JSON
        {
            "adminName":"<adminName>",
            "email":"<email>",
            "password":"<password>"
        }
        */
        let db_connection;

        try {
            // Lock the necessary tables to prevent concurrent writes
            db_connection = await db.promise().getConnection();
            await db_connection.query('LOCK TABLES USERDATA WRITE');

            const currentUserRole = req.query.userRole;

            if (currentUserRole != 1) {
                return res.status(403).json({ error: 'Permission denied. Only admins can add admin users.' });
            }

            const { adminName, email, password } = req.body;

            const salt = crypto.randomBytes(16).toString('hex');
            const hashedPassword = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');

            // Start a transaction
            await db_connection.query('START TRANSACTION');

            const [result] = await db_connection.query('INSERT INTO USERDATA (profName, email, password, userRole) VALUES (?, ?, ?, ?)', [adminName, email, hashedPassword, 1]);

            if (result.affectedRows === 1) {
                // Commit the transaction
                await db_connection.query('COMMIT');
                res.status(201).json({ message: 'Admin user created successfully' });
            } else {
                // Rollback the transaction
                await db_connection.query('ROLLBACK');
                res.status(500).json({ error: 'Failed to create admin user' });
            }
        } catch (error) {
            console.error(error);

            // Rollback the transaction in case of an error
            if (db_connection) {
                await db_connection.query('ROLLBACK');
            }

            fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - addAdmin - ${error}\n`);

            res.status(500).json({ error: 'Failed to create admin user' });
        } finally {
            // Unlock the tables
            if (db_connection) {
                await db_connection.query('UNLOCK TABLES');
                db_connection.release();
            }
        }
    },

    editAdmin: async (req, res) => {
        /*
        queries {
           userRole:<userRole>
           id:<adminID>
        }
        JSON
        {
            "adminName":"<adminName>",
            "email":"<email>",
            "password":"<password>"
        }
        */

        let db_connection;

        try {
            // Lock the necessary tables to prevent concurrent writes
            db_connection = await db.promise().getConnection();
            await db_connection.query('LOCK TABLES USERDATA WRITE');

            const currentUserRole = req.query.userRole;
            const adminID = req.query.id;
            const { adminName, email, password } = req.body;

            let result;

            if (currentUserRole != 1) {
                return res.status(403).json({ error: 'Permission denied. Only admins can edit admin profiles.' });
            }

            // Start a transaction
            await db_connection.query('START TRANSACTION');

            try {
                if (password) {
                    const salt = crypto.randomBytes(16).toString('hex');
                    const hashedPassword = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');

                    [result] = await db_connection.query('UPDATE USERDATA SET profName = ?, email = ?, password = ? WHERE profID = ?', [adminName, email, hashedPassword, adminID]);
                } else {
                    [result] = await db_connection.query('UPDATE USERDATA SET profName = ?, email = ? WHERE profID = ?', [adminName, email, adminID]);
                }

                if (result.affectedRows === 1) {
                    // Commit the transaction
                    await db_connection.query('COMMIT');
                    res.json({ message: 'Admin member updated successfully' });
                } else {
                    // Rollback the transaction
                    await db_connection.query('ROLLBACK');
                    res.status(404).json({ error: 'Admin member not found' });
                }
            } catch (error) {
                console.error(error);

                // Rollback the transaction in case of an error
                await db_connection.query('ROLLBACK');

                fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - editAdmin - ${error}\n`);

                res.status(500).json({ error: 'Failed to update admin member' });
            } finally {
                // Unlock the tables
                await db_connection.query('UNLOCK TABLES');
                db_connection.release();
            }
        } catch (error) {
            console.error(error);
            res.status(500).json({ error: 'Failed to acquire database connection' });
        }
    },

    deleteAdmin: async (req, res) => {
        /*
        queries {
           userRole:<userRole>
           id:<adminID>
        }
        JSON
        {
            "adminName":"<adminName>",
            "email":"<email>",
            "password":"<password>"
        }
        */

        let db_connection;

        try {
            // Lock the necessary tables to prevent concurrent writes
            db_connection = await db.promise().getConnection();
            await db_connection.query('LOCK TABLES USERDATA WRITE');

            const currentUserRole = req.query.userRole;
            const adminID = req.query.id;

            if (currentUserRole != 1) {
                return res.status(403).json({ error: 'Permission denied. Only admins can delete admin members.' });
            }

            // Start a transaction
            await db_connection.query('START TRANSACTION');

            try {
                const [result] = await db_connection.query('UPDATE USERDATA SET isActive = ? WHERE profID = ?', [0, adminID]);

                if (result.affectedRows === 1) {
                    // Commit the transaction
                    await db_connection.query('COMMIT');
                    res.json({ message: 'Admin member deleted successfully' });
                } else {
                    // Rollback the transaction
                    await db_connection.query('ROLLBACK');
                    res.status(404).json({ error: 'Admin member not found' });
                }
            } catch (error) {
                console.error(error);

                // Rollback the transaction in case of an error
                await db_connection.query('ROLLBACK');

                fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - deleteAdmin - ${error}\n`);

                res.status(500).json({ error: 'Failed to delete admin member' });
            } finally {
                // Unlock the tables
                await db_connection.query('UNLOCK TABLES');
                db_connection.release();
            }
        } catch (error) {
            console.error(error);
            res.status(500).json({ error: 'Failed to acquire database connection' });
        }
    },

    // -------------------Admin Operations Ends-------------------------

    // -------------------Faculty Operations Starts-------------------------

    addFaculty: async (req, res) => {
        /*
       queries {
          userRole:<userRole>
       }
       JSON
       { 
           "profName":<profName>,
           "email":<email>,
           "password":<password>,
           "courseID":<courseID>
       }
       */

        let db_connection;

        try {
            const currentUserRole = req.query.userRole;

            if (currentUserRole != 1) {
                return res.status(403).json({ error: 'Permission denied. Only admins can add faculty members.' });
            }

            const { profName, email, password, courseID } = req.body;

            const salt = crypto.randomBytes(16).toString('hex');
            const hashedPassword = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');

            // Lock the necessary tables to prevent concurrent writes
            db_connection = await db.promise().getConnection();

            // Start a transaction
            await db_connection.query('START TRANSACTION');

            try {
                const [result] = await db_connection.query('INSERT INTO USERDATA (profName, email, password, userRole, courseID) VALUES (?, ?, ?, ?, ?)', [profName, email, hashedPassword, USER_ROLE.FACULTY, courseID]);

                if (result.affectedRows === 1) {
                    // Commit the transaction
                    await db_connection.query('COMMIT');
                    res.status(201).json({ message: 'Faculty member created successfully' });
                } else {
                    // Rollback the transaction
                    await db_connection.query('ROLLBACK');
                    res.status(500).json({ error: 'Failed to create faculty member' });
                }
            } catch (error) {
                console.error(error);

                // Rollback the transaction in case of an error
                await db_connection.query('ROLLBACK');

                fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - addFaculty - ${error}\n`);

                res.status(500).json({ error: 'Failed to create faculty member' });
            } finally {
                // Unlock the tables
                await db_connection.query('UNLOCK TABLES');
                db_connection.release();
            }
        } catch (error) {
            console.error(error);
            res.status(500).json({ error: 'Failed to acquire database connection' });
        }
    },

    editFaculty: async (req, res) => {
        /*
            queries {
                userRole: <userRole>,
                id: <facultyID>
            }
            JSON
            {
                "profName": <profName>,
                "email": <email>,
                "password": <password>,
                "courseID": <courseID>
            }
        */

        let db_connection;

        try {
            const currentUserRole = req.query.userRole;
            const facultyID = req.query.id;
            const { profName, email, password, courseID } = req.body;

            // Lock the necessary tables to prevent concurrent writes
            db_connection = await db.promise().getConnection();
            await db_connection.query('LOCK TABLES USERDATA WRITE');

            const [faculty] = await db_connection.query('SELECT userRole FROM USERDATA WHERE profID = ?', [facultyID]);

            if (currentUserRole != 1) {
                return res.status(403).json({ error: 'Permission denied. Only admins can edit faculty members.' });
            }

            if (faculty.length === 0) {
                return res.status(404).json({ error: 'Faculty member not found' });
            }

            const facultyUserRole = faculty[0].userRole;

            if (currentUserRole === 0) {
                if (facultyUserRole === 1) {
                    return res.status(403).json({ error: 'Permission denied. Professors cannot edit admin profiles.' });
                } else if (facultyID != req.userID) {
                    return res.status(403).json({ error: 'Permission denied. Professors can only edit their own faculty profile.' });
                }
            }

            let result;

            // Start a transaction
            await db_connection.query('START TRANSACTION');

            try {
                if (password) {
                    const salt = crypto.randomBytes(16).toString('hex');
                    const hashedPassword = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');

                    [result] = await db_connection.query('UPDATE USERDATA SET profName = ?, email = ?, password = ?, courseID = ? WHERE profID = ?', [profName, email, hashedPassword, courseID, facultyID]);
                } else {
                    [result] = await db_connection.query('UPDATE USERDATA SET profName = ?, email = ?, courseID = ? WHERE profID = ?', [profName, email, courseID, facultyID]);
                }

                if (result.affectedRows === 1) {
                    // Commit the transaction
                    await db_connection.query('COMMIT');
                    res.json({ message: 'Faculty member updated successfully' });
                } else {
                    // Rollback the transaction
                    await db_connection.query('ROLLBACK');
                    res.status(404).json({ error: 'Faculty member not found' });
                }
            } catch (error) {
                console.error(error);

                // Rollback the transaction in case of an error
                await db_connection.query('ROLLBACK');

                fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - editFaculty - ${error}\n`);

                res.status(500).json({ error: 'Failed to update faculty member' });
            } finally {
                // Unlock the tables
                await db_connection.query('UNLOCK TABLES');
                db_connection.release();
            }
        } catch (error) {
            console.error(error);
            res.status(500).json({ error: 'Failed to acquire database connection' });
        }
    },

    deleteFaculty: async (req, res) => {
        /*
            queries {
                userRole: <userRole>,
                id: <facultyID>
            }
        */

        let db_connection;

        try {
            const currentUserRole = req.query.userRole;

            if (currentUserRole != 1) {
                return res.status(403).json({ error: 'Permission denied. Only admins can deactivate faculty members.' });
            }

            // Lock the necessary tables to prevent concurrent writes
            db_connection = await db.promise().getConnection();
            await db_connection.query('LOCK TABLES USERDATA WRITE');

            const facultyID = req.query.id;

            let result;

            // Start a transaction
            await db_connection.query('START TRANSACTION');

            try {
                [result] = await db_connection.query('UPDATE USERDATA SET isActive = ? WHERE profID = ?', [0, facultyID]); // Deactivate faculty member

                if (result.affectedRows === 1) {
                    // Commit the transaction
                    await db_connection.query('COMMIT');
                    res.json({ message: 'Faculty member deactivated successfully' });
                } else {
                    // Rollback the transaction
                    await db_connection.query('ROLLBACK');
                    res.status(404).json({ error: 'Faculty member not found' });
                }
            } catch (error) {
                console.error(error);

                // Rollback the transaction in case of an error
                await db_connection.query('ROLLBACK');

                fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - deleteFaculty - ${error}\n`);

                res.status(500).json({ error: 'Failed to deactivate faculty member' });
            } finally {
                // Unlock the tables
                await db_connection.query('UNLOCK TABLES');
                db_connection.release();
            }
        } catch (error) {
            console.error(error);
            res.status(500).json({ error: 'Failed to acquire database connection' });
        }
    },

    allFaculty: async (req, res) => {
        /*
            queries {
                userRole: <userRole>
            }
        */

        let db_connection;

        try {
            const currentUserRole = req.query.userRole;

            if (currentUserRole != 1) {
                return res.status(403).json({ error: 'Permission denied. Only administrators can access faculty members.' });
            }

            // Lock the necessary tables to prevent concurrent writes
            db_connection = await db.promise().getConnection();
            await db_connection.query('LOCK TABLES USERDATA READ');

            const [rows] = await db_connection.query('SELECT * FROM USERDATA WHERE isActive = ? AND userRole = ?', [1, 0]);

            res.json(rows);
        } catch (error) {
            console.error(error);
            fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - allFaculty - ${error}\n`);
            res.status(500).json({ error: 'Failed to fetch faculty members' });
        } finally {
            // Unlock the tables
            if (db_connection) {
                await db_connection.query('UNLOCK TABLES');
                db_connection.release();
            }
        }
    },

    // -------------------Faculty Operations Ends-------------------------

    // -------------------Authentication Starts-------------------------

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
                    return res.status(401).send({ "message": "Your Operations has been deactivated." });
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

    // -------------------Authentication Ends--------------------------

    // -------------------Student Operations Starts------------------------------

    addStudent: async (req, res) => {
        // Add a single student
        /*
            queries {
                userRole: <userRole>
            }
            JSON
            {
                "RollNo": "<RollNo>",
                "StdName": "<StdName>",
                "classID": "<classID>"
            }
        */

        let db_connection;

        try {
            const { RollNo, StdName, classID } = req.body;

            db_connection = await db.promise().getConnection();

            // Validate the presence of required fields

            // Ensure all required fields are defined
            if (!RollNo || !StdName || !classID) {
                return res.status(400).json({ error: 'All fields are required' });
            }

            // Lock the necessary tables to prevent concurrent writes
            await db_connection.query('LOCK TABLES studentData WRITE');

            const query = 'INSERT INTO studentData (RollNo, StdName, classID) VALUES (?, ?, ?)';

            const [result] = await db_connection.query(query, [RollNo, StdName, classID]);

            if (result.affectedRows === 1) {
                // Commit the transaction
                await db_connection.query('COMMIT');
                res.status(201).json({ message: 'Student added successfully' });
            } else {
                // Rollback the transaction
                await db_connection.query('ROLLBACK');
                res.status(500).json({ error: 'Failed to add student' });
            }
        } catch (error) {
            console.error(error);
            // Rollback the transaction in case of an error
            if (db_connection) {
                await db_connection.query('ROLLBACK');
            }

            fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - addStudent - ${error}\n`);

            res.status(500).json({ error: 'Failed to add student' });
        } finally {
            // Unlock the tables
            await db_connection.query('UNLOCK TABLES');
            db_connection.release();
        }
    },

    editStudent: async (req, res) => {
        // Edit student details
        /*
            queries {
                userRole: <userRole>
            }
            JSON
            {
                "RollNo": "<NewRollNo>",
                "StdName": "<NewStdName>",
                "classID": "<NewClassID>"
            }
        */
        let db_connection;

        try {
            const { RollNo, StdName, classID } = req.body;

            db_connection = await db.promise().getConnection();

            // Ensure all required fields are defined
            if (!RollNo || !StdName || !classID) {
                return res.status(400).json({ error: 'All fields are required' });
            }

            // Lock the necessary tables to prevent concurrent writes
            await db_connection.query('LOCK TABLES studentData WRITE');

            const [result] = await db_connection.query('UPDATE studentData SET RollNo = ?, StdName = ?, classID = ? WHERE RollNo = ?', [RollNo, StdName, classID, RollNo]);

            if (result.affectedRows === 1) {
                // Commit the transaction
                await db_connection.query('COMMIT');
                res.json({ message: 'Student updated successfully' });
            } else {
                // Rollback the transaction
                await db_connection.query('ROLLBACK');
                res.status(404).json({ error: 'Student not found' });
            }
        } catch (error) {
            console.error(error);
            // Rollback the transaction in case of an error
            if (db_connection) {
                await db_connection.query('ROLLBACK');
            }
            fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - editStudent - ${error}\n`);
            res.status(500).json({ error: 'Failed to update student' });
        } finally {
            // Unlock the tables
            await db_connection.query('UNLOCK TABLES');
            db_connection.release();
        }
    },

    deleteStudent: async (req, res) => {
        // Deactivate a student
        /*
            queries {
                userRole: <userRole>
            }
            JSON
            {
                "RollNo": "<RollNo>"
            }
        */

        let db_connection;

        try {

            // const stdID = req.params.id;
            const RollNo = req.body.id;
            const currentUserRole = req.query.userRole;

            if (currentUserRole != 0 && currentUserRole != 1) {
                return res.status(403).json({ error: 'Permission denied. Only professors and admins can delete a student.' });
            }

            // Ensure all required fields are defined
            if (!RollNo) {
                return res.status(400).json({ error: 'All fields are required' });
            }

            // Lock the necessary tables to prevent concurrent writes
            await db_connection.query('LOCK TABLES studentData WRITE');

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
        } catch (error) {
            console.error(error);
            // Rollback the transaction in case of an error
            if (db_connection) {
                await db_connection.query('ROLLBACK');
            }
            fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - deleteStudent - ${error}\n`);
            res.status(500).json({ error: 'Failed to deactivate student' });
        } finally {
            // Unlock the tables
            await db_connection.query('UNLOCK TABLES');
            db_connection.release();
        }
    },

    activateStudent: async (req, res) => {
        // Activate a student
        /*
            queries {
                userRole: <userRole>
            }
            JSON
            {
                "RollNo": "<RollNo>"
            }
        */

        let db_connection;

        try {

            // const stdID = req.params.id;
            const RollNo = req.body.id;
            const currentUserRole = req.query.userRole;

            if (currentUserRole != 0 && currentUserRole != 1) {
                return res.status(403).json({ error: 'Permission denied. Only professors and admins can activate a student.' });
            }

            // Ensure all required fields are defined
            if (!RollNo) {
                return res.status(400).json({ error: 'All fields are required' });
            }

            // Lock the necessary tables to prevent concurrent writes
            await db_connection.query('LOCK TABLES studentData WRITE');

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
        } catch (error) {
            console.error(error);
            // Rollback the transaction in case of an error
            if (db_connection) {
                await db_connection.query('ROLLBACK');
            }
            fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - activateStudent - ${error}\n`);
            res.status(500).json({ error: 'Failed to activate student' });
        } finally {
            // Unlock the tables
            await db_connection.query('UNLOCK TABLES');
            db_connection.release();
        }
    },

    allStudents: async (req, res) => {
        // Fetch all students based on batchYear, dept, and section
        /*
            queries {
                batchYear: <batchYear>,
                dept: <dept>,
                section: <section>
            }
        */

        let db_connection;

        try {

            const { batchYear, dept, section } = req.query;

            // Lock the necessary tables to prevent concurrent writes
            await db_connection.query('LOCK TABLES studentData READ, class WRITE');

            if (batchYear !== undefined && dept !== undefined && section !== undefined) {
                const [rows] = await db_connection.query('SELECT s.* FROM studentData s JOIN class c ON s.classID = c.classID WHERE s.isActive = ? AND c.batchYear = ? AND c.Dept = ? AND c.Section = ?', [1, batchYear, dept, section]);
                res.json(rows);
            } else {
                // Handle the case where one of the variables is undefined
                console.error('One of the parameters is undefined');
                res.status(500).json({ error: 'Internal Server Error' });
            }
        } catch (error) {
            console.error(error);
            fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - allStudents - ${error}\n`);
            res.status(500).json({ error: 'Failed to fetch students' });
        } finally {
            // Unlock the tables
            await db_connection.query('UNLOCK TABLES');
            db_connection.release();
        }
    },

    addStudents: async (req, res) => {
        // Add multiple students
        /*
            JSON
            [
                {
                    "RollNo": "<RollNo1>",
                    "StdName": "<StdName1>",
                    "classID": "<classID1>"
                },
                {
                    "RollNo": "<RollNo2>",
                    "StdName": "<StdName2>",
                    "classID": "<classID2>"
                },
                ...
            ]
        */

        let db_connection;

        try {

            const students = req.body;
            const isActive = 1;

            const values = students.map(({ RollNo, StdName, classID, isActive }) => [RollNo, StdName, classID, isActive]);

            db_connection = await db.promise().getConnection();

            const query = 'INSERT INTO studentData (RollNo, StdName, classID, isActive) VALUES ?';

            // Lock the necessary tables to prevent concurrent writes
            await db_connection.query('LOCK TABLES studentData WRITE');

            const [result] = await db_connection.query(query, [values]);

            if (result.affectedRows > 0) {
                // Commit the transaction
                await db_connection.query('COMMIT');
                res.status(201).json({ message: 'Students added successfully' });
            } else {
                // Rollback the transaction
                await db_connection.query('ROLLBACK');
                res.status(500).json({ error: 'Failed to add students' });
            }
        } catch (error) {
            console.error(error);
            // Rollback the transaction in case of an error
            if (db_connection) {
                await db_connection.query('ROLLBACK');
            }
            fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - addStudents - ${error}\n`);
            res.status(500).json({ error: 'Failed to add students' });
        } finally {
            // Unlock the tables
            await db_connection.query('UNLOCK TABLES');
            db_connection.release();
        }
    },

    // -------------------Student Operations Ends------------------------------

    // -------------------Class Operations Starts------------------------------

    createClass: async (req, res) => {
        // Create a class
        /*
            queries {
                userRole: <userRole>
            }
            JSON
            {
                "batchYear": "<batchYear>",
                "Dept": "<Dept>",
                "Section": "<Section>",
                "Semester": "<Semester>",
                "profID": "<profID>"
            }
        */

        let db_connection;

        try {
            db_connection = await db.promise().getConnection();

            // Lock the necessary tables to prevent concurrent writes
            await db_connection.query('LOCK TABLES class WRITE');

            const currentUserRole = req.query.userRole;
            const isActive = 1;

            if (currentUserRole != 0 && currentUserRole != 1) {
                return res.status(403).json({ error: 'Permission denied. Only professors and admins can create classes.' });
            }

            // Start a transaction
            await db_connection.query('START TRANSACTION');

            const { batchYear, Dept, Section, Semester, profID } = req.body;

            const [result] = await db_connection.query('INSERT INTO class (batchYear, Dept, Section, Semester, profID, isActive) VALUES (?, ?, ?, ?, ?, ?)', [batchYear, Dept, Section, Semester, profID, isActive]);

            if (result.affectedRows === 1) {
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
            fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - createClass - ${error}\n`);
            res.status(500).json({ error: 'Failed to create class' });
        } finally {
            // Unlock the tables
            await db_connection.query('UNLOCK TABLES');
            db_connection.release();
        }
    },

    myClasses: async (req, res) => {
        // Fetch classes for a professor
        /*
            queries {
                userRole: <userRole>
                id: <profID>
            }
        */

        let db_connection;

        try {
            db_connection = await db.promise().getConnection();

            // Lock the necessary tables to prevent concurrent writes

            await db_connection.query('LOCK TABLES class READ, userdata READ, course READ');

            const currentUserRole = req.query.userRole;

            if (currentUserRole != 0 && currentUserRole != 1) {
                return res.status(403).json({ error: 'Permission denied. Only professors and admins can access classes.' });
            }

            // Start a transaction
            await db_connection.query('START TRANSACTION');

            const profID = req.query.id;
            console.log(profID)

            // Fetch classes along with course information
            const [rows] = await db_connection.query('SELECT c.Dept, c.Section, c.semester, c.batchYear, co.courseName FROM (class c JOIN userdata on userdata.profID = c.profID ) join course co on co.courseID = userdata.courseID WHERE c.profID = ? AND c.isActive = ?', [profID, 1]);
            console.log(rows)

            // Commit the transaction
            await db_connection.query('COMMIT');

            res.json(rows);
        } catch (error) {
            console.error(error);
            // Rollback the transaction in case of an error
            if (db_connection) {
                await db_connection.query('ROLLBACK');
            }
            fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - myClasses - ${error}\n`);
            res.status(500).json({ error: 'Failed to fetch classes' });
        } finally {
            // Unlock the tables
            await db_connection.query('UNLOCK TABLES');
            db_connection.release();
        }
    },

    deleteClass: async (req, res) => {
        // Delete a class
        /*
            queries {
                userRole: <userRole>
                id: <classID>
            }
        */

        let db_connection;

        try {
            db_connection = await db.promise().getConnection();

            // Lock the necessary tables to prevent concurrent writes
            await db_connection.query('LOCK TABLES class WRITE');

            const currentUserRole = req.query.userRole;
            const classID = req.query.id;

            // console.log(currentUserRole)
            // console.log(classID)

            if (currentUserRole != 0 && currentUserRole != 1) {
                return res.status(403).json({ error: 'Permission denied. Only professors and admins can delete classes.' });
            }

            // Start a transaction
            await db_connection.query('START TRANSACTION');

            const [result] = await db_connection.query('UPDATE class SET isActive = ? WHERE classID = ?', [0, classID]);

            if (result.affectedRows === 1) {
                // Commit the transaction
                await db_connection.query('COMMIT');
                res.json({ message: 'Class deleted successfully' });
            } else {
                // Rollback the transaction
                await db_connection.query('ROLLBACK');
                res.status(404).json({ error: 'Class not found' });
            }
        } catch (error) {
            console.error(error);
            // Rollback the transaction in case of an error
            if (db_connection) {
                await db_connection.query('ROLLBACK');
            }
            fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - deleteClass - ${error}\n`);
            res.status(500).json({ error: 'Failed to delete class' });
        } finally {
            // Unlock the tables
            await db_connection.query('UNLOCK TABLES');
            db_connection.release();
        }
    },

    // -------------------Class Operations Ends------------------------------

    // -------------------Slot Operations Starts------------------------------

    createSlots: async (req, res) => {
        // Create a class slot
        /*
            queries {
                userRole: <userRole>
            }
            JSON
            {
                "classID": "<classID>",
                "periodNo": "<periodNo>"
            }
        */

        let db_connection;

        try {
            db_connection = await db.promise().getConnection();

            // Lock the necessary tables to prevent concurrent writes
            await db_connection.query('LOCK TABLES slots WRITE');

            const currentUserRole = req.query.userRole;

            if (currentUserRole != 0 && currentUserRole != 1) {
                return res.status(403).json({ error: 'Permission denied. Only professors and admins can create class slots.' });
            }

            // Start a transaction
            await db_connection.query('START TRANSACTION');

            const { classID, periodNo } = req.body;

            const [result] = await db_connection.query('INSERT INTO slots (classID, periodNo) VALUES (?, ?)', [classID, periodNo]);

            if (result.affectedRows === 1) {
                // Commit the transaction
                await db_connection.query('COMMIT');
                res.status(201).json({ message: 'Slot created successfully' });
            } else {
                // Rollback the transaction
                await db_connection.query('ROLLBACK');
                res.status(500).json({ error: 'Failed to create slot' });
            }
        } catch (error) {
            console.error(error);
            // Rollback the transaction in case of an error
            if (db_connection) {
                await db_connection.query('ROLLBACK');
            }
            fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - createSlots - ${error}\n`);
            res.status(500).json({ error: 'Failed to create slot' });
        } finally {
            // Unlock the tables
            await db_connection.query('UNLOCK TABLES');
            db_connection.release();
        }
    },

    deleteSlot: async (req, res) => {
        // Delete a class slot
        /*
            queries {
                userRole: <userRole>
                id: <slotID>
            }
        */

        let db_connection;

        try {
            db_connection = await db.promise().getConnection();

            // Lock the necessary tables to prevent concurrent writes
            await db_connection.query('LOCK TABLES slots WRITE');

            const currentUserRole = req.query.userRole;
            const slotID = req.query.id;

            if (currentUserRole != 0 && currentUserRole != 1) {
                return res.status(403).json({ error: 'Permission denied. Only professors and admins can delete slots.' });
            }

            // Start a transaction
            await db_connection.query('START TRANSACTION');

            const [result] = await db_connection.query('DELETE FROM slots WHERE slotID = ?', [slotID]);

            if (result.affectedRows === 1) {
                // Commit the transaction
                await db_connection.query('COMMIT');
                res.json({ message: 'Slot deleted successfully' });
            } else {
                // Rollback the transaction
                await db_connection.query('ROLLBACK');
                res.status(404).json({ error: 'Slot not found' });
            }
        } catch (error) {
            console.error(error);
            // Rollback the transaction in case of an error
            if (db_connection) {
                await db_connection.query('ROLLBACK');
            }
            fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - deleteSlot - ${error}\n`);
            res.status(500).json({ error: 'Failed to delete slot' });
        } finally {
            // Unlock the tables
            await db_connection.query('UNLOCK TABLES');
            db_connection.release();
        }
    }

    // -------------------Slot Operations Ends------------------------------
};