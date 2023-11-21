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

    // -----------------------User Operations Start---------------------------

    getAllUsers: [webTokenValidator, async (req, res) => {
        /*
        Headers: {
            "Authorization": "Bearer <SECRET_TOKEN>"
        }
        JSON
        {
            "email": "email",
            "reqRole": "reqRole"
        }
        */

        let db_connection = await db.promise().getConnection();

        if (
            req.body.email === null ||
            req.body.email === undefined ||
            req.body.email === ""
        ) {
            db_connection.release();
            return res.status(400).send({ "message": "Invalid email!" });
        } else {
            try {
                // Lock necessary tables before executing any query
                await db_connection.query('LOCK TABLES USERDATA READ');

                // Check if the user making the request is an admin
                const [admin] = await db_connection.query(
                    `SELECT * from USERDATA WHERE email = ? AND userRole = ?`,
                    [req.body.email, "1"]
                );

                await db_connection.query('UNLOCK TABLES');

                if (admin.length === 0) {
                    db_connection.release();
                    return res.status(401).send({ "message": "Access Restricted!" });
                }

                await db_connection.query('LOCK TABLES USERDATA u READ, COURSE c READ');

                let users;
                if (req.body.reqRole === "0") {
                    // Fetch all faculty members
                    [users] = await db_connection.query(
                        `SELECT u.profName, u.email, c.courseName FROM USERDATA u LEFT JOIN COURSE c ON u.courseID = c.courseID WHERE u.userRole = ? AND u.isActive = ?`, ["0", "1"]
                    );
                } else if (req.body.reqRole === "1") {
                    // Fetch all administrators
                    [users] = await db_connection.query(
                        `SELECT u.profName, u.email, c.courseName FROM USERDATA u LEFT JOIN COURSE c ON u.courseID = c.courseID WHERE u.userRole = ? AND u.isActive = ?`, ["1", "1"]
                    );
                } else {
                    await db_connection.query('UNLOCK TABLES');
                    db_connection.release();
                    return res.status(400).send({ "message": "Invalid request role!" });
                }

                await db_connection.query('UNLOCK TABLES');

                if (users.length === 0) {
                    db_connection.release();
                    return res.status(200).send({ "message": "No users found!", "users": [] });
                }

                return res.status(200).send({ "message": "Users fetched!", "users": users });
            } catch (err) {
                console.log(err);
                const time = new Date();
                fs.appendFileSync(
                    "logs/errorLogs.txt",
                    `${time.toISOString()} - getAllUsers - ${err}\n`
                );
                return res.status(500).send({ "message": "Internal Server Error." });
            } finally {
                // Always unlock the tables in the finally block
                await db_connection.query('UNLOCK TABLES');
                db_connection.release();
            }
        }
    },
    ],

    editUser: [webTokenValidator, async (req, res) => {
        /*
        Headers: {
            "Authorization": "Bearer <SECRET_TOKEN>"
        }
        queries {
            currentUserEmail: <currentUserEmail>,
        }
        JSON
        {
            "profName": <profName>,
            "email": <email>,
            "password": <password>,
            "courseName": <courseName>
        }
        */

        let db_connection;

        try {
            const currentUserEmail = req.query.currentUserEmail;
            const userEmail = req.body.email;
            const { profName, email, password, courseName } = req.body;

            // Lock the necessary tables to prevent concurrent writes
            db_connection = await db.promise().getConnection();
            await db_connection.query('LOCK TABLES USERDATA WRITE, COURSE READ');

            const [currentUser] = await db_connection.query('SELECT userRole FROM USERDATA WHERE email = ?', [currentUserEmail]);

            if (currentUser.length === 0) {
                await db_connection.query(`UNLOCK TABLES`);
                return res.status(404).json({ error: 'Current user not found' });
            }

            const currentUserRole = currentUser[0].userRole;

            // Start a transaction
            await db_connection.query('START TRANSACTION');

            try {
                let result;

                if (currentUserRole === "1") {
                    // Admin editing user
                    const [course] = await db_connection.query('SELECT courseID FROM COURSE WHERE courseName = ?', [courseName]);

                    if (course.length === 0) {
                        // If the course does not exist, you may want to handle this case appropriately.
                        await db_connection.query('ROLLBACK');
                        return res.status(404).json({ error: 'Course not found' });
                    }

                    const courseID = course[0].courseID;

                    const [professor] = await db_connection.execute(`SELECT * FROM USERDATA WHERE email = ? AND isActive = 1`, [userEmail]);

                    if (professor.length === 0) {
                        // Handle the case where no active professor is found with the given email
                        await db_connection.query('ROLLBACK');
                        return res.status(404).json({ error: 'Active Professor not found' });
                    }

                    const profID = professor[0].profID;

                    if (password) {
                        const salt = crypto.randomBytes(16).toString('hex');
                        const hashedPassword = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');

                        [result] = await db_connection.query('UPDATE USERDATA SET profName = ?, email = ?, password = ?, courseID = ? WHERE profID = ?', [profName, userEmail, hashedPassword, courseID, profID]);
                    } else {
                        [result] = await db_connection.query('UPDATE USERDATA SET profName = ?, email = ?, courseID = ? WHERE profID = ?', [profName, userEmail, courseID, profID]);
                    }
                } else if (currentUserRole === "0") {
                    // Faculty editing their own profile
                    if (userEmail != currentUserEmail) {
                        // Faculty can only edit their own profile
                        return res.status(403).json({ error: 'Permission denied. Faculty can only edit their own profile.' });
                    }

                    const [course] = await db_connection.query('SELECT courseID FROM COURSE WHERE courseName = ?', [courseName]);

                    if (course.length === 0) {
                        // If the course does not exist, you may want to handle this case appropriately.
                        await db_connection.query('ROLLBACK');
                        return res.status(404).json({ error: 'Course not found' });
                    }

                    const courseID = course[0].courseID;

                    if (password) {
                        const salt = crypto.randomBytes(16).toString('hex');
                        const hashedPassword = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');

                        [result] = await db_connection.query('UPDATE USERDATA SET profName = ?, email = ?, password = ?, courseID = ? WHERE email = ? AND isActive = 1', [profName, email, hashedPassword, courseID, currentUserEmail]);
                    } else {
                        [result] = await db_connection.query('UPDATE USERDATA SET profName = ?, email = ?, courseID = ? WHERE email = ? AND isActive = 1', [profName, email, courseID, currentUserEmail]);
                    }
                } else {
                    // Invalid userRole
                    return res.status(400).json({ error: 'Invalid user role!' });
                }

                if (result.affectedRows === 1) {
                    // Commit the transaction
                    await db_connection.query('COMMIT');
                    res.json({ message: 'User profile updated successfully' });
                } else {
                    // Rollback the transaction
                    await db_connection.query('ROLLBACK');
                    res.status(404).json({ error: 'User not found' });
                }
            } catch (error) {
                console.error(error);

                // Rollback the transaction in case of an error
                await db_connection.query('ROLLBACK');

                const time = new Date();
                fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - editUser - ${error}\n`);

                res.status(500).json({ error: 'Failed to update user profile' });
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
    ],

    deleteAdmin: [webTokenValidator, async (req, res) => {
        /*
        Headers: {
            "Authorization": "Bearer <SECRET_TOKEN>"
        }
    
        JSON
        {
            "userEmail": "<userEmail>",
            "currentUserEmail": "<currentUserEmail>",
            "adminProfName": "<profName>"
        }
        */

        if (
            req.body.userEmail === null ||
            req.body.userEmail === undefined ||
            req.body.userEmail === "" ||
            !validator.isEmail(req.body.userEmail) ||
            req.body.currentUserEmail === null ||
            req.body.currentUserEmail === undefined ||
            req.body.currentUserEmail === "" ||
            !validator.isEmail(req.body.currentUserEmail)
        ) {
            return res.status(400).send({ "message": "Access Restricted!" });
        }

        if (
            req.body.adminProfName === null ||
            req.body.adminProfName === undefined ||
            req.body.adminProfName === ""
        ) {
            return res.status(400).send({ "message": "Missing details." });
        }

        let db_connection = await db.promise().getConnection();

        try {
            await db_connection.query(`LOCK TABLES USERDATA WRITE`);

            // Check if the current user is an admin
            let [admin] = await db_connection.query(
                `SELECT * FROM USERDATA WHERE email = ? AND userRole = ?`,
                [req.body.currentUserEmail, "1"]
            );

            if (admin.length === 0) {
                await db_connection.query(`UNLOCK TABLES`);
                return res.status(401).send({ "message": "Access Restricted!" });
            }

            // Check if admin exists
            let [adminToDelete] = await db_connection.query(
                `SELECT profID, profName, email, userRole FROM USERDATA WHERE profName = ? AND isActive = ? AND userRole = ?`,
                [req.body.adminProfName, "2", "1"]
            );

            if (adminToDelete.length === 0) {
                await db_connection.query(`UNLOCK TABLES`);
                return res.status(400).send({ "message": "Admin doesn't exist!" });
            }

            const adminID = adminToDelete[0].profID;

            // Update the admin's status to inactive
            await db_connection.query(
                `UPDATE USERDATA SET isActive = ? WHERE profID = ?`,
                [0, adminID]
            );

            await db_connection.query(`UNLOCK TABLES`);

            // Notify via email
            mailer.accountDeactivated(
                adminToDelete[0].profName,
                adminToDelete[0].email,
            );

            return res.status(200).send({ "message": "Admin member deleted successfully!" });
        } catch (err) {
            console.log(err);
            const time = new Date();
            fs.appendFileSync(
                "logs/errorLogs.txt",
                `${time.toISOString()} - deleteAdmin - ${err}\n`
            );
            return res.status(500).send({ "message": "Internal Server Error." });
        }
    },
    ],

    deleteFaculty: [webTokenValidator, async (req, res) => {
        /*
        Headers: {
            "Authorization": "Bearer <SECRET_TOKEN>"
        }
    
        JSON
        {
            "userEmail": "<userEmail>",
            "currentUserEmail": "<currentUserEmail>",
            "facultyProfName": "<profName>"
        }
        */

        if (
            req.body.userEmail === null ||
            req.body.userEmail === undefined ||
            req.body.userEmail === "" ||
            !validator.isEmail(req.body.userEmail) ||
            req.body.currentUserEmail === null ||
            req.body.currentUserEmail === undefined ||
            req.body.currentUserEmail === "" ||
            !validator.isEmail(req.body.currentUserEmail)
        ) {
            return res.status(400).send({ "message": "Access Restricted!" });
        }

        if (
            req.body.facultyProfName === null ||
            req.body.facultyProfName === undefined ||
            req.body.facultyProfName === ""
        ) {
            return res.status(400).send({ "message": "Missing details." });
        }

        let db_connection = await db.promise().getConnection();

        try {
            await db_connection.query(`LOCK TABLES USERDATA WRITE`);

            // Check if the current user is an admin
            let [admin] = await db_connection.query(
                `SELECT * FROM USERDATA WHERE email = ? AND userRole = ?`,
                [req.body.currentUserEmail, "1"]
            );

            if (admin.length === 0) {
                await db_connection.query(`UNLOCK TABLES`);
                return res.status(401).send({ "message": "Access Restricted!" });
            }

            // Check if faculty exists
            let [faculty] = await db_connection.query(
                `SELECT profID, profName, email, userRole FROM USERDATA WHERE profName = ? AND isActive = ? AND userRole = ?`,
                [req.body.facultyProfName, "1", "0"]
            );

            if (faculty.length === 0) {
                await db_connection.query(`UNLOCK TABLES`);
                return res.status(400).send({ "message": "Faculty doesn't exist!" });
            }

            const facultyID = faculty[0].profID;

            // Update the faculty's status to inactive
            await db_connection.query(
                `UPDATE USERDATA SET isActive = ? WHERE profID = ?`,
                [0, facultyID]
            );

            await db_connection.query(`UNLOCK TABLES`);

            // Notify via email
            mailer.accountDeactivated(
                faculty[0].profName,
                faculty[0].email,
            );

            return res.status(200).send({ "message": "Faculty member deleted successfully!" });
        } catch (err) {
            console.log(err);
            const time = new Date();
            fs.appendFileSync(
                "logs/errorLogs.txt",
                `${time.toISOString()} - deleteFaculty - ${err}\n`
            );
            return res.status(500).send({ "message": "Internal Server Error." });
        }
    },
    ],

    addFaculty: [webTokenValidator, async (req, res) => {
        let db_connection;

        try {
            const { userName, newUserEmail, courseName } = req.body;

            if (
                req.body.newUserEmail === null ||
                req.body.newUserEmail === undefined ||
                req.body.newUserEmail === "" ||
                !validator.isEmail(req.body.newUserEmail) ||
                req.body.userName === null ||
                req.body.userName === undefined ||
                req.body.userName === "" ||
                req.body.courseName === null ||
                req.body.courseName === undefined ||
                req.body.courseName === ""
            ) {
                return res.status(400).send({ "message": "Missing details." });
            }

            db_connection = await db.promise().getConnection();

            // Ensure all required fields are defined
            if (!newUserEmail || !userName || !courseName) {
                return res.status(400).json({ error: 'All fields are required' });
            }

            // Lock the necessary tables to prevent concurrent writes
            await db_connection.query('LOCK TABLES USERDATA WRITE, course READ');

            // Fetch courseID based on courseName
            const [courseResult] = await db_connection.query(
                'SELECT courseID FROM course WHERE courseName = ?',
                [courseName]
            );

            if (courseResult.length === 0) {
                await db_connection.query('UNLOCK TABLES');
                return res.status(400).send({ "message": "Course not found!" });
            }

            // Your faculty-specific logic here
            // For example, you may want to perform additional checks or validations

            // Check if the user is already registered
            let [existingUser] = await db_connection.query(
                'SELECT * from USERDATA WHERE email = ?',
                [newUserEmail]
            );

            if (existingUser.length > 0) {
                await db_connection.query('UNLOCK TABLES');
                return res.status(400).send({ "message": "User already registered!" });
            }

            // Generate a random password for the faculty.
            const memberPassword = passwordGenerator.randomPassword({
                length: 8,
                characters: [passwordGenerator.lower, passwordGenerator.upper, passwordGenerator.digits]
            });

            const salt = crypto.randomBytes(16).toString('hex');
            const hashedPassword = crypto.pbkdf2Sync(memberPassword, salt, 10000, 64, 'sha512').toString('hex');

            // Email the password to the user.
            mailer.officialCreated(userName, newUserEmail, hashedPassword);

            // Insert the user into the USERDATA table with faculty role ('0' for faculty)
            await db_connection.query(
                'INSERT INTO USERDATA (profName, email, password, userRole, courseID, isActive) VALUES (?, ?, ?, ?, ?, "2")',
                [userName, newUserEmail, hashedPassword, '0', courseResult[0].courseID]
            );

            // Unlock the tables
            await db_connection.query('UNLOCK TABLES');

            // Return success response
            return res.status(200).send({ "message": "Faculty registered!" });
        } catch (err) {
            console.error(err);
            const time = new Date();
            fs.appendFileSync(
                'logs/errorLogs.txt',
                `${time.toISOString()} - addFaculty - ${err}\n`
            );
            return res.status(500).send({ "message": "Internal Server Error." });
        } finally {
            // Unlock the tables and release the database connection
            await db_connection.query('UNLOCK TABLES');
            db_connection.release();
        }
    },
    ],

    addAdmin: [
        webTokenValidator,
        async (req, res) => {
            let db_connection;

            try {
                const { userName, newUserEmail, courseName } = req.body;

                if (
                    req.body.newUserEmail === null ||
                    req.body.newUserEmail === undefined ||
                    req.body.newUserEmail === "" ||
                    !validator.isEmail(req.body.newUserEmail) ||
                    req.body.userName === null ||
                    req.body.userName === undefined ||
                    req.body.userName === "" ||
                    req.body.courseName === null ||
                    req.body.courseName === undefined ||
                    req.body.courseName === ""
                ) {
                    return res.status(400).send({ "message": "Missing details." });
                }

                db_connection = await db.promise().getConnection();

                // Ensure all required fields are defined
                if (!newUserEmail || !userName || !courseName) {
                    return res.status(400).json({ error: 'All fields are required' });
                }

                // Lock the necessary tables to prevent concurrent writes
                await db_connection.query('LOCK TABLES USERDATA WRITE, course READ');

                // Fetch courseID based on courseName
                const [courseResult] = await db_connection.query(
                    'SELECT courseID FROM course WHERE courseName = ?',
                    [courseName]
                );

                if (courseResult.length === 0) {
                    await db_connection.query('UNLOCK TABLES');
                    return res.status(400).send({ "message": "Course not found!" });
                }

                // Check if the user is actually an admin
                // let [admin] = await db_connection.query(
                //     'SELECT * from USERDATA WHERE email = ? AND userRole = ?',
                //     [newUserEmail, '1']
                // );

                // if (admin.length === 0) {
                //     await db_connection.query('UNLOCK TABLES');
                //     return res.status(401).send({ "message": "Access Restricted!" });
                // }

                // Check if the user is already registered
                let [existingUser] = await db_connection.query(
                    'SELECT * from USERDATA WHERE email = ?',
                    [newUserEmail]
                );

                if (existingUser.length > 0) {
                    await db_connection.query('UNLOCK TABLES');
                    return res.status(400).send({ "message": "User already registered!" });
                }

                // Generate a random password for the manager.
                const memberPassword = passwordGenerator.randomPassword({
                    length: 8,
                    characters: [passwordGenerator.lower, passwordGenerator.upper, passwordGenerator.digits]
                });

                const salt = crypto.randomBytes(16).toString('hex');
                const hashedPassword = crypto.pbkdf2Sync(memberPassword, salt, 10000, 64, 'sha512').toString('hex');

                // Email the password to the user.
                mailer.officialCreated(userName, newUserEmail, hashedPassword);

                // Insert the user into the USERDATA table
                await db_connection.query(
                    'INSERT INTO USERDATA (profName, email, password, userRole, courseID, isActive) VALUES (?, ?, ?, ?, ?, "2")',
                    [userName, newUserEmail, hashedPassword, '1', courseResult[0].courseID]
                );

                // Unlock the tables
                await db_connection.query('UNLOCK TABLES');

                // Return success response
                return res.status(200).send({ "message": "Admin registered!" });
            } catch (err) {
                console.error(err);
                const time = new Date();
                fs.appendFileSync(
                    'logs/errorLogs.txt',
                    `${time.toISOString()} - addAdmin - ${err}\n`
                );
                return res.status(500).send({ "message": "Internal Server Error." });
            } finally {
                // Unlock the tables and release the database connection
                await db_connection.query('UNLOCK TABLES');
                db_connection.release();
            }
        },
    ],

    // -----------------------User Operations End---------------------------

    // -----------------------Authentication Operations Start-----------------

    userLogin: async (req, res) => {
        /*
        JSON
        {
            "email": "<email>",
            "password": "<password>"
        }
        */
        if (
            req.body.email === null ||
            req.body.email === undefined ||
            req.body.email === '' ||
            !validator.isEmail(req.body.email) ||
            req.body.password === null ||
            req.body.password === undefined ||
            req.body.password === ''
        ) {
            return res.status(400).send({ message: 'Missing details.' });
        }

        let db_connection = await db.promise().getConnection();

        try {
            await db_connection.query(`LOCK TABLES USERDATA READ`);

            let [user] = await db_connection.query(`SELECT * FROM USERDATA WHERE email = ? AND password = ?`, [req.body.email, req.body.password]);

            if (user.length > 0) {

                if (user[0].isActive === "0") {
                    await db_connection.query(`UNLOCK TABLES`);
                    return res.status(401).send({ "message": "Your Account has been deactivated. Check your mail for further instructions." });
                }
                console.log(user)
                if (user[0].isActive == "2") {
                    // send otp
                    const otp = generateOTP();

                    await db_connection.query(`LOCK TABLES USERREGISTER WRITE`);

                    let [user_2] = await db_connection.query(`SELECT * FROM USERREGISTER WHERE email = ?`, [req.body.email]);

                    if (user_2.length === 0) {
                        await db_connection.query(`INSERT INTO USERREGISTER (Email, otp, createdAt) VALUES (?, ?, ?)`, [req.body.email, otp, new Date()]);
                    } else {
                        await db_connection.query(`UPDATE USERREGISTER SET otp = ?, createdAt = ? WHERE email = ?`, [otp, new Date(), req.body.email]);
                    }

                    // send mail
                    mailer.loginOTP(user[0].profName, otp, user[0].email);

                    const secret_token = await otpTokenGenerator({
                        "email": req.body.email,
                        "userRole": user[0].userRole,
                    });

                    console.log(req.body.email)
                    console.log(user[0].userRole)

                    await db_connection.query(`UNLOCK TABLES`);

                    console.log(secret_token)
                    return res.status(201).send({
                        "message": "First time login! OTP sent to email.",
                        "SECRET_TOKEN": secret_token,
                        "email": user[0].email,
                        "profName": user[0].profName,
                    });


                }
                else if (user[0].isActive === "1") {
                    const secret_token = await webTokenGenerator({
                        "email": req.body.email,
                        "userRole": user[0].userRole,
                    });

                    await db_connection.query(`UNLOCK TABLES`);

                    return res.status(200).send({
                        "message": "User logged in!",
                        "SECRET_TOKEN": secret_token,
                        "email": user[0].email,
                        "profName": user[0].profName,
                        "userRole": user[0].userRole,
                        "profId": user[0].id,
                        "isActive": user[0].isActive,
                    });
                }
                else {
                    await db_connection.query(`UNLOCK TABLES`);
                    return res.status(401).send({ "message": "Access Restricted." });
                }



            }

            await db_connection.query(`UNLOCK TABLES`);

            return res.status(400).send({ "message": "Invalid email or password!" });

        } catch (err) {
            console.log(err);
            const time = new Date();
            fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - userLogin - ${err}\n`);
            return res.status(500).send({ "message": "Internal Server Error." });
        } finally {
            await db_connection.query(`UNLOCK TABLES`);
            db_connection.release();
        }
    },

    loginVerify: [
        /*
        JSON
        {
            "otp":"<otp>",
            "newPassword": "<password>"
        }
        */
        otpTokenValidator,
        async (req, res) => {

            console.log(req.email)
            console.log(req.body)

            if (
                req.body.otp === null ||
                req.body.otp === undefined ||
                req.body.otp === '' ||
                req.body.password === null ||
                req.body.password === undefined ||
                req.body.password === '' ||
                req.email === null ||
                req.email === undefined ||
                req.email === ''
            ) {
                return res.status(400).send({ message: 'Missing details.' });
            }

            let db_connection = await db.promise().getConnection();

            try {
                await db_connection.query(`LOCK TABLES USERREGISTER WRITE, USERDATA WRITE`);

                let [check_1] = await db_connection.query(`DELETE FROM USERREGISTER WHERE email = ? AND otp = ?`, [req.email, req.body.otp]);

                if (check_1.affectedRows === 0) {
                    await db_connection.query(`UNLOCK TABLES`);
                    return res.status(400).send({ "message": "Invalid OTP." });
                }

                let [user] = await db_connection.query(`SELECT * FROM USERDATA WHERE email = ?`, [req.email]);

                if (user.length === 0) {
                    await db_connection.query(`UNLOCK TABLES`);
                    return res.status(400).send({ "message": "Invalid Email." }); //bad req 400
                }

                await db_connection.query(`UPDATE USERDATA SET password = ? WHERE email = ?`, [req.body.password, req.email]);

                await db_connection.query(`UNLOCK TABLES`);

                const secret_token = await webTokenGenerator({
                    "email": req.body.email,
                    "userRole": user[0].userRole,
                });

                return res.status(201).send({
                    "message": "User Verified and Password updated",
                    "SECRET_TOKEN": secret_token,
                    "email": user[0].email,
                    "profName": user[0].profName,
                });

            } catch (err) {
                console.log(err);
                const time = new Date();
                fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - loginVerify - ${err}\n`);
                return res.status(500).send({ "message": "Internal Server Error." });
            } finally {
                await db_connection.query(`UNLOCK TABLES`);
                db_connection.release();
            }
        }
    ],

    forgotPassword: async (req, res) => {
        /*
        JSON
        {
            "email": "<email_id>"
        }
        */
        if (
            req.body.email === null ||
            req.body.email === undefined ||
            req.body.email === "" ||
            !validator.isEmail(req.body.email)
        ) {
            return res.status(400).send({ message: "Missing details." });
        }

        let db_connection = await db.promise().getConnection();

        try {
            await db_connection.query(`LOCK TABLES USERDATA READ`);
            let [professor] = await db_connection.query(
                `SELECT profName, isActive FROM USERDATA WHERE email = ?`,
                [req.body.email]
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
                [req.body.email]
            );

            const otp = generateOTP();

            if (professor_2.length === 0) {
                await db_connection.query(
                    `INSERT INTO USERREGISTER (email, otp, createdAt) VALUES (?, ?, ?)`,
                    [req.body.email, otp, new Date()]
                );
            } else {
                await db_connection.query(
                    `UPDATE USERREGISTER SET otp = ?, createdAt = ? WHERE email = ?`,
                    [otp, new Date(), req.body.email]
                );
            }
            await db_connection.query(`UNLOCK TABLES`);

            let [userRole] = await db_connection.query(
                `SELECT userRole FROM USERDATA WHERE email = ?`,
                [req.body.email]
            );

            const secret_token = await otpTokenGenerator({
                email: req.body.email,
                userRole: userRole,
            });

            mailer.reset_PW_OTP([professor].profName, otp, req.body.email);

            return res.status(200).send({
                message: "OTP sent to email.",
                SECRET_TOKEN: secret_token,
                email: req.body.email,
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

    resetVerify: [otpTokenValidator, async (req, res) => {
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

            const secret_token = await webTokenGenerator({
                "email": professor[0].profEmail,
                "userRole": professor[0].userRole,
            });

            return res.status(200).send({
                "message": "OTP verification successful.",
                "SECRET_TOKEN": secret_token,
                "email": professor[0].profEmail,
                "profName": professor[0].profName,
            });

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
    },],

    resetPassword: [webTokenValidator, async (req, res) => {
        /*
        JSON
        {
            "email": "<email_id>",
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

            const secret_token = await webTokenGenerator({
                "email": professor[0].profEmail,
                "userRole": professor[0].userRole,
            });

            return res.status(200).send({
                "message": "Password reset successful.",
                "SECRET_TOKEN": secret_token,
                "email": professor[0].profEmail,
                "profName": professor[0].profName,
            });

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
    },],

    // -----------------------Authentication Operations End-----------------

    // -----------------------Student Operations Start---------------------------

    addStudent: [webTokenValidator, async (req, res) => {
        /*
            JSON
            {
                "currentUserEmail": "<currentUserEmail>",
                "RollNo": "<RollNo>",
                "StdName": "<StdName>",
                "batchYear": "<batchYear>",
                "Dept": "<Dept>",
                "Section": "<Section>",
                "Semester": "<Semester>"
            }
        */

        let db_connection;

        try {
            const { currentUserEmail, RollNo, StdName, batchYear, Dept, Section, Semester } = req.body;

            db_connection = await db.promise().getConnection();

            // Ensure all required fields are defined
            if (!currentUserEmail || !RollNo || !StdName || !batchYear || !Dept || !Section || !Semester) {
                return res.status(400).json({ error: 'All fields are required' });
            }

            // Validate the RollNo format
            const pattern = /^[A-Z]{2}\.[A-Z]{2}\.[A-Z]{1}[0-9]{1}[A-Z]{3}[0-9]{5}$/;
            if (!pattern.test(RollNo)) {
                return res.status(400).json({ error: 'Invalid roll number format' });
            }

            // Lock the necessary tables to prevent concurrent writes
            await db_connection.query('LOCK TABLES studentData WRITE, USERDATA READ, class WRITE, course READ');

            // Fetch userRole based on currentUserEmail
            const [currentUser] = await db_connection.query('SELECT userRole FROM USERDATA WHERE email = ?', [currentUserEmail]);

            if (currentUser.length === 0) {
                await db_connection.query('UNLOCK TABLES');
                return res.status(404).json({ error: 'Current user not found' });
            }

            const currentUserRole = currentUser[0].userRole;

            // Continue with your logic based on currentUserRole...

            // Fetch courseID based on Dept
            const [courseResult] = await db_connection.query('SELECT courseID FROM course WHERE courseName = ?', [Dept]);

            if (courseResult.length === 0) {
                await db_connection.query('UNLOCK TABLES');
                return res.status(400).send({ "message": "Course not found!" });
            }

            // Insert data into class table
            const [classResult] = await db_connection.query(
                'INSERT INTO class (batchYear, Dept, Section, courseID, Semester) VALUES (?, ?, ?, ?, ?)',
                [batchYear, Dept, Section, courseResult[0].courseID, Semester]
            );

            // Insert data into studentData table
            const [result] = await db_connection.query(
                'INSERT INTO studentData (RollNo, StdName, classID) VALUES (?, ?, ?)',
                [RollNo, StdName, classResult.insertId]
            );

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

            const time = new Date();
            fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - addStudent - ${error}\n`);

            res.status(500).json({ error: 'Failed to add student' });
        } finally {
            // Unlock the tables and release the database connection
            await db_connection.query('UNLOCK TABLES');
            db_connection.release();
        }
    },
    ],

    editStudent: [webTokenValidator, async (req, res) => {
        // Edit student details
        /*
            queries {
                currentUserEmail: <currentUserEmail>
            }
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
            const currentUserEmail = req.query.currentUserEmail;

            db_connection = await db.promise().getConnection();

            // Ensure all required fields are defined
            if (!RollNo || !StdName || !batchYear || !Section || !Dept || !Semester || !currentUserEmail) {
                return res.status(400).json({ error: 'All fields are required' });
            }

            const pattern = /^[A-Z]{2}\.[A-Z]{2}\.[A-Z]{1}[0-9]{1}[A-Z]{3}[0-9]{5}$/;
            if (pattern.test(RollNo)) {
                // Roll number is in the correct format
            } else {
                // Roll number format is incorrect
                return res.status(400).json({ error: 'Invalid roll number format' });
            }

            // Lock the necessary tables to prevent concurrent writes
            await db_connection.query('LOCK TABLES studentData WRITE, USERDATA READ, class READ');

            // Fetch userRole based on currentUserEmail
            const [currentUser] = await db_connection.query('SELECT userRole FROM USERDATA WHERE email = ?', [currentUserEmail]);

            if (currentUser.length === 0) {
                await db_connection.query('UNLOCK TABLES');
                return res.status(404).json({ error: 'Current user not found' });
            }

            const currentUserRole = currentUser[0].userRole;

            // Get classID based on batchYear, Section, Dept, and Semester
            const [classResult] = await db_connection.query('SELECT classID FROM class WHERE batchYear = ? AND Section = ? AND Dept = ? AND Semester = ?', [batchYear, Section, Dept, Semester]);

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
            queries {
                currentUserEmail: <currentUserEmail>
            }
            JSON
            {
                "RollNo": "<RollNo>"
            }
        */

        let db_connection;

        try {
            const RollNo = req.body.RollNo;
            const currentUserEmail = req.query.currentUserEmail;

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
            queries {
                currentUserEmail: <currentUserEmail>
            }
            JSON
            {
                "RollNo": "<RollNo>"
            }
        */

        let db_connection;

        try {
            const RollNo = req.body.RollNo;
            const currentUserEmail = req.query.currentUserEmail;

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
        // Fetch all students based on batchYear, dept, section, and semester
        /*
            JSON
            {
                "batchYear": "<batchYear>",
                "dept": "<dept>",
                "section": "<section>",
                "semester": "<semester>"
            }
        */

        let db_connection;

        try {
            const { batchYear, dept, section, semester } = req.body;

            db_connection = await db.promise().getConnection();

            // Lock the necessary tables to prevent concurrent writes
            await db_connection.query('LOCK TABLES studentData s READ, class c READ');

            if (batchYear !== undefined && dept !== undefined && section !== undefined && semester !== undefined) {
                const [rows] = await db_connection.query('SELECT s.* FROM studentData s JOIN class c ON s.classID = c.classID WHERE s.isActive = ? AND c.batchYear = ? AND c.Dept = ? AND c.Section = ? AND c.Semester = ?', [1, batchYear, dept, section, semester]);
                res.json(rows);
            } else {
                // Handle the case where one of the parameters is undefined
                console.error('One of the parameters is undefined');
                res.status(400).json({ error: 'All parameters are required' });
            }
        } catch (error) {
            console.error(error);
            const time = new Date();
            fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - allStudents - ${error}\n`);
            res.status(500).json({ error: 'Failed to fetch students' });
        } finally {
            // Unlock the tables
            await db_connection.query('UNLOCK TABLES');
            db_connection.release();
        }
    }],

    addStudents: [webTokenValidator, async (req, res) => {
        /*
        query
        {
            currentUserEmail: <currentUserEmail>
        }
        JSON
        [
            {
                "RollNo": "<RollNo1>",
                "StdName": "<StdName1>",
                "batchYear": "<batchYear1>",
                "Dept": "<Dept1>",
                "Section": "<Section1>",
                "courseName": "<courseName1>",
                "Semester": "<Semester1>"
            },
            {
                "RollNo": "<RollNo2>",
                "StdName": "<StdName2>",
                "batchYear": "<batchYear2>",
                "Dept": "<Dept2>",
                "Section": "<Section2>",
                "courseName": "<courseName2>",
                "Semester": "<Semester2>"
            },
            ...
        ]
        */

        let db_connection;

        try {
            const students = req.body;

            db_connection = await db.promise().getConnection();

            // Begin a transaction
            await db_connection.beginTransaction();

            for (const student of students) {
                const currentUserEmail = req.query.currentUserEmail;
                const { RollNo, StdName, batchYear, Dept, Section, Semester, courseName } = student;

                // Ensure all required fields are defined
                if (!currentUserEmail || !RollNo || !StdName || !batchYear || !Dept || !Section || !Semester || !courseName) {
                    await db_connection.rollback();
                    return res.status(400).json({ error: 'All fields are required' });
                }

                // Validate the RollNo format
                const pattern = /^[A-Z]{2}\.[A-Z]{2}\.[A-Z]{1}[0-9]{1}[A-Z]{3}[0-9]{5}$/;
                if (!pattern.test(RollNo)) {
                    await db_connection.rollback();
                    return res.status(400).json({ error: 'Invalid roll number format' });
                }

                // Fetch userRole based on currentUserEmail
                const [currentUser] = await db_connection.query('SELECT userRole FROM USERDATA WHERE email = ?', [currentUserEmail]);

                if (currentUser.length === 0) {
                    await db_connection.rollback();
                    return res.status(404).json({ error: 'Current user not found' });
                }

                const currentUserRole = currentUser[0].userRole;

                // Fetch courseID based on Dept
                const [courseResult] = await db_connection.query('SELECT courseID FROM course WHERE courseName = ?', [courseName]);

                if (courseResult.length === 0) {
                    await db_connection.rollback();
                    return res.status(400).send({ "message": "Course not found!" });
                }

                // Insert data into class table
                const [classResult] = await db_connection.query(
                    'INSERT INTO class (batchYear, Dept, Section, courseID, Semester) VALUES (?, ?, ?, ?, ?)',
                    [batchYear, Dept, Section, courseResult[0].courseID, Semester]
                );

                // Insert data into studentData table
                const [result] = await db_connection.query(
                    'INSERT INTO studentData (RollNo, StdName, classID) VALUES (?, ?, ?)',
                    [RollNo, StdName, classResult.insertId]
                );

                if (result.affectedRows !== 1) {
                    await db_connection.rollback();
                    return res.status(500).json({ error: `Failed to add student: ${RollNo}` });
                } else {
                    // Log success for this student
                    console.log(`Student added successfully: ${RollNo}`);
                }
            }

            // Commit the transaction
            await db_connection.query('COMMIT');
            res.status(201).json({ message: 'Students added successfully' });
        } catch (error) {
            console.error(error);
            // Rollback the transaction in case of an error
            if (db_connection) {
                await db_connection.rollback();
            }

            const time = new Date();
            fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - addStudents - ${error}\n`);

            res.status(500).json({ error: 'Failed to add students' });
        } finally {
            // Unlock the tables and release the database connection
            await db_connection.query('UNLOCK TABLES');
            db_connection.release();
        }
    },],

    // -------------------Student Operations Ends------------------------------

    // -------------------Class Operations Starts------------------------------

    createClass: [webTokenValidator, async (req, res) => {
        // Create a class
        /*
            queries {
                currentUserEmail: <currentUserEmail>
            }
            JSON
            {
                "batchYear": "<batchYear>",
                "Dept": "<Dept>",
                "Section": "<Section>",
                "Semester": "<Semester>",
                "courseName": "<courseName>",
                "profEmail": "<profEmail>"
            }
        */

        let db_connection;

        try {
            db_connection = await db.promise().getConnection();

            // Lock the necessary tables to prevent concurrent writes
            await db_connection.query('LOCK TABLES class WRITE, course READ, ProfessorClass WRITE, USERDATA READ');

            const isActive = '1'; // Assuming isActive is a CHAR(1) field

            const currentUserEmail = req.query.currentUserEmail; // Updated: Extract email from request body

            // Find the current user's role based on email
            const [userRoleResult] = await db_connection.query('SELECT userRole FROM USERDATA WHERE email = ?', [currentUserEmail]);

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

            const { batchYear, Dept, Section, Semester, courseName, profEmail } = req.body;

            // Find courseID based on courseName
            const [courseResult] = await db_connection.query('SELECT courseID FROM course WHERE courseName = ?', [courseName]);

            if (courseResult.length === 0) {
                // Rollback the transaction
                await db_connection.query('ROLLBACK');
                return res.status(400).json({ error: 'Course not found' });
            }

            const courseID = courseResult[0].courseID;

            let profResult;
            console.log(currentUserRole)
            if (currentUserRole === '1') {
                [profResult] = await db_connection.query('SELECT profID FROM USERDATA WHERE email = ? AND userRole = ? AND isActive = ?', [profEmail, 1, 1]);
            } else if (currentUserRole === '0') {
                // Find profID based on profEmail
                [profResult] = await db_connection.query('SELECT profID FROM USERDATA WHERE email = ? AND userRole = ? AND isActive = ?', [currentUserEmail, 0, 1]);
            }

            console.log('#########' + profResult)

            if (profResult.length === 0) {
                // Rollback the transaction
                await db_connection.query('ROLLBACK');
                return res.status(400).json({ error: 'Professor not found or inactive' });
            }

            const profID = profResult[0].profID;

            // Insert class into class table
            const [classResult] = await db_connection.query(
                'INSERT INTO class (batchYear, Dept, Section, Semester, courseID, isActive) VALUES (?, ?, ?, ?, ?, ?)',
                [batchYear, Dept, Section, Semester, courseID, isActive]
            );

            if (classResult.affectedRows === 1) {
                const classID = classResult.insertId;

                // Insert professor and class association into ProfessorClass table
                await db_connection.query(
                    'INSERT INTO ProfessorClass (professorID, classID) VALUES (?, ?)',
                    [profID, classID]
                );

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
        /*
            queries {
                currentUserEmail: <currentUserEmail>
            */
        let db_connection;

        try {
            db_connection = await db.promise().getConnection();

            // Lock the necessary tables to prevent concurrent writes
            await db_connection.query('LOCK TABLES USERDATA READ, ProfessorClass READ, class READ, course READ');

            const currentUserEmail = req.query.currentUserEmail;

            if (!currentUserEmail || !validator.isEmail(currentUserEmail)) {
                return res.status(400).json({ error: 'Invalid current user email' });
            }

            // Fetch userRole based on the email
            const [userRoleResult] = await db_connection.query('SELECT userRole FROM USERDATA WHERE email = ?', [currentUserEmail]);

            if (userRoleResult.length === 0) {
                return res.status(404).json({ error: 'User not found' });
            }

            const currentUserRole = userRoleResult[0].userRole;

            if (currentUserRole !== '0' && currentUserRole !== '1') {
                return res.status(403).json({ error: 'Permission denied. Only professors and admins can access classes.' });
            }

            // Fetch profID based on the email
            const [profData] = await db_connection.query(`
            SELECT profID FROM USERDATA WHERE email = ? AND userRole = '0' AND isActive = '2'
        `, [currentUserEmail]);

            await db_connection.query('UNLOCK TABLES');


            if (profData.length === 0) {
                return res.status(404).json({ error: 'Professor not found or inactive' });
            }

            const profID = profData[0].profID;

            await db_connection.query('LOCK TABLES ProfessorClass pc READ, class c READ, course co READ');

            // Fetch classes along with course information
            const [rows] = await db_connection.query(`
            SELECT c.Dept, c.Section, c.Semester, c.batchYear, co.courseName 
            FROM ProfessorClass pc
            JOIN class c ON c.classID = pc.classID
            JOIN course co ON co.courseID = c.courseID
            WHERE pc.professorID = ? AND c.isActive = '1'
        `, [profID]);

            if (rows.length === 0) {
                return res.status(401).json({ message: 'No classes found' });
            }

            // Unlock the tables
            await db_connection.query('UNLOCK TABLES');

            res.json(rows);
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
        // Delete a class
        /*
        queries 
        {
            currentUserEmail: <currentUserEmail>
        }
            JSON
            {
                "email": "<email>",
                "batchYear": "<batchYear>",
                "Semester": "<Semester>",
                "Section": "<Section>",
                "Dept": "<Dept>",
                "courseName": "<courseName>"
            }
        */

        let db_connection;

        try {
            db_connection = await db.promise().getConnection();

            // Lock the necessary tables to prevent concurrent writes
            await db_connection.query('LOCK TABLES class WRITE, ProfessorClass WRITE, USERDATA READ, course READ');

            const currentUserEmail = req.query.currentUserEmail;
            const userEmail = req.body.email;
            const batchYear = req.body.batchYear;
            const Semester = req.body.Semester;
            const Section = req.body.Section;
            const Dept = req.body.Dept;
            const courseName = req.body.courseName;

            if (!currentUserEmail || !validator.isEmail(currentUserEmail)) {
                return res.status(400).json({ error: 'Invalid user email' });
            }

            // Fetch userRole based on the currentUserEmail
            const [userData] = await db_connection.query(`
            SELECT userRole
            FROM USERDATA
            WHERE email = ? AND isActive = '1'
        `, [currentUserEmail]);

            if (userData.length === 0) {
                return res.status(404).json({ error: 'User not found' });
            }

            const userRole = userData[0].userRole;

            if (userRole === '0') {
                // If the user is a faculty, ensure they can only delete their own classes
                const [profData] = await db_connection.query(`
                SELECT profID
                FROM USERDATA
                WHERE email = ? AND isActive = '1'
            `, [currentUserEmail]);

                if (profData.length === 0) {
                    return res.status(404).json({ error: 'Professor not found' });
                }

                const profID = profData[0].profID;

                // Fetch classID based on the provided details and profID
                const [classData] = await db_connection.query(`
                SELECT classID
                FROM ProfessorClass
                WHERE professorID = ? AND classID IN (
                    SELECT classID
                    FROM class
                    WHERE batchYear = ? AND Semester = ? AND Section = ? AND Dept = ? AND courseID = (
                        SELECT courseID
                        FROM course
                        WHERE courseName = ?
                    ) AND isActive = '1'
                )
            `, [profID, batchYear, Semester, Section, Dept, courseName]);

                if (classData.length === 0) {
                    return res.status(404).json({ error: 'Class not found or you do not have permission to delete' });
                }

                const classID = classData[0].classID;

                // Start a transaction
                await db_connection.query('START TRANSACTION');

                // Delete entry from ProfessorClass
                await db_connection.query('DELETE FROM ProfessorClass WHERE professorID = ? AND classID = ?', [profID, classID]);

                // Delete class from class table
                const [result] = await db_connection.query('UPDATE class SET isActive = ? WHERE classID = ?', [0, classID]);

                if (result.affectedRows === 1) {
                    // Commit the transaction
                    await db_connection.query('COMMIT');
                    res.json({ message: 'Class deleted successfully' });
                } else {
                    // Rollback the transaction
                    await db_connection.query('ROLLBACK');
                    res.status(500).json({ error: 'Failed to delete class' });
                }
            } else if (userRole === '1') {

                // If the user is an admin, ensure they provide the userEmail to delete any class
                if (!userEmail || !validator.isEmail(userEmail)) {
                    return res.status(400).json({ error: 'Invalid user email for admin deletion' });
                }

                // Fetch profID based on the userEmail
                const [profData] = await db_connection.query(`
                SELECT profID
                FROM USERDATA
                WHERE email = ? AND isActive = '1'
            `, [userEmail]);

                if (profData.length === 0) {
                    return res.status(404).json({ error: 'Professor not found or invalid permissions' });
                }

                const profID = profData[0].profID;

                // Fetch classID based on the provided details and profID
                const [classData] = await db_connection.query(`
                SELECT classID
                FROM class
                WHERE batchYear = ? AND Semester = ? AND Section = ? AND Dept = ? AND courseID = (
                    SELECT courseID
                    FROM course
                    WHERE courseName = ?
                ) AND isActive = '1'
            `, [batchYear, Semester, Section, Dept, courseName]);

                if (classData.length === 0) {
                    return res.status(404).json({ error: 'Class not found or already deleted' });
                }

                const classID = classData[0].classID;

                // Start a transaction
                await db_connection.query('START TRANSACTION');

                // Delete entry from ProfessorClass
                await db_connection.query('DELETE FROM ProfessorClass WHERE professorID = ? AND classID = ?', [profID, classID]);

                // Delete class from class table
                const [result] = await db_connection.query('UPDATE class SET isActive = ? WHERE classID = ?', [0, classID]);

                if (result.affectedRows === 1) {
                    // Commit the transaction
                    await db_connection.query('COMMIT');
                    res.json({ message: 'Class deleted successfully' });
                } else {
                    // Rollback the transaction
                    await db_connection.query('ROLLBACK');
                    res.status(500).json({ error: 'Failed to delete class' });
                }
            } else {
                return res.status(403).json({ error: 'Permission denied. Only faculty and admins can delete classes.' });
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

    // -------------------Class Operations Ends------------------------------

    // -------------------Slot Operations Starts------------------------------

    createSlot: [webTokenValidator, async (req, res) => {
        // Create a class slot
        /*
            queries {
                email: <userEmail>
            }
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
            await db_connection.query('LOCK TABLES slots WRITE, class READ, userdata READ');

            const userEmail = req.query.email;

            if (!userEmail || !validator.isEmail(userEmail)) {
                return res.status(400).json({ error: 'Invalid user email' });
            }

            // Fetch userRole based on the email
            const [userResult] = await db_connection.query(`
            SELECT userRole
            FROM userdata
            WHERE email = ? AND isActive = '1'
        `, [userEmail]);

            if (userResult.length === 0) {
                return res.status(404).json({ error: 'User not found or inactive' });
            }

            const currentUserRole = userResult[0].userRole;

            if (currentUserRole != 0 && currentUserRole != 1) {
                // Unlock the tables
                await db_connection.query('UNLOCK TABLES');
                db_connection.release();

                return res.status(403).json({ error: 'Permission denied. Only professors and admins can create class slots.' });
            }

            // Start a transaction
            await db_connection.query('START TRANSACTION');

            const { batchYear, Dept, Section, Semester, periodNo } = req.body;

            // Find classID based on provided details
            const [classResult] = await db_connection.query(`
            SELECT classID
            FROM class
            WHERE batchYear = ? AND Dept = ? AND Section = ? AND Semester = ? AND isActive = '1'
        `, [batchYear, Dept, Section, Semester]);

            if (classResult.length === 0) {
                // Rollback the transaction
                await db_connection.query('ROLLBACK');
                return res.status(400).json({ error: 'Class not found or inactive' });
            }

            const classID = classResult[0].classID;

            // Insert slot into slots table
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
            queries {
                userEmail: <userEmail>
            }
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
            await db_connection.query('LOCK TABLES slots WRITE, class READ, userdata READ');

            const userEmail = req.query.userEmail;
            const batchYear = req.body.batchYear;
            const Dept = req.body.Dept;
            const Section = req.body.Section;
            const Semester = req.body.Semester;
            const PeriodNo = req.body.periodNo;

            // Fetch userRole based on the email
            const [userResult] = await db_connection.query(`
            SELECT userRole
            FROM userdata
            WHERE email = ? AND isActive = '1'
        `, [userEmail]);

            if (userResult.length === 0) {
                return res.status(404).json({ error: 'User not found' });
            }

            const currentUserRole = userResult[0].userRole;

            if (currentUserRole != 0 && currentUserRole != 1) {
                return res.status(403).json({ error: 'Permission denied. Only professors and admins can delete slots.' });
            }

            // Fetch profID based on the email
            const [profData] = await db_connection.query(`
            SELECT profID FROM USERDATA WHERE email = ? AND userRole = '0' AND isActive = '1'
        `, [userEmail]);

            if (profData.length === 0) {
                return res.status(404).json({ error: 'Professor not found or inactive' });
            }

            const profID = profData[0].profID;

            // Fetch classID based on the provided details
            const [classData] = await db_connection.query(`
            SELECT classID
            FROM class
            WHERE batchYear = ? AND Semester = ? AND Section = ? AND isActive = '1'
        `, [batchYear, Semester, Section]);

            if (classData.length === 0) {
                return res.status(404).json({ error: 'Class not found' });
            }

            const classID = classData[0].classID;

            // Fetch slotID based on classID and PeriodNo
            const [slotData] = await db_connection.query('SELECT slotID FROM slots WHERE classID = ? AND PeriodNo = ?', [classID, PeriodNo]);

            if (slotData.length === 0) {
                return res.status(404).json({ error: 'Slot not found' });
            }

            const slotID = slotData[0].slotID;

            // Start a transaction
            await db_connection.query('START TRANSACTION');

            await db_connection.query('DELETE FROM attendance WHERE slotID = ?', [slotID]);
            const [result] = await db_connection.query('DELETE FROM slots WHERE slotID = ?', [slotID]);

            if (result.affectedRows === 1) {
                // Commit the transaction
                await db_connection.query('COMMIT');
                res.json({ message: 'Slot deleted successfully' });
            } else {
                // Rollback the transaction
                await db_connection.query('ROLLBACK');
                res.status(500).json({ error: 'Failed to delete slot' });
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

    // -------------------Slot Operations Ends------------------------------

    // -------------------Course Operations Starts--------------------------

    createCourse: [webTokenValidator, async (req, res) => {
        /*
            queries {
                email: <userEmail>
            }
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

            const userEmail = req.query.email;

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
        } catch (error) {
            console.error(error);
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
            queries {
                email: <userEmail>
            }
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

            const userEmail = req.query.email;
            const courseName = req.body.courseName;

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
                return res.status(403).json({ error: 'Permission denied. Only professors and admins can delete courses.' });
            }

            // Fetch courseID based on courseName
            const [courseData] = await db_connection.query(`
            SELECT courseID
            FROM course
            WHERE courseName = ? AND isActive = '1'
        `, [courseName]);

            if (courseData.length === 0) {
                return res.status(404).json({ error: 'Course not found or inactive' });
            }

            const courseID = courseData[0].courseID;

            // Start a transaction
            await db_connection.query('START TRANSACTION');

            const [result] = await db_connection.query('UPDATE course SET isActive = ? WHERE courseID = ?', [0, courseID]);

            if (result.affectedRows === 1) {
                // Commit the transaction
                await db_connection.query('COMMIT');
                res.json({ message: 'Course deleted successfully' });
            } else {
                // Rollback the transaction
                await db_connection.query('ROLLBACK');
                res.status(404).json({ error: 'Course not found' });
            }
        } catch (error) {
            console.error(error);
            // Rollback the transaction in case of an error
            if (db_connection) {
                await db_connection.query('ROLLBACK');
            }
            const time = new Date();
            fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - deleteCourse - ${error}\n`);
            res.status(500).json({ error: 'Failed to delete course' });
        } finally {
            // Unlock the tables
            await db_connection.query('UNLOCK TABLES');
            db_connection.release();
        }
    },],

    // -------------------Course Operations Ends----------------------------

    // -------------------Attendance Operations Starts--------------------------

    addAttendance: async (req, res) => {
        /*
            JSON
            {
                "RollNo": "<RollNo>",
                "attdStatus": "<attdStatus>",
                "timestamp": "<timestamp>",
                "classID: <class id>",
                "PeriodNo: < period no>"
            }
        */

        let db_connection;

        try {
            db_connection = await db.promise().getConnection();

            // Lock the necessary tables to prevent concurrent writes
            await db_connection.query('LOCK TABLES attendance WRITE');

            // Start a transaction
            await db_connection.query('START TRANSACTION');

            const { RollNo, attdStatus, timestamp, classID, PeriodNo } = req.body;

            const [s] = await db_connection.query('SELECT slotID FROM slots WHERE ClassID = ? AND PeriodNo = ?', [classID, PeriodNo]);
            const slotID = s[0].slotID

            // Validate attdStatus
            const validStatusValues = ['0', '1', '2', '3', '4'];
            if (!validStatusValues.includes(attdStatus)) {
                return res.status(400).json({ error: 'Invalid attendance status value' });
            }

            const [result] = await db_connection.query('INSERT INTO attendance (RollNo, attdStatus, timestamp, slotID) VALUES (?, ?, ?, ?)', [RollNo, attdStatus, timestamp, slotID]);

            if (result.affectedRows === 1) {
                // Commit the transaction
                await db_connection.query('COMMIT');
                res.status(201).json({ message: 'Attendance recorded successfully' });
            } else {
                // Rollback the transaction
                await db_connection.query('ROLLBACK');
                res.status(500).json({ error: 'Failed to record attendance' });
            }
        } catch (error) {
            console.error(error);
            // Rollback the transaction in case of an error
            if (db_connection) {
                await db_connection.query('ROLLBACK');
            }
            fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - addAttendance - ${error}\n`);
            res.status(500).json({ error: 'Failed to record attendance' });
        } finally {
            // Unlock the tables
            await db_connection.query('UNLOCK TABLES');
            db_connection.release();
        }
    },

    getAttendanceForSlot: async (req, res) => {
        /*
            queries {
                classID: <class id>
                PeriodNo: < period no>       
            }
        */

        let db_connection;

        try {
            db_connection = await db.promise().getConnection();

            // Start a transaction
            await db_connection.query('START TRANSACTION');

            const classID = req.query.classID;
            const PeriodNo = req.query.PeriodNo;
            const Date = req.query.date;
            const [s] = await db_connection.query('SELECT slotID FROM slots WHERE ClassID = ? AND PeriodNo = ?', [classID, PeriodNo]);
            const slotID = s[0].slotID;

            const [rows] = await db_connection.query('SELECT (RollNO, attstatus) FROM attendance WHERE slotID = ? and ', [slotID]);

            // Commit the transaction
            await db_connection.query('COMMIT');

            res.json(rows);
        } catch (error) {
            console.error(error);
            // Rollback the transaction in case of an error
            if (db_connection) {
                await db_connection.query('ROLLBACK');
            }
            fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - getAttendanceForSlot - ${error}\n`);
            res.status(500).json({ error: 'Failed to fetch attendance' });
        } finally {
            // Unlock the tables
            await db_connection.query('UNLOCK TABLES');
            db_connection.release();
        }
    },

    updateAttendanceStatus: async (req, res) => {
        /*
            JSON
            {
                "RollNo": "<RollNo>",
                "timestamp": "<timestamp>",
                "attdStatus": "<attdStatus>"
            }
        */

        let db_connection;

        try {
            db_connection = await db.promise().getConnection();

            // Lock the necessary tables to prevent concurrent writes
            await db_connection.query('LOCK TABLES attendance WRITE');

            // Start a transaction
            await db_connection.query('START TRANSACTION');

            const { RollNo, timestamp, attdStatus } = req.body;

            // Validate attdStatus
            const validStatusValues = ['0', '1', '2', '3', '4'];
            if (!validStatusValues.includes(attdStatus)) {
                return res.status(400).json({ error: 'Invalid attendance status value' });
            }

            const [result] = await db_connection.query('UPDATE attendance SET attdStatus = ? WHERE RollNo = ? AND timestamp = ?', [attdStatus, RollNo, timestamp]);

            if (result.affectedRows === 1) {
                // Commit the transaction
                await db_connection.query('COMMIT');
                res.json({ message: 'Attendance status updated successfully' });
            } else {
                // Rollback the transaction
                await db_connection.query('ROLLBACK');
                res.status(404).json({ error: 'Attendance record not found' });
            }
        } catch (error) {
            console.error(error);
            // Rollback the transaction in case of an error
            if (db_connection) {
                await db_connection.query('ROLLBACK');
            }
            fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - updateAttendanceStatus - ${error}\n`);
            res.status(500).json({ error: 'Failed to update attendance status' });
        } finally {
            // Unlock the tables
            await db_connection.query('UNLOCK TABLES');
            db_connection.release();
        }
    },

    // -------------------Attendance Operations Ends----------------------------

};