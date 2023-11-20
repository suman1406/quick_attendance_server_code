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

    getAllUsers: async (req, res) => {
        /*
        Headers: {
            "Authorization": "Bearer <SECRET_TOKEN>"
        }
        JSON
        {
            "userRole": "<userRole>"
        }
        */

        if (
            req.body.userRole === null ||
            req.body.userRole === undefined ||
            req.body.userRole === "" ||
            (req.body.userRole !== "0" && req.body.userRole !== "1")
        ) {
            return res.status(400).send({ "message": "Invalid user role!" });
        }

        let db_connection = await db.promise().getConnection();

        try {
            await db_connection.query(`LOCK TABLES USERDATA READ`);

            // Check if the user making the request is an admin
            let [admin] = await db_connection.query(
                `SELECT * from USERDATA WHERE email = ? AND userRole = ?`,
                [req.body.userEmail, "1"]
            );

            if (admin.length === 0) {
                await db_connection.query(`UNLOCK TABLES`);
                return res.status(401).send({ "message": "Access Restricted!" });
            }

            let users;
            if (req.body.userRole === "0") {
                // Fetch all faculty members
                [users] = await db_connection.query(
                    `SELECT u.profName, u.email, c.courseName FROM USERDATA u LEFT JOIN course c ON u.courseID = c.courseID WHERE u.userRole = ? AND u.isActive = ?`, ["0", "1"]
                );
            } else {
                // Fetch all administrators
                [users] = await db_connection.query(
                    `SELECT u.profName, u.email, c.courseName FROM USERDATA u LEFT JOIN course c ON u.courseID = c.courseID WHERE u.userRole = ? AND u.isActive = ?`, ["1", "1"]
                );
            }

            if (users.length === 0) {
                await db_connection.query(`UNLOCK TABLES`);
                return res.status(200).send({ "message": "No users found!", "users": [] });
            }

            await db_connection.query(`UNLOCK TABLES`);
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
            await db_connection.query(`UNLOCK TABLES`);
            db_connection.release();
        }
    },

    editUser: async (req, res) => {
        /*
        Headers: {
            "Authorization": "Bearer <SECRET_TOKEN>"
        }
        queries {
            userRole: <userRole>,
            id: <userID>
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
            const currentUserRole = req.query.userRole;
            const userID = req.query.id;
            const { profName, email, password, courseName } = req.body;

            // Lock the necessary tables to prevent concurrent writes
            db_connection = await db.promise().getConnection();
            await db_connection.query('LOCK TABLES USERDATA WRITE, COURSE READ');

            const [user] = await db_connection.query('SELECT userRole FROM USERDATA WHERE profID = ?', [userID]);

            if (user.length === 0) {
                await db_connection.query(`UNLOCK TABLES`);
                return res.status(404).json({ error: 'User not found' });
            }

            const userRole = user[0].userRole;

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

                    if (password) {
                        const salt = crypto.randomBytes(16).toString('hex');
                        const hashedPassword = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');

                        [result] = await db_connection.query('UPDATE USERDATA SET profName = ?, email = ?, password = ?, courseID = ? WHERE profID = ?', [profName, email, hashedPassword, courseID, userID]);
                    } else {
                        [result] = await db_connection.query('UPDATE USERDATA SET profName = ?, email = ?, courseID = ? WHERE profID = ?', [profName, email, courseID, userID]);
                    }
                } else if (currentUserRole === "0") {
                    // Faculty editing their own profile
                    if (userID != req.query.userID) {
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

                        [result] = await db_connection.query('UPDATE USERDATA SET profName = ?, email = ?, password = ?, courseID = ? WHERE profID = ?', [profName, email, hashedPassword, courseID, userID]);
                    } else {
                        [result] = await db_connection.query('UPDATE USERDATA SET profName = ?, email = ?, courseID = ? WHERE profID = ?', [profName, email, courseID, userID]);
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

    deleteMember: async (req, res) => {
        /*
        Headers: {
            "Authorization": "Bearer <SECRET_TOKEN>"
        }
    
        JSON
        {
            "userEmail": "<userEmail>",
            "memberProfName": "<profName>"
        }
        */

        if (
            req.body.userRole === null ||
            req.body.userRole === undefined ||
            req.body.userRole === "" ||
            req.body.userEmail === null ||
            req.body.userEmail === undefined ||
            req.body.userEmail === "" ||
            !validator.isEmail(req.body.userEmail) ||
            req.body.userRole !== "1"
        ) {
            return res.status(400).send({ "message": "Access Restricted!" });
        }

        if (
            req.body.memberProfName === null ||
            req.body.memberProfName === undefined ||
            req.body.memberProfName === ""
        ) {
            return res.status(400).send({ "message": "Missing details." });
        }

        let db_connection = await db.promise().getConnection();

        try {
            await db_connection.query(`LOCK TABLES USERDATA WRITE`);

            // check if actually admin
            let [admin] = await db_connection.query(
                `SELECT * from USERDATA WHERE email = ? AND userRole = ?`,
                [req.body.userEmail, "1"]
            );

            if (admin.length === 0) {
                await db_connection.query(`UNLOCK TABLES`);
                return res.status(401).send({ "message": "Access Restricted!" });
            }

            // check if member exists.
            let [member] = await db_connection.query(
                `SELECT profID, profName, email, userRole from USERDATA WHERE profName = ? AND isActive = ?`,
                [req.body.memberProfName, "1"]
            );

            if (member.length === 0) {
                await db_connection.query(`UNLOCK TABLES`);
                return res.status(400).send({ "message": "Member doesn't exist!" });
            }

            const memberID = member[0].profID;
            const memberRole = member[0].userRole;

            // Admins can delete both admins and faculty
            if (memberRole === "0" || memberRole === "1") {
                await db_connection.query(
                    `UPDATE USERDATA SET isActive = ? WHERE profID = ?`,
                    [0, memberID]
                );
                await db_connection.query(`UNLOCK TABLES`);

                // Notify via email
                mailer.accountDeactivated(
                    member[0].profName,
                    member[0].email,
                );

                return res.status(200).send({
                    "message": `${memberRole === "1" ? "Admin" : "Faculty"} member deleted successfully!`,
                });
            }

            await db_connection.query(`UNLOCK TABLES`);
            return res.status(400).send({ "message": "Action not permitted" });
        } catch (err) {
            console.log(err);
            const time = new Date();
            fs.appendFileSync(
                "logs/errorLogs.txt",
                `${time.toISOString()} - deleteMember - ${err}\n`
            );
            return res.status(500).send({ "message": "Internal Server Error." });
        }
    },

    deleteAdmin: [
        webTokenValidator,
        async (req, res) => {
            await deleteMember(req, res, "1"); // "1" represents admin userRole
        },
    ],

    deleteFaculty: [
        webTokenValidator,
        async (req, res) => {
            await deleteMember(req, res, "0"); // "0" represents faculty userRole
        },
    ],

    addUser: async (req, res, userType) => {
        /*
        Headers: {
            "Authorization": "Bearer <SECRET_TOKEN>"
        }
        JSON
        {
            "userName": "<name>",
            "userEmail": "<email>",
            "courseName": "<course_name>"
        }
        */

        if (
            req.body.userRole === null ||
            req.body.userRole === undefined ||
            req.body.userRole === "" ||
            req.body.userEmail === null ||
            req.body.userEmail === undefined ||
            req.body.userEmail === "" ||
            !validator.isEmail(req.body.userEmail) ||
            req.body.userRole !== "1"
        ) {
            return res.status(400).send({ "message": "Access Restricted!" });
        }

        if (
            req.body.userName === null ||
            req.body.userName === undefined ||
            req.body.userName === "" ||
            req.body.courseName === null ||
            req.body.courseName === undefined ||
            req.body.courseName === ""
        ) {
            return res.status(400).send({ "message": "Missing details." });
        }

        let db_connection = await db.promise().getConnection();

        try {
            await db_connection.query(`LOCK TABLES USERDATA WRITE, course READ`);

            // check if actually admin
            let [admin] = await db_connection.query(
                `SELECT * from USERDATA WHERE email = ? AND userRole = ?`,
                [req.body.userEmail, "1"]
            );

            if (admin.length === 0) {
                await db_connection.query(`UNLOCK TABLES`);
                return res.status(401).send({ "message": "Access Restricted!" });
            }

            let [existingUser] = await db_connection.query(
                `SELECT * from USERDATA WHERE email = ?`,
                [req.body.userEmail]
            );

            if (existingUser.length > 0) {
                await db_connection.query(`UNLOCK TABLES`);
                return res.status(400).send({ "message": "User already registered!" });
            }

            // Fetch courseID based on courseName
            let [courseResult] = await db_connection.query(
                `SELECT courseID FROM course WHERE courseName = ?`,
                [req.body.courseName]
            );

            if (courseResult.length === 0) {
                await db_connection.query(`UNLOCK TABLES`);
                return res.status(400).send({ "message": "Course not found!" });
            }

            // generate a random password for the manager.
            const memberPassword = passwordGenerator.randomPassword({
                length: 8,
                characters: [passwordGenerator.lower, passwordGenerator.upper, passwordGenerator.digits]
            });

            const salt = crypto.randomBytes(16).toString('hex');
            const hashedPassword = crypto.pbkdf2Sync(memberPassword, salt, 10000, 64, 'sha512').toString('hex');

            // Email the password to the user.
            mailer.officialCreated(req.body.userName, req.body.userEmail, hashedPassword);

            await db_connection.query(
                `INSERT INTO USERDATA (profName, email, password, userRole, courseID, isActive) VALUES (?, ?, ?, ?, ?, "2")`,
                [req.body.userName, req.body.userEmail, hashedPassword, userType, courseResult[0].courseID]
            );

            await db_connection.query(`UNLOCK TABLES`);

            return res.status(200).send({ "message": "User registered!" });
        } catch (err) {
            console.log(err);
            const time = new Date();
            fs.appendFileSync(
                "logs/errorLogs.txt",
                `${time.toISOString()} - addUser - ${err}\n`
            );
            return res.status(500).send({ "message": "Internal Server Error." });
        } finally {
            await db_connection.query(`UNLOCK TABLES`);
            db_connection.release();
        }
    },

    addFaculty: [
        webTokenValidator,
        async (req, res) => {
            await addUser(req, res, "0"); // "0" represents faculty userRole
        },
    ],

    addAdmin: [
        webTokenValidator,
        async (req, res) => {
            await addUser(req, res, "1"); // "1" represents admin userRole
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

                if (user[0].isActive === "1") {
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

                    const secret_token = await webTokenGenerator({
                        "email": req.body.email,
                        "userRole": user[0].userRole,
                    });

                    await db_connection.query(`UNLOCK TABLES`);

                    console.log(secret_token)
                    return res.status(201).send({
                        "message": "First time login! OTP sent to email.",
                        "SECRET_TOKEN": secret_token,
                        "email": user[0].email,
                        "profName": user[0].profName,
                    });


                } else if (user[0].isActive != "1") {
                    await db_connection.query(`UNLOCK TABLES`);
                    return res.status(401).send({ "message": "Access Restricted." });
                }

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
                await db_connection.query(`LOCK TABLES USERREGISTER WRITE, USERDATA WRITE`);

                let [check_1] = await db_connection.query(`DELETE FROM USERREGISTER WHERE email = ? AND otp ?`, [req.body.email, req.body.otp]);

                if (check_1.affectedRows === 0) {
                    await db_connection.query(`UNLOCK TABLES`);
                    return res.status(401).send({ "message": "Invalid OTP." });
                }

                let [user] = await db_connection.query(`SELECT * FROM USERDATA WHERE email = ?`, [req.email]);

                if (user.length === 0) {
                    await db_connection.query(`UNLOCK TABLES`);
                    return res.status(401).send({ "message": "Invalid Email." });
                }

                await db_connection.query(`UPDATE USERDATA SET password = ? WHERE email = ?`, [req.body.password, req.email]);

                await db_connection.query(`UNLOCK TABLES`);

                const secret_token = await webTokenGenerator({
                    "email": req.body.email,
                    "userRole": user[0].userRole,
                });

                return res.status(201).send({
                    "message": "First time login! OTP sent to email.",
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

            const secret_token = await otpTokenGenerator({
                email: req.body.email,
                userRole: userRole,
            });

            mailer.reset_PW_OTP(profName, otp, req.body.email);

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

    resetPassword: async (req, res) => {
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

    // -----------------------Authentication Operations End-----------------

    // -----------------------Student Operations Start---------------------------

    addStudent: async (req, res) => {
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
            console.log("Request ")
            // Validate the presence of required fields

            // Ensure all required fields are defined
            if (!RollNo || !StdName || !classID) {
                return res.status(400).json({ error: 'All fields are required' });
            }
            const pattern = /^[A-Z]{2}\.[A-Z]{2}\.[A-Z]{1}[0-9]{1}[A-Z]{3}[0-9]{5}$/;
            if (pattern.test(RollNo)) {
                // Roll number is in the correct format
            } else {
                // Roll number format is incorrect
                res.status(400).json({ error: 'Invalid roll number format' });
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
        /*
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

            const insertValues = students.map(({ RollNo, StdName, batchYear, Dept, Section, courseName, Semester }) => [
                RollNo,
                StdName,
                batchYear,
                Dept,
                Section,
                courseName,
                Semester,
                '1', // isActive should be a string
            ]);

            // Subquery to fetch classID
            const classIdSubquery = `SELECT classID FROM class WHERE batchYear = VALUES(batchYear) AND Dept = VALUES(Dept) AND Section = VALUES(Section) AND courseID = (SELECT courseID FROM course WHERE courseName = VALUES(courseName)) AND Semester = VALUES(Semester) LIMIT 1`;

            const query = `INSERT INTO studentData (RollNo, StdName, isActive, classID) VALUES ? ON DUPLICATE KEY UPDATE StdName = VALUES(StdName), isActive = VALUES(isActive), classID = (${classIdSubquery})`;

            const [result] = await db_connection.query(query, [insertValues]);

            if (result.affectedRows > 0) {
                // Commit the transaction
                await db_connection.commit();
                res.status(201).json({ message: 'Students added successfully' });
            } else {
                // Rollback the transaction
                await db_connection.rollback();
                res.status(500).json({ error: 'Failed to add students' });
            }
        } catch (error) {
            console.error(error);
            // Rollback the transaction in case of an error
            if (db_connection) {
                await db_connection.rollback();
            }
            fs.appendFileSync('logs/errorLogs.txt', `${new Date().toISOString()} - addStudents - ${error}\n`);
            res.status(500).json({ error: 'Failed to add students' });
        } finally {
            // Release the connection
            if (db_connection) {
                await db_connection.release();
            }
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
                "courseName": "<courseName>",
                "profEmail": "<profEmail>"
            }
        */

        let db_connection;

        try {
            db_connection = await db.promise().getConnection();

            // Lock the necessary tables to prevent concurrent writes
            await db_connection.query('LOCK TABLES class WRITE, course READ, ProfessorClass WRITE');

            const currentUserRole = req.query.userRole;
            const isActive = '1'; // Assuming isActive is a CHAR(1) field

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

            // Find profID based on profEmail
            const [profResult] = await db_connection.query('SELECT profID FROM USERDATA WHERE email = ? AND userRole = \'0\' AND isActive = \'1\'', [profEmail]);

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
    },

    myClasses: async (req, res) => {
        // Fetch classes for a professor
        /*
            queries {
                userRole: <userRole>
                email: <profEmail>
            */

        let db_connection;

        try {
            db_connection = await db.promise().getConnection();

            // Lock the necessary tables to prevent concurrent writes
            await db_connection.query('LOCK TABLES ProfessorClass READ, class READ, course READ');

            const currentUserRole = req.query.userRole;

            if (currentUserRole !== '0' && currentUserRole !== '1') {
                return res.status(403).json({ error: 'Permission denied. Only professors and admins can access classes.' });
            }

            const profEmail = req.query.email;

            if (!profEmail || !validator.isEmail(profEmail)) {
                return res.status(400).json({ error: 'Invalid professor email' });
            }

            // Fetch profID based on the email
            const [profData] = await db_connection.query(`
            SELECT profID FROM USERDATA WHERE email = ? AND userRole = '0' AND isActive = '1'
        `, [profEmail]);

            if (profData.length === 0) {
                return res.status(404).json({ error: 'Professor not found or inactive' });
            }

            const profID = profData[0].profID;

            // Fetch classes along with course information
            const [rows] = await db_connection.query(`
            SELECT c.Dept, c.Section, c.Semester, c.batchYear, co.courseName 
            FROM ProfessorClass pc
            JOIN class c ON c.classID = pc.classID
            JOIN course co ON co.courseID = c.courseID
            WHERE pc.profID = ? AND c.isActive = '1'
        `, [profID]);

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
    },

    deleteClass: async (req, res) => {
        // Delete a class
        /*
            queries {
                profName: <profName>
                batchYear: <batchYear>
                Semester: <Semester>
                Section: <Section>
                courseName: <courseName>
            }
        */

        let db_connection;

        try {
            db_connection = await db.promise().getConnection();

            // Lock the necessary tables to prevent concurrent writes
            await db_connection.query('LOCK TABLES class WRITE, userdata READ, course READ');

            const profName = req.query.profName;
            const batchYear = req.query.batchYear;
            const Semester = req.query.Semester;
            const Section = req.query.Section;
            const courseName = req.query.courseName;

            if (!profName) {
                return res.status(400).json({ error: 'Invalid professor name' });
            }

            // Fetch profID based on the profName
            const [profData] = await db_connection.query(`
            SELECT profID, userRole
            FROM USERDATA
            WHERE profName = ? AND isActive = '1'
        `, [profName]);

            if (profData.length === 0 || profData[0].userRole !== '0') {
                return res.status(404).json({ error: 'Professor not found or invalid permissions' });
            }

            const profID = profData[0].profID;

            // Fetch classID based on the provided details
            const [classData] = await db_connection.query(`SELECT classID FROM ProfessorClass WHERE profID = ? AND classID IN (SELECT classID FROM class WHERE batchYear = ? AND Semester = ? AND Section = ? AND courseID = (SELECT courseID FROM course WHERE courseName = ?) AND isActive = '1')`, [profID, batchYear, Semester, Section, courseName]);

            if (classData.length === 0) {
                return res.status(404).json({ error: 'Class not found or already deleted' });
            }

            const classID = classData[0].classID;

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
                res.status(500).json({ error: 'Failed to delete class' });
            }
        } catch (error) {
            console.error(error);
            // Rollback the transaction in case of an error
            if (db_connection) {
                await db_connection.query('ROLLBACK');
            }
            fs.appendFileSync('logs/errorLogs.txt', `${new Date().toISOString()} - deleteClass - ${error}\n`);
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
    },

    deleteSlot: async (req, res) => {
        // Delete a class slot
        /*
            queries {
                email: <userEmail>
                batchYear: <batchYear>
                Dept: <Dept>
                Section: <Section>
                Semester: <Semester>
                PeriodNo: <PeriodNo>
            */
        let db_connection;

        try {
            db_connection = await db.promise().getConnection();

            // Lock the necessary tables to prevent concurrent writes
            await db_connection.query('LOCK TABLES slots WRITE, class READ, userdata READ');

            const userEmail = req.query.email;
            const batchYear = req.query.batchYear;
            const Dept = req.query.Dept;
            const Section = req.query.Section;
            const Semester = req.query.Semester;
            const PeriodNo = req.query.PeriodNo;

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
            WHERE profID = ? AND batchYear = ? AND Semester = ? AND Section = ? AND isActive = '1'
        `, [profID, batchYear, Semester, Section]);

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
    },

    // -------------------Slot Operations Ends------------------------------

    // -------------------Course Operations Starts--------------------------

    createCourse: async (req, res) => {
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
    },

    deleteCourse: async (req, res) => {
        /*
            queries {
                email: <userEmail>
                courseName: <courseName>
            }
        */

        let db_connection;

        try {
            db_connection = await db.promise().getConnection();

            // Lock the necessary tables to prevent concurrent writes
            await db_connection.query('LOCK TABLES course WRITE, userdata READ');

            const userEmail = req.query.email;
            const courseName = req.query.courseName;

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
    },

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