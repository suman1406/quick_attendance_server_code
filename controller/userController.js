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

        console.log(req.userEmail)

        if (
            req.userEmail === null ||
            req.userEmail === undefined ||
            req.userEmail === ""
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
                    [req.userEmail, "1"]
                );

                await db_connection.query('UNLOCK TABLES');

                if (admin.length === 0) {
                    db_connection.release();
                    return res.status(401).send({ "message": "Access Restricted!" });
                }

                await db_connection.query('LOCK TABLES USERDATA u READ, COURSE c READ');

                console.log(req.body.reqRole)

                let users;
                if (req.body.reqRole == "0") {
                    // Fetch all faculty members
                    [users] = await db_connection.query(
                        `SELECT u.profName, u.email FROM USERDATA u WHERE u.userRole = '0' AND u.isActive = '2'`, // change to 1 later
                    );
                } else if (req.body.reqRole == "1") {
                    // Fetch all administrators
                    [users] = await db_connection.query(
                        `SELECT u.profName, u.email FROM USERDATA u WHERE u.userRole = '1' AND u.isActive = '2'`
                    );

                    console.log(users)
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

    getAllProfEmails: [webTokenValidator, async (req, res) => {
        /*
        Headers: {
            "Authorization": "Bearer <SECRET_TOKEN>"
        }
        */

        let db_connection = await db.promise().getConnection();

        console.log(req.userEmail)

        if (
            req.userEmail === null ||
            req.userEmail === undefined ||
            req.userEmail === ""
        ) {
            db_connection.release();
            return res.status(400).send({ "message": "Invalid User or Inactive User!" });
        } else {
            try {
                // Lock necessary tables before executing any query
                await db_connection.query('LOCK TABLES USERDATA READ');

                // Check if the user making the request is an admin
                const [admin] = await db_connection.query(
                    `SELECT * from USERDATA WHERE email = ? AND userRole = ?`,
                    [req.userEmail, "1"]
                );

                await db_connection.query('UNLOCK TABLES');

                if (admin.length === 0) {
                    db_connection.release();
                    return res.status(401).send({ "message": "Access Restricted!" });
                }

                await db_connection.query('LOCK TABLES USERDATA u READ');
                const [users] = await db_connection.query(
                    `SELECT u.email FROM USERDATA u WHERE u.isActive = '1'`,
                );
                console.log(users)
                await db_connection.query('UNLOCK TABLES');

                if (users.length === 0) {
                    db_connection.release();
                    return res.status(200).send({ "message": "No users found!", "users": [] });
                }
                return res.status(200).send({ "message": "Users fetched!", "profs": users });
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
            const currentUserEmail = req.userEmail;
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
                        const passwordHashed = crypto.createHash('sha256').update(password).digest('hex');
                        [result] = await db_connection.query('UPDATE USERDATA u JOIN ProfCourse pc ON u.profID = pc.professorID SET u.profName = ? and  u.email = ? and password = ? and u.courseID = pc.courseID WHERE u.profID = ? AND pc.courseID = ?', [profName, userEmail, passwordHashed, profID, courseID]);
                    } else {
                        [result] = await db_connection.query('UPDATE USERDATA u JOIN ProfCourse pc ON u.profID = pc.professorID SET u.profName = ? and  u.email = ? and u.courseID = pc.courseID WHERE u.profID = ? AND pc.courseID = ?', [profName, userEmail, courseID, profID]);
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
                        const passwordHashed = crypto.createHash('sha256').update(password).digest('hex');

                        [result] = await db_connection.query('UPDATE USERDATA SET profName = ?, email = ?, password = ?, courseID = ? WHERE email = ? AND isActive = 1', [profName, email, passwordHashed, courseID, currentUserEmail]);
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
            "adminProfName": "<profName>"
        }
        */
        console.log(req.body.Email)
        if (
            req.body.Email === null ||
            req.body.Email === undefined ||
            req.body.Email === "" ||
            !validator.isEmail(req.body.Email)
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

            // Check if admin exists
            let [adminToDelete] = await db_connection.query(
                `SELECT * FROM USERDATA WHERE email = ? AND isActive = ? AND userRole = ?`,
                [req.body.Email, "1", "1"]
            );

            if (adminToDelete.length === 0) {
                await db_connection.query(`UNLOCK TABLES`);
                return res.status(400).send({ "message": "Admin doesn't exist!" });
            }

            const adminEmail = adminToDelete[0].email;

            // Update the admin's status to inactive
            await db_connection.query(
                `UPDATE USERDATA SET isActive = '0' WHERE email = ? AND userRole = '1' AND isActive = '1'`,
                [adminEmail]
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
            "Email": "<userEmail>",
            "facultyProfName": "<profName>"
        }
        */

        if (
            req.body.Email === null ||
            req.body.Email === undefined ||
            req.body.Email === "" ||
            !validator.isEmail(req.body.Email)
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

            // Check if faculty exists
            let [faculty] = await db_connection.query(
                `SELECT profID, profName, userRole FROM USERDATA WHERE email = ? AND userRole = ? AND isActive = 1`,
                [req.body.Email, "0"]
            );

            if (faculty.length === 0) {
                await db_connection.query(`UNLOCK TABLES`);
                return res.status(400).send({ "message": "Faculty doesn't exist!" });
            }

            // Update the faculty's status to inactive
            await db_connection.query(
                `UPDATE USERDATA SET isActive = '0' WHERE email = ? AND userRole = '0' AND isActive = '1'`,
                [req.body.Email]
            );

            await db_connection.query(`UNLOCK TABLES`);

            // Notify via email
            mailer.accountDeactivated(
                faculty[0].profName,
                req.body.Email,
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
            const { userName, newUserEmail } = req.body;

            if (
                newUserEmail === null ||
                newUserEmail === undefined ||
                newUserEmail === "" ||
                !validator.isEmail(newUserEmail) ||
                userName === null ||
                userName === undefined ||
                userName === ""
            ) {
                console.log(userName, newUserEmail)
                return res.status(400).send({ "message": "Missing details." });
            }

            // Attempt to get a connection from the pool
            db_connection = await db.promise().getConnection();

            // Ensure a connection is obtained
            if (!db_connection) {
                throw new Error('Failed to obtain a database connection.');
            }

            // Lock the necessary tables to prevent concurrent writes
            await db_connection.query('LOCK TABLES USERDATA WRITE');

            // Check if the user is already registered
            let [existingUser] = await db_connection.query(
                'SELECT * FROM USERDATA WHERE email = ?',
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


            const passwordHashed = crypto.createHash('sha256').update(memberPassword).digest('hex');

            // Email the password to the user.
            mailer.officialCreated(userName, newUserEmail, memberPassword);

            // Insert the user into the USERDATA table with faculty role ('0' for faculty)
            const [insertUserResult] = await db_connection.query(
                'INSERT INTO USERDATA (profName, email, password, userRole, isActive) VALUES(?, ?, ?, 0, 2)',
                [userName, newUserEmail, passwordHashed]
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
            if (db_connection) {
                await db_connection.query('UNLOCK TABLES');
                db_connection.release();
            }
        }
    }],

    addAdmin: [webTokenValidator, async (req, res) => {
        let db_connection;

        try {
            const { userName, newUserEmail } = req.body;

            if (
                newUserEmail === null ||
                newUserEmail === undefined ||
                newUserEmail === "" ||
                !validator.isEmail(req.body.newUserEmail) ||
                userName === null ||
                userName === undefined ||
                userName === ""
            ) {
                return res.status(404).send({ "message": "Missing details." });
            }

            db_connection = await db.promise().getConnection();

            // Ensure all required fields are defined
            if (!newUserEmail || !userName) {
                return res.status(400).json({ error: 'All fields are required' });
            }

            // Lock the necessary tables to prevent concurrent writes
            await db_connection.query('LOCK TABLES USERDATA WRITE');

            // Check if the user is already registered
            let [existingUser] = await db_connection.query(
                'SELECT * FROM USERDATA WHERE email = ?',
                [newUserEmail]
            );

            if (existingUser.length > 0) {
                await db_connection.query('UNLOCK TABLES');
                return res.status(403).send({ "message": "User already registered!" });
            }

            // Generate a random password for the manager.
            const memberPassword = passwordGenerator.randomPassword({
                length: 8,
                characters: [passwordGenerator.lower, passwordGenerator.upper, passwordGenerator.digits]
            });


            const passwordHashed = crypto.createHash('sha256').update(memberPassword).digest('hex');

            // Email the password to the user.
            mailer.officialCreated(userName, newUserEmail, memberPassword);

            // Insert the user into the USERDATA table
            await db_connection.query(
                'INSERT INTO USERDATA (profName, email, password, userRole, isActive) VALUES (?, ?, ?, 1, 2)',
                [userName, newUserEmail, passwordHashed]
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

    activateUser: [webTokenValidator, async (req,res)=>{
        let db_connection;

        try {
            const { email } = req.body;

            if (
                email === null ||
                email === undefined ||
                email === "" ||
                !validator.isEmail(req.body.email)
            ) {
                return res.status(404).send({ "message": "Missing details." });
            }

            db_connection = await db.promise().getConnection();

            // Lock the necessary tables to prevent concurrent writes
            await db_connection.query('LOCK TABLES USERDATA WRITE');

            let [existingUser] = await db_connection.query(
                'SELECT * FROM USERDATA WHERE email = ?',
                [email]
            );

            if (existingUser.length == 0) {
                await db_connection.query('UNLOCK TABLES');
                return res.status(403).send({ "message": "User Not Found!" });
            }
            else{
                await db_connection.query('START TRANSACTION')
                const [result] = await db_connection.query('UPDATE userdata SET isActive = ? WHERE email = ?', [1,email]);
                if (result.affectedRows === 1) {
                    // Commit the transaction
                    await db_connection.query('COMMIT');
                    res.status(201).json({ message: 'User activated successfully' });
                } else {
                    // Rollback the transaction
                    await db_connection.query('ROLLBACK');
                    res.status(500).json({ error: 'Failed to activate user' });
                }
            }
        }catch(error){
            if (db_connection) {
                await db_connection.query('ROLLBACK');
            }
            const time = new Date();
            fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - activateUser - ${error}\n`);
            res.status(500).json({ error: 'Failed to activate user' });
        }finally{
            // Unlock the tables
            await db_connection.query('UNLOCK TABLES');
            db_connection.release();
        }
    }],

    fetchUserData: [webTokenValidator, async (req, res) => {
        /*
        query
        {
            "userEmail": "<userEmail>"
        }
        */

        let dbConnection;

        try {
            const { userEmail } = req.query;

            // Validate that userEmail is present
            if (userEmail === undefined) {
                console.error('userEmail is undefined');
                return res.status(400).json({ error: 'userEmail is required' });
            }

            dbConnection = await db.promise().getConnection();

            // Lock the necessary tables to prevent concurrent writes
            await dbConnection.query('LOCK TABLES USERDATA READ');

            const [rows] = await dbConnection.query(
                'SELECT profName, email, userRole, isActive FROM USERDATA WHERE email = ?',
                [userEmail]
            );

            console.log(rows);

            if (rows.length > 0) {
                const userData = rows[0];

                res.status(200).json({ user: userData });
            } else {
                res.status(404).json({ error: 'User not found' });
            }
        } catch (error) {
            console.error(error);
            const time = new Date();
            await fs.promises.appendFile('logs/errorLogs.txt', `${time.toISOString()} - fetchUserData - ${error}\n`);
            res.status(500).json({ error: 'Failed to fetch user data' });
        } finally {
            // Unlock the tables even if an error occurs
            if (dbConnection) {
                await dbConnection.query('UNLOCK TABLES');
                dbConnection.release();
            }
        }
    }],

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
        // console.log(req)
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
            const passwordHashed = crypto.createHash('sha256').update(req.body.password).digest('hex');

            let [user] = await db_connection.query(`SELECT * FROM USERDATA WHERE email = ? AND password = ?`, [req.body.email, passwordHashed]);

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
                        "userRole": user[0].userRole,
                        "email": user[0].email,
                        "profName": user[0].profName,
                    });


                }
                else if (user[0].isActive === "1") {
                    const secret_token = await webTokenGenerator({
                        "userEmail": req.body.email,
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
                    return res.status(403).send({ "message": "Access Restricted." });
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

                const passwordHashed = crypto.createHash('sha256').update(req.body.password).digest('hex');
                await db_connection.query(`UPDATE USERDATA SET password = ?, isActive = '1' WHERE email = ?`, [passwordHashed, req.email]);

                await db_connection.query(`UNLOCK TABLES`);

                const secret_token = await webTokenGenerator({
                    "userEmail": req.email,
                    "userRole": user[0].userRole,
                });


                return res.status(200).send({
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
                return res.status(403).send({ message: "Professor doesn't exist!" });
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

            let [userName] = await db_connection.query(
                `SELECT profName FROM USERDATA WHERE email = ?`,
                [req.body.email]
            );

            const secret_token = await otpTokenGenerator({
                userName: userName,
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
                `SELECT * FROM USERDATA WHERE email = ?`,
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
                return res.status(400).send({ message: "Invalid OTP." });
            }

            await db_connection.query(`UNLOCK TABLES`);

            console.log(professor[0])

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
            req.body.email === null ||
            req.body.email === undefined ||
            req.body.email === "" ||
            !validator.isEmail(req.body.email) ||
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
                `SELECT * FROM USERDATA WHERE email = ?`,
                [req.body.email]
            );

            if (professor.length === 0) {
                await db_connection.query(`UNLOCK TABLES`);
                return res.status(403).send({ message: "Professor doesn't exist!" });
            }

            if (professor[0].isActive === "0") {
                return res.status(401).send({
                    message: "Your Account has been deactivated. Check your email for further instructions.",
                });
            }
            const passwordHashed = crypto.createHash('sha256').update(req.body.newPassword).digest('hex');
            await db_connection.query(
                `UPDATE USERDATA SET password = ? WHERE email = ?`,
                [passwordHashed, req.body.email]
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

    allUserRoles: [webTokenValidator, async (req, res) => {
        let db_connection;

        try {
            db_connection = await db.promise().getConnection();

            // Lock the necessary tables to prevent concurrent writes
            await db_connection.query('LOCK TABLES userdata READ');

            const [rows] = await db_connection.query('SELECT DISTINCT userRole FROM userData WHERE isActive = 1');
            const userRole = rows.map(row => row.userRole);

            res.status(200).json({ userRole: userRole });
        } catch (error) {
            console.error(error);
            const time = new Date();
            fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - api/userRole - ${error}\n`);
            res.status(500).json({ error: 'Failed to fetch userRole' });
        } finally {
            // Unlock the tables
            await db_connection.query('UNLOCK TABLES');
            db_connection?.release();
        }
    }],

    // -----------------------Authentication Operations End-----------------

    // -----------------------Student Operations Start---------------------------


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
                return res.status(400).json({ error: 'Invalid roll number format' });
            }

            await db_connection.query('START TRANSACTION');

            // Fetch userRole based on currentUserEmail
            const [currentUser] = await db_connection.query('SELECT userRole FROM USERDATA WHERE email = ?', [req.userEmail]);

            if (currentUser.length === 0) {
                await db_connection.query('ROLLBACK');
                return res.status(404).json({ error: 'Current user not found' });
            }

            const [StudentPresent] = await db_connection.query('SELECT RollNo FROM StudentData WHERE RollNo=?', [RollNo])
            if (StudentPresent.length != 0) {
                await db_connection.query('ROLLBACK');
                return res.status(500).json({ error: 'Student already present' });
            }

            const currentUserRole = currentUser[0].userRole;

            // Fetch DeptID based on Dept
            const [DeptResult] = await db_connection.query('SELECT * FROM Department WHERE DeptName = ?', [Dept]);

            if (DeptResult.length === 0) {
                await db_connection.query('ROLLBACK');
                return res.status(400).send({ "message": "Department not found!" });
            }

            // Insert data into class table
            const [classResult] = await db_connection.query(
                'SELECT classID from class where batchYear = ? AND DeptID = ? AND Section = ? AND Semester = ?',
                [batchYear, DeptResult[0].DeptID, Section, Semester]
            );
            if (classResult.length == 0) {
                await db_connection.query('ROLLBACK');
                return res.status(400).send({ "message": "Class not found!" });
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
            console.log(RollNo,StdName,batchYear,Section,Semester)

            // Ensure all required fields are defined
            if (!RollNo || !StdName || !batchYear || !Section || !Dept || !Semester || !currentUserEmail) {
                return res.status(400).json({ error: 'All fields are required' });
            }

            // const pattern = /^[A-Z]{2}\.[A-Z]{2}\.[A-Z]{1}[0-9]{1}[A-Z]{3}[0-9]{5}$/;
            // if (!pattern.test(RollNo)) {
            //     return res.status(400).json({ error: 'Invalid roll number format' });
            // }

            // Lock the necessary tables to prevent concurrent writes
            await db_connection.query('LOCK TABLES studentData WRITE, USERDATA READ, class WRITE, ProfessorClass READ, Department READ');
            const [DeptResult] = await db_connection.query('SELECT * FROM Department WHERE DeptName = ?', [Dept]);
            if (DeptResult.length === 0) {
                await db_connection.query('ROLLBACK');
                return res.status(400).send({ "message": "Department not found!" });
            }
            console.log(DeptResult)

            // Fetch userRole based on currentUserEmail
            const [currentUser] = await db_connection.query('SELECT userRole FROM USERDATA WHERE email = ?', [currentUserEmail]);
            if (currentUser.length === 0) {
                await db_connection.query('UNLOCK TABLES');
                return res.status(404).json({ error: 'Current user not found' });
            }

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
              "semester": "<semester>"
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
        let db_connection;

        try {
            const students = req.body;

            db_connection = await db.promise().getConnection();

            // Begin a transaction
            await db_connection.beginTransaction();
            let currentUserEmail = req.userEmail
            for (const student of students) {
                const { RollNo, StdName, batchYear, Dept, Section, Semester } = student;

                // Ensure all required fields are defined
                if (!RollNo || !StdName || !batchYear || !Dept || !Section || !Semester) {
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

                // Fetch courseID based on courseName
                const [courseResult] = await db_connection.query('SELECT courseID FROM course WHERE courseName = ?', [courseName]);

                if (courseResult.length === 0) {
                    await db_connection.rollback();
                    return res.status(400).send({ "message": "Course not found!" });
                }

                // Insert data into class table
                const [classResult] = await db_connection.query(
                    'INSERT INTO class (batchYear, DeptID, Section, courseID, Semester) VALUES (?, ?, ?, ?, ?)',
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
            await fs.promises.appendFile('logs/errorLogs.txt', `${time.toISOString()} - addStudents - ${error}\n`);

            res.status(500).json({ error: 'Failed to add students' });
        } finally {
            // Release the database connection
            if (db_connection) {
                db_connection.release();
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


    // -------------------Student Operations Ends------------------------------

    // -------------------Class Operations Starts------------------------------

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
            `, [batchYear,deptData[0].DeptID,Section,Semester]);
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

            const { batchYear, Dept, Section, Semester} = req.body;

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
            `, [batchYear,deptData[0].DeptID,Section,Semester]);
            console.log(classData)
            if (classData.length === 0) {
                await db_connection.query('ROLLBACK');
                return res.status(404).json({ error: 'Class entered is not present' });
            }
            console.log(currentUserRole)

            // Delete class from class table
            const [classResult] = await db_connection.query(
                'DELETE FROM class WHERE batchYear = ? AND DeptID = ? AND Section = ? AND Semester = ? AND isActive = ?',
                [batchYear, deptData[0].DeptID, Section, Semester,1]
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

    // -------------------Class Operations Ends------------------------------

    // -------------------Slot Operations Starts------------------------------

    createSlot: [webTokenValidator, async (req, res) => {
        // Create a class slot
        /*
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

            const userEmail = req.userEmail;

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

            const cUserRole = userResult[0].userRole;

            if (cUserRole != 0 && cUserRole != 1) {
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

            const userEmail = req.userEmail;
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

            const cUserRole = userResult[0].userRole;

            if (currentUserRole != 0 && currentUserRole != 1) {
                return res.status(403).json({ error: 'Permission denied. Only professors and admins can delete slots.' });
            }

            // Fetch profID based on the email
            const [profData] = await db_connection.query(`
            SELECT profID FROM USERDATA WHERE email = ? AND isActive = '1'
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

            const [active] = await db_connection.query("SELECT * FROM course WHERE courseName = ? AND isActive='0'",[courseName])
            if(active.length==1){
                const [result] = await db_connection.query('UPDATE course SET isActive = ? WHERE courseName = ?', [1,courseName]);
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
            else{
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

            // Lock the necessary tables to prevent concurrent writes
            await db_connection.query('LOCK TABLES course WRITE, userdata READ');

            const userEmail = req.userEmail;
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

    // -------------------Course Operations Ends----------------------------

    // -------------------Department Operations Starts-----------------------

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
            await db_connection.query('LOCK TABLES department WRITE, userdata READ');

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

            const [active] = await db_connection.query("SELECT * FROM Department WHERE DeptName = ? AND isActive='0'",[deptName])
            if(active.length==1){
                const [result] = await db_connection.query('UPDATE department SET isActive = ? WHERE DeptName = ?', [1,deptName]);
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
            else{
                const [result] = await db_connection.query('INSERT INTO department (DeptName, isActive) VALUES (?, ?)', [deptName, 1]);
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
                // Handle the primary key violation error for department names
                return res.status(400).json({ error: 'Department name already exists' });
            }
            // Rollback the transaction in case of an error
            if (db_connection) {
                await db_connection.query('ROLLBACK');
            }
            const time = new Date();
            fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - createDept - ${error}\n`);
            res.status(500).json({ error: 'Failed to create department' });
        } finally {
            // Unlock the tables
            await db_connection.query('UNLOCK TABLES');
            db_connection.release();
        }
    },],

    deleteDept: [webTokenValidator, async (req, res) => {
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
            await db_connection.query('LOCK TABLES department WRITE, userdata READ');

            const userEmail = req.userEmail;
            const deptName = req.body.deptName;

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
                return res.status(403).json({ error: 'Permission denied. Only professors and admins can delete departments.' });
            }

            const [deptData] = await db_connection.query(`
            SELECT DeptID
            FROM department
            WHERE deptName = ? AND isActive = '1'`, [deptName]);

            if (deptData.length === 0) {
                return res.status(404).json({ error: 'Department not found or inactive' });
            }
            const deptID = deptData[0].DeptID;

            // Start a transaction
            await db_connection.query('START TRANSACTION');

            const [result] = await db_connection.query('UPDATE department SET isActive = ? WHERE deptID = ?', [0, deptID]);

            if (result.affectedRows === 1) {
                // Commit the transaction
                await db_connection.query('COMMIT');
                res.json({ message: 'department deleted successfully' });
            } else {
                // Rollback the transaction
                await db_connection.query('ROLLBACK');
                res.status(404).json({ error: 'department not found' });
            }
        } catch (error) {
            console.error(error);
            // Rollback the transaction in case of an error
            if (db_connection) {
                await db_connection.query('ROLLBACK');
            }
            const time = new Date();
            fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - deletedept - ${error}\n`);
            res.status(500).json({ error: 'Failed to delete dept' });
        } finally {
            // Unlock the tables
            await db_connection.query('UNLOCK TABLES');
            db_connection.release();
        }
    },],

    allDepts: [webTokenValidator, async (req, res) => {
        let db_connection;

        try {
            db_connection = await db.promise().getConnection();

            // Lock the necessary tables to prevent concurrent writes
            await db_connection.query('LOCK TABLES department READ');

            const [rows] = await db_connection.query('SELECT deptName FROM department WHERE isActive = ?', [1]);
            const deptNames = rows.map(row => row.deptName);

            res.status(200).json({ depts: deptNames }); // Wrap course names in an object with 'courses' key
        } catch (error) {
            console.error(error);
            const time = new Date();
            fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - api/depts - ${error}\n`);
            res.status(500).json({ error: 'Failed to fetch departments' });
        } finally {
            // Unlock the tables
            await db_connection.query('UNLOCK TABLES');
            db_connection?.release();
        }
    }],
    // -------------------Department Operations Ends-----------------------

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

    // -------------------Many-to-Many Operations Starts------------------------

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

    // -------------------Many-to-Many Operations Ends--------------------------

};