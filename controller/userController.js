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
                        `SELECT u.profName, u.email FROM USERDATA u WHERE u.userRole = '0' AND u.isActive = '1'`,
                    );
                } else if (req.body.reqRole == "1") {
                    // Fetch all administrators
                    [users] = await db_connection.query(
                        `SELECT u.profName, u.email FROM USERDATA u WHERE u.userRole = '1' AND u.isActive = '1'`
                    );

                    console.log(users)
                } else {
                    await db_connection.query('UNLOCK TABLES');
                    db_connection.release();
                    return res.status(401).send({ "message": "Invalid request role!" });
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
            const { profName, email } = req.body;
            console.log(currentUserEmail, profName, email)
            // Lock the necessary tables to prevent concurrent writes
            db_connection = await db.promise().getConnection();
            await db_connection.query('LOCK TABLES USERDATA WRITE');

            const [currentUser] = await db_connection.query('SELECT userRole FROM USERDATA WHERE email = ? and isActive=1', [currentUserEmail]);
            if (currentUser.length === 0) {
                await db_connection.query(`UNLOCK TABLES`);
                return res.status(404).json({ error: 'Current user not found' });
            }

            const currentUserRole = currentUser[0].userRole;

            // Start a transaction
            await db_connection.query('START TRANSACTION');
            try {
                if (currentUserRole === "1") {
                    const [professor] = await db_connection.execute(`SELECT * FROM USERDATA WHERE email = ? AND isActive = 1`, [email]);
                    console.log(professor)
                    if (professor.length == 0) {
                        // Handle the case where no active professor is found with the given email
                        await db_connection.query('ROLLBACK');
                        return res.status(401).json({ error: 'Professor email not found' });
                    }

                    const profID = professor[0].profID;
                    const [result] = await db_connection.query('UPDATE USERDATA SET profName = ? WHERE profID = ?', [profName, profID]);
                    if (result.affectedRows === 1) {
                        // Commit the transaction
                        await db_connection.query('COMMIT');
                        res.json({ message: 'User profile updated successfully' });
                    } else {
                        // Rollback the transaction
                        await db_connection.query('ROLLBACK');
                        res.status(401).json({ error: 'User not found' });
                    }

                } else if (currentUserRole === "0") {
                    // Faculty editing their own profile
                    return res.status(403).json({ error: 'Permission denied. Admins can only edit profile.' });
                } else {
                    // Invalid userRole
                    return res.status(403).json({ error: 'Invalid user role!' });
                }
            } catch (error) {
                console.error(error);

                // Rollback the transaction in case of an error
                await db_connection.query('ROLLBACK');

                const time = new Date();
                fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - editUser - ${error}\n`);

                res.status(405).json({ error: 'Failed to update user profile' });
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

            // Fetch userRole based on the email
            const [userData] = await db_connection.query(`
            SELECT userRole
            FROM USERDATA
            WHERE email = ? AND isActive = '1'
            `, [req.userEmail]);

            if (userData.length === 0) {
                await db_connection.query(`UNLOCK TABLES`);
                return res.status(404).json({ error: 'User not found or inactive' });
            }

            //Check if the delete operation is performed on the same user
            if(req.userEmail == req.body.Email){
                await db_connection.query(`UNLOCK TABLES`);
                return res.status(406).send({ "message": "Admin can't delete himself / herself" });   
            }

            // Check if admin exists
            let [adminToDelete] = await db_connection.query(
                `SELECT * FROM USERDATA WHERE email = ? AND isActive = ? AND userRole = ?`,
                [req.body.Email, "1", "1"]
            );

            if (adminToDelete.length === 0) {
                await db_connection.query(`UNLOCK TABLES`);
                return res.status(401).send({ "message": "Admin doesn't exist!" });
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
                return res.status(401).send({ "message": "Faculty doesn't exist!" });
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
                return res.status(401).send({ "message": "User already registered!" });
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
                return res.status(400).send({ "message": "Missing details." });
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
                return res.status(401).send({ "message": "User already registered!" });
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

    activateUser: [webTokenValidator, async (req, res) => {
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
            else {
                await db_connection.query('START TRANSACTION')
                const [result] = await db_connection.query('UPDATE userdata SET isActive = ? WHERE email = ?', [1, email]);
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
        } catch (error) {
            if (db_connection) {
                await db_connection.query('ROLLBACK');
            }
            const time = new Date();
            fs.appendFileSync('logs/errorLogs.txt', `${time.toISOString()} - activateUser - ${error}\n`);
            res.status(500).json({ error: 'Failed to activate user' });
        } finally {
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

};