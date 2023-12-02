const { db } = require('../connection')

const webTokenGenerator = require('../middleware/webTokenGenerator');
const webTokenValidator = require('../middleware/webTokenValidator');
const otpTokenGenerator = require('../middleware/otpTokenGenerator');
const [otpTokenValidator] = require('../middleware/otpTokenValidator');

const generateOTP = require("../middleware/otpGenerator");

const crypto = require('crypto');

const mailer = require('../mail/mailer');

const fs = require('fs');
const validator = require('validator');

module.exports = {

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

}