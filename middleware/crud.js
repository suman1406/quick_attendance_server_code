// Import necessary modules and dependencies
const { db } = require('../connection');
const validator = require('validator');
const crypto = require('crypto');
const passwordGenerator = require('secure-random-password');
const fs = require('fs');
const mailer = require('../mail/mailer');

const deleteMember = async (req, res) => {
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
};

module.exports = deleteMember;