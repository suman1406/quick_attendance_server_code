const { db } = require("../connection");
const webTokenValidator = require("../middleware/webTokenValidator");
const fs = require("fs");
const validator = require("validator");

module.exports = {
  returnSlotID: [
    webTokenValidator,
    async (req, res) => {
      /*
            JSON
            {

            }
        */

      let db_connection;

      try {
        db_connection = await db.promise().getConnection();

        // Lock the necessary tables to prevent concurrent writes
        await db_connection.query(
          "LOCK TABLES slots READ, class READ, userdata READ, Department READ, classcourse READ, course READ"
        );

        const userEmail = req.userEmail;

        if (!userEmail || !validator.isEmail(userEmail)) {
          return res.status(400).json({ error: "Invalid user email" });
        }

        // Fetch userRole based on the email
        const [userResult] = await db_connection.query(
          `
            SELECT userRole
            FROM userdata
            WHERE email = ? AND isActive = '1'
            `,
          [userEmail]
        );

        if (userResult.length === 0) {
          return res.status(404).json({ error: "User not found or inactive" });
        }

        const cUserRole = userResult[0].userRole;

        if (cUserRole != 0 && cUserRole != 1) {
          // Unlock the tables
          await db_connection.query("UNLOCK TABLES");
          db_connection.release();
          return res.status(403).json({
            error:
              "Permission denied. Only professors and admins can create class slots.",
          });
        }

        // Start a transaction
        await db_connection.query("START TRANSACTION");

        const { batchYear, Dept, Section, Semester, course, periodNo } =
          req.body;
        console.log(batchYear, Dept, Section, Semester, course, periodNo);
        if (
          batchYear == undefined ||
          Dept == undefined ||
          Section == undefined ||
          Semester == undefined ||
          periodNo == undefined ||
          course == undefined
        ) {
          await db_connection.query("ROLLBACK");
          return res.status(401).json({ error: "Missing parameters" });
        }
        let periods = periodNo.split(",");

        //Check if Dept is available
        const [deptData] = await db_connection.query(
          `
            SELECT DeptID
            FROM department
            WHERE DeptName = ? AND isActive = '1'
            `,
          [Dept]
        );
        console.log(deptData);
        if (deptData.length === 0) {
          await db_connection.query("ROLLBACK");
          return res
            .status(404)
            .json({ error: "Department entered was not found or inactive" });
        }

        //check if class is already present
        const [classData] = await db_connection.query(
          `
            SELECT classID
            FROM class
            WHERE batchYear = ? AND DeptID = ? AND Section = ? AND Semester = ? AND isActive = '1'
            `,
          [batchYear, deptData[0].DeptID, Section, Semester]
        );
        console.log(classData);
        if (classData.length === 0) {
          await db_connection.query("ROLLBACK");
          return res
            .status(404)
            .json({ error: "Class entered is not present" });
        }
        const classID = classData[0].classID;
        console.log(periods);

        //get courseID from course
        const [courseData] = await db_connection.query(
          "SELECT courseID from course WHERE courseName = ?",
          [course]
        );
        const courseID = courseData[0].courseID;
        console.log("#############" + courseID);

        //Check if class has that course
        const [classCourseData] = await db_connection.query(
          "SELECT * FROM classcourse WHERE classID = ? AND courseID = ?",
          [classID, courseID]
        );
        if (classCourseData.length == 0) {
          await db_connection.query("ROLLBACK");
          return res
            .status(501)
            .json({ error: "This class doesn't offer this course" });
        }

        let period;
        console.log(periods);
        let slotIDlist = [];
        // Check if slot is present slots table
        for (period of periods) {
          const [available] = await db_connection.query(
            "SELECT * FROM slots WHERE classID = ? AND periodNo = ?",
            [classID, period]
          );
          console.log(available);
          if (available.length == 0) {
            await db_connection.query("ROLLBACK");
            return res
              .status(500)
              .json({ error: "Period entered does not exist" });
          } else {
            slotIDlist.push(available[0].slotID);
          }
        }
        return res.status(200).json({ SlotIDs: slotIDlist });
      } catch (error) {
        if (db_connection) {
          await db_connection.query("ROLLBACK");
        }
        const time = new Date();
        fs.appendFileSync(
          "logs/errorLogs.txt",
          `${time.toISOString()} - SlotID returned - ${error}\n`
        );
        res.status(500).json({ error: "Failed to return SlotID" });
      } finally {
        // Unlock the tables
        await db_connection.query("UNLOCK TABLES");
        db_connection.release();
      }
    },
  ],

  addAttendance: [
    webTokenValidator,
    async (req, res) => {
      /*
            JSON
            {
                "RollNo": "<RollNo>",
                "timestamp": "<timestamp>",
                "slotID: [<slot id>,..]",
                "courseName": "<courseName>"
            }
        */

      let db_connection;

      try {
        db_connection = await db.promise().getConnection();

        // Lock the necessary tables to prevent concurrent writes
        await db_connection.query(
          "LOCK TABLES attendance WRITE, userdata READ, course READ"
        );

        const userEmail = req.userEmail;

        if (!userEmail || !validator.isEmail(userEmail)) {
          return res.status(400).json({ error: "Invalid user email" });
        }

        // Fetch userRole based on the email
        const [userResult] = await db_connection.query(
          `
            SELECT *
            FROM userdata
            WHERE email = ? AND isActive = '1'
            `,
          [userEmail]
        );

        if (userResult.length === 0) {
          return res.status(404).json({ error: "User not found or inactive" });
        }

        const cUserRole = userResult[0].userRole;

        if (cUserRole != 0 && cUserRole != 1) {
          // Unlock the tables
          await db_connection.query("UNLOCK TABLES");
          db_connection.release();
          return res.status(403).json({
            error:
              "Permission denied. Only professors and admins can create class slots.",
          });
        }

        // Start a transaction
        await db_connection.query("START TRANSACTION");

        const { RollNo, date, SlotIDs, courseName } = req.body;

        //Check if student is present
        const [stuData] = await db_connection.query(
          "SELECT * FROM StudentData WHERE RollNo = ?",
          [RollNo]
        );
        if (stuData.length == 0) {
          // Rollback the transaction
          await db_connection.query("ROLLBACK");
          return res.status(500).json({ error: "Student Doesnt Exist" });
        }

        //get courseID from course
        const [courseData] = await db_connection.query(
          "SELECT courseID from course WHERE courseName = ?",
          [courseName]
        );
        console.log(courseData);
        const courseID = courseData[0].courseID;

        let addedAttd = 0;
        let slot;
        for (slot of SlotIDs) {
          console.log(slot);
          const [result] = await db_connection.query(
            "INSERT INTO attendance (RollNo, attdStatus, AttDateTime, slotID, courseID) VALUES (?, ?, ?,?, ?)",
            [RollNo, 1, date, slot, courseID]
          );
          if (result.affectedRows === 1) {
            addedAttd += 1;
            // Commit the transaction
            await db_connection.query("COMMIT");
          } else {
            // Rollback the transaction
            await db_connection.query("ROLLBACK");
            return res
              .status(500)
              .json({ error: "Failed to record attendance" });
          }
        }
        if (addedAttd == SlotIDs.length) {
          // Commit the transaction
          await db_connection.query("COMMIT");
        }
        return res
          .status(201)
          .json({ message: "Attendance recorded successfully" });
      } catch (error) {
        console.error(error);
        // Rollback the transaction in case of an error
        if (db_connection) {
          await db_connection.query("ROLLBACK");
        }
        fs.appendFileSync(
          "logs/errorLogs.txt",
          `${time.toISOString()} - addAttendance - ${error}\n`
        );
        res.status(500).json({ error: "Failed to record attendance" });
      } finally {
        // Unlock the tables
        await db_connection.query("UNLOCK TABLES");
        db_connection.release();
      }
    },
  ],

  getAttendanceForSlot: [
    webTokenValidator,
    async (req, res) => {
      /*
            queries {
                slotID: <slot id>
                courseName: <courseName>
                date: <date>
            }
        */

      let db_connection;

      try {
        db_connection = await db.promise().getConnection();

        // Lock the necessary tables to prevent concurrent writes
        await db_connection.query(
          "LOCK TABLES attendance READ, userdata READ, course READ"
        );

        const userEmail = req.userEmail;

        if (!userEmail || !validator.isEmail(userEmail)) {
          return res.status(400).json({ error: "Invalid user email" });
        }

        // Fetch userRole based on the email
        const [userResult] = await db_connection.query(
          `
            SELECT *
            FROM userdata
            WHERE email = ? AND isActive = '1'
            `,
          [userEmail]
        );

        if (userResult.length === 0) {
          return res.status(404).json({ error: "User not found or inactive" });
        }

        const cUserRole = userResult[0].userRole;

        if (cUserRole != 0 && cUserRole != 1) {
          // Unlock the tables
          await db_connection.query("UNLOCK TABLES");
          db_connection.release();
          return res.status(403).json({
            error:
              "Permission denied. Only professors and admins can create class slots.",
          });
        }

        // Start a transaction
        await db_connection.query("START TRANSACTION");

        const { date, slotID, courseName } = req.query;
        console.log(date, slotID, courseName);

        //get courseID from course
        const [courseData] = await db_connection.query(
          "SELECT courseID from course WHERE courseName = ?",
          [courseName]
        );
        console.log(courseData);
        const courseID = courseData[0].courseID;

        const [AttdData] = await db_connection.query(
          "SELECT RollNo, AttDateTime , attdStatus from Attendance WHERE courseID = ? AND slotID = ? AND DATE(AttDateTime) = ? ORDER BY RollNo, AttDateTime",
          [courseID, slotID, date]
        );
        console.log(AttdData);
        if (AttdData.length > 0) {
          db_connection.query("COMMIT");
          res.status(200).json(AttdData);
        } else {
          db_connection.query("ROLLBACK");
          res.status(501).json({ msg: "No students Present" });
        }
      } catch (error) {
        console.error(error);
        // Rollback the transaction in case of an error
        if (db_connection) {
          await db_connection.query("ROLLBACK");
        }
        fs.appendFileSync(
          "logs/errorLogs.txt",
          `${time.toISOString()} - getAttendanceForSlot - ${error}\n`
        );
        res.status(500).json({ error: "Failed to fetch attendance" });
      } finally {
        // Unlock the tables
        await db_connection.query("UNLOCK TABLES");
        db_connection.release();
      }
    },
  ],

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
      await db_connection.query("LOCK TABLES attendance WRITE");

      // Start a transaction
      await db_connection.query("START TRANSACTION");

      const { RollNo, timestamp, attdStatus } = req.body;

      // Validate attdStatus
      const validStatusValues = ["0", "1", "2", "3", "4"];
      if (!validStatusValues.includes(attdStatus)) {
        return res
          .status(400)
          .json({ error: "Invalid attendance status value" });
      }

      const [result] = await db_connection.query(
        "UPDATE attendance SET attdStatus = ? WHERE RollNo = ? AND timestamp = ?",
        [attdStatus, RollNo, timestamp]
      );

      if (result.affectedRows === 1) {
        // Commit the transaction
        await db_connection.query("COMMIT");
        res.json({ message: "Attendance status updated successfully" });
      } else {
        // Rollback the transaction
        await db_connection.query("ROLLBACK");
        res.status(404).json({ error: "Attendance record not found" });
      }
    } catch (error) {
      console.error(error);
      // Rollback the transaction in case of an error
      if (db_connection) {
        await db_connection.query("ROLLBACK");
      }
      fs.appendFileSync(
        "logs/errorLogs.txt",
        `${time.toISOString()} - updateAttendanceStatus - ${error}\n`
      );
      res.status(500).json({ error: "Failed to update attendance status" });
    } finally {
      // Unlock the tables
      await db_connection.query("UNLOCK TABLES");
      db_connection.release();
    }
  },

  getAttendanceForCourse: [
    webTokenValidator,
    async (req, res) => {
      let db_connection;
      try {
        db_connection = await db.promise().getConnection();

        // Lock the necessary tables to prevent concurrent writes
        await db_connection.query(
          "LOCK TABLES attendance READ, userdata READ, course READ,slots READ, class READ, department READ"
        );

        const userEmail = req.userEmail;

        if (!userEmail || !validator.isEmail(userEmail)) {
          return res.status(400).json({ error: "Invalid user email" });
        }

        // Fetch userRole based on the email
        const [userResult] = await db_connection.query(
          `
            SELECT *
            FROM userdata
            WHERE email = ? AND isActive = '1'
            `,
          [userEmail]
        );

        if (userResult.length === 0) {
          return res.status(404).json({ error: "User not found or inactive" });
        }

        const cUserRole = userResult[0].userRole;

        if (cUserRole != 0 && cUserRole != 1) {
          // Unlock the tables
          await db_connection.query("UNLOCK TABLES");
          db_connection.release();
          return res.status(403).json({
            error:
              "Permission denied. Only professors and admins can create class slots.",
          });
        }

        // Start a transaction
        await db_connection.query("START TRANSACTION");

        const { batchYear, Semester, Section, Dept, courseName } = req.body;

        //Check if Dept is available
        const [deptData] = await db_connection.query(
          `
            SELECT DeptID
            FROM department
            WHERE DeptName = ? AND isActive = '1'
            `,
          [Dept]
        );
        console.log(deptData);
        if (deptData.length === 0) {
          await db_connection.query("ROLLBACK");
          return res
            .status(404)
            .json({ error: "Department entered was not found or inactive" });
        }

        //check if class is already present
        const [classData] = await db_connection.query(
          `
            SELECT classID
            FROM class
            WHERE batchYear = ? AND DeptID = ? AND Section = ? AND Semester = ? AND isActive = '1'
            `,
          [batchYear, deptData[0].DeptID, Section, Semester]
        );
        console.log(classData);
        if (classData.length === 0) {
          await db_connection.query("ROLLBACK");
          return res
            .status(404)
            .json({ error: "Class entered is not present" });
        }
        const classID = classData[0].classID;

        const [courseAvai] = await db_connection.query(
          "SELECT courseID FROM Course WHERE courseName = ?",
          [courseName]
        );
        console.log(courseAvai);
        if (courseAvai.length === 0) {
          await db_connection.query("ROLLBACK");
          return res
            .status(404)
            .json({ error: "Course entered is not present" });
        }

        const [attendanceOfCourse] = await db_connection.query(
          `SELECT a.RollNo, sd.StdName, a.AttDateTime, a.slotID
          FROM attendance a
          JOIN studentdata sd ON a.RollNo = sd.RollNo
          WHERE a.slotID IN (SELECT slotID FROM slots WHERE classID = ?) 
          AND a.courseID = ?
          GROUP BY a.RollNo, sd.StdName, a.AttDateTime
          ORDER BY a.AttDateTime`,
          [classID, courseAvai[0].courseID]
        );
        console.log(attendanceOfCourse);

        return res.status(200).json(attendanceOfCourse);
      } catch (error) {
        console.error(error);
        // Rollback the transaction in case of an error
        if (db_connection) {
          await db_connection.query("ROLLBACK");
        }
        const time = new Date();
        fs.appendFileSync(
          "logs/errorLogs.txt",
          `${time.toISOString()} - getAttCourse - ${error}\n`
        );
        res.status(500).json({ error: "Failed to retrive attd" });
      } finally {
        // Unlock the tables
        await db_connection.query("UNLOCK TABLES");
        db_connection.release();
      }
    },
  ],
};
