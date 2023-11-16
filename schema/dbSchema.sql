-- Table 1: Professors Table
-- userRole: 0 -> professor, 1 -> admin
-- isActive: 1 -> Active, 0 -> Deactivated.
-- attdStatus: 0 -> Absent, 1 -> Present, 2 -> OD, 3 -> ML, 4 -> Other
-- Table 1: Professors Table
-- userRole: 0 -> professor, 1 -> admin.
CREATE TABLE USERDATA (
    profID INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    profName VARCHAR(255) NOT NULL,
    userRole CHAR(1) NOT NULL,
    isActive CHAR(1) NOT NULL DEFAULT '1'
);
-- This will act like a temporary table. Once the student verifies their email, the data will be moved to studentData table.
CREATE TABLE USERREGISTER (
    id INT NOT NULL AUTO_INCREMENT,
    email VARCHAR(255) NOT NULL,
    otp VARCHAR(6) NOT NULL,
    createdAt TIMESTAMP NOT NULL,
    PRIMARY KEY (id)
);
-- Table 2: Students Table
-- isActive: 1 -> Active, 0 -> Deactivated.
-- Section: A, B, C, D, E, F
-- batchYear: 20XX -> Passing out year
CREATE TABLE studentData (
    StdID INT AUTO_INCREMENT PRIMARY KEY,
    RollNo VARCHAR(20) NOT NULL UNIQUE,
    StdName VARCHAR(255) NOT NULL,
    batchYear INT NOT NULL,
    Dept VARCHAR(255) NOT NULL,
    Section VARCHAR(10) NOT NULL,
    isActive CHAR(1) NOT NULL DEFAULT '1'
);
-- Table 3: Class Table
CREATE TABLE class (
    classID INT AUTO_INCREMENT PRIMARY KEY,
    batchYear INT NOT NULL,
    Dept VARCHAR(255) NOT NULL,
    Section VARCHAR(10) NOT NULL,
    profID INT,
    Semester INT NOT NULL,
    FOREIGN KEY (profID) REFERENCES USERDATA(profID),
    FOREIGN KEY (batchYear) REFERENCES studentData(batchYear),
    FOREIGN KEY (Dept) REFERENCES studentData(Dept),
    FOREIGN KEY (Section) REFERENCES studentData(Section)
);
-- Table 4
CREATE TABLE Slots (
    slotID INT AUTO_INCREMENT PRIMARY KEY,
    classID INT,
    periodNo INT NOT NULL,
    FOREIGN KEY (classID) REFERENCES class(classID)
);
-- Table 5
CREATE TABLE attendance (
    StdID INT,
    attdStatus VARCHAR(20) NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    slotID INT NOT NULL,
    PRIMARY KEY (StdID, timestamp),
    FOREIGN KEY (StdID) REFERENCES studentData(StdID),
    FOREIGN KEY (slotID) REFERENCES Slots(slotID)
);
/*
 1. Login
 
 Admin Functions
 2. addFaculty => create new faculty member
 3. editFaculty => edit existing faculty details
 4. deleteFaculty => set faculty isActive Status to 0
 5. allFaculty => show all faculty
 
 Faculty Functions --> accessible by admin also
 6. addStudent
 7. editStudent
 8. deleteStudent => set student isActive Status to 0
 9. allStudents => Filter by class
 10. addStudents
 11. resetPassword
 12. createClass
 13. myClasses => faculty's classes
 14. deleteClass
 15. createSlots
 16. getAttendanceReport
 17. markAttendance
 
 */