-- Table 1: Course Table
-- isActive: 1 -> Active, 0 -> Deactivated.
CREATE TABLE IF NOT EXISTS course (
    courseID INT AUTO_INCREMENT PRIMARY KEY,
    courseName VARCHAR(255) NOT NULL,
    isActive CHAR(1) NOT NULL DEFAULT '1',
    UNIQUE (courseName)
);
-- Table 2: Users Table
-- userRole: 0 -> professor, 1 -> admin
-- isActive: 1 -> Active, 0 -> Deactivated.
-- attdStatus: 0 -> Absent, 1 -> Present, 2 -> OD, 3 -> ML, 4 -> Other
-- userRole: 0 -> professor, 1 -> admin.
CREATE TABLE IF NOT EXISTS USERDATA (
    profID INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    profName VARCHAR(255) NOT NULL,
    userRole CHAR(1) NOT NULL,
    isActive CHAR(1) NOT NULL DEFAULT '1',
    courseID INT,
    FOREIGN KEY (courseID) REFERENCES course(courseID)
);
-- Table 3: Class Table
CREATE TABLE IF NOT EXISTS class (
    classID INT AUTO_INCREMENT PRIMARY KEY,
    batchYear INT NOT NULL,
    Dept VARCHAR(255) NOT NULL,
    Section VARCHAR(10) NOT NULL,
    courseID INT,
    Semester INT NOT NULL,
    isActive CHAR(1) NOT NULL DEFAULT '1',
    UNIQUE INDEX (classID),
    FOREIGN KEY (courseID) REFERENCES course(courseID)
);
-- Table 4: ProfessorClass Table
CREATE TABLE IF NOT EXISTS ProfessorClass (
    professorID INT,
    classID INT,
    FOREIGN KEY (professorID) REFERENCES USERDATA(profID),
    FOREIGN KEY (classID) REFERENCES class(classID)
);
-- Table 5: Students Table
-- isActive: 1 -> Active, 0 -> Deactivated.
-- Section: A, B, C, D, E, F
-- batchYear: 20XX -> Passing out year
CREATE TABLE IF NOT EXISTS studentData (
    RollNo VARCHAR(20) NOT NULL UNIQUE,
    StdName VARCHAR(255) NOT NULL,
    classID INT,
    isActive CHAR(1) NOT NULL DEFAULT '1',
    FOREIGN KEY (classID) REFERENCES class(classID)
);
-- Table 6: Slots Table
CREATE TABLE IF NOT EXISTS Slots (
    slotID INT AUTO_INCREMENT PRIMARY KEY,
    classID INT,
    periodNo INT NOT NULL,
    isActive CHAR(1) NOT NULL DEFAULT '1',
    FOREIGN KEY (classID) REFERENCES class(classID)
);
-- Table 7: Attendance Table
CREATE TABLE IF NOT EXISTS attendance (
    RollNo VARCHAR(20),
    attdStatus CHAR(1) NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    slotID INT NOT NULL,
    PRIMARY KEY (RollNo, timestamp),
    FOREIGN KEY (RollNo) REFERENCES studentData(RollNo),
    FOREIGN KEY (slotID) REFERENCES Slots(slotID)
);
-- Table 8:: UserRegister Table
-- This will act like a temporary table. Once the student verifies their email, the data will be moved to studentData table.
CREATE TABLE USERREGISTER (
    id INT NOT NULL AUTO_INCREMENT,
    email VARCHAR(255) NOT NULL,
    otp VARCHAR(6) NOT NULL,
    createdAt TIMESTAMP NOT NULL,
    PRIMARY KEY (id)
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