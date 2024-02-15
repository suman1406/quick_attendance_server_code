DROP DATABASE IF EXISTS quick_attendance;
CREATE DATABASE quick_attendance;
USE quick_attendance;
DROP TABLE IF EXISTS USERDATA;
DROP TABLE IF EXISTS studentData;
DROP TABLE IF EXISTS class;
DROP TABLE IF EXISTS Slots;
DROP TABLE IF EXISTS attendance;
DROP TABLE IF EXISTS userregister;
-- Create the course table
CREATE TABLE IF NOT EXISTS course (
    courseID INT AUTO_INCREMENT PRIMARY KEY,
    courseName VARCHAR(255) NOT NULL,
    isActive CHAR(1) NOT NULL DEFAULT '1',
    UNIQUE (courseName)
);

CREATE TABLE IF NOT EXISTS Department (
    DeptID INT AUTO_INCREMENT PRIMARY KEY,
    DeptName VARCHAR(255) NOT NULL,
    isActive CHAR(1) NOT NULL DEFAULT '1',
    UNIQUE (DeptName)
);

CREATE TABLE IF NOT EXISTS USERDATA (
    profID INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    profName VARCHAR(255) NOT NULL,
    userRole CHAR(1) NOT NULL,
    isActive CHAR(1) NOT NULL DEFAULT '2'
);

CREATE TABLE IF NOT EXISTS class (
    classID INT AUTO_INCREMENT PRIMARY KEY,
    batchYear INT NOT NULL,
    DeptID INT NOT NULL,
    Section VARCHAR(10) NOT NULL,
    Semester INT NOT NULL,
    isActive CHAR(1) NOT NULL DEFAULT '1',
    UNIQUE INDEX (classID),
    FOREIGN KEY (DeptID) REFERENCES Department(DeptID)
);

CREATE TABLE IF NOT EXISTS ProfessorClass (
    professorID INT,
    classID INT,
    FOREIGN KEY (professorID) REFERENCES USERDATA(profID),
    FOREIGN KEY (classID) REFERENCES class(classID)
);

CREATE TABLE IF NOT EXISTS ProfCourse (
    professorID INT,
    courseID INT,
    FOREIGN KEY (professorID) REFERENCES USERDATA(profID),
    FOREIGN KEY (courseID) REFERENCES course(courseID)
);

CREATE TABLE IF NOT EXISTS ClassCourse (
    courseID INT,
    classID INT,
    FOREIGN KEY (courseID) REFERENCES course(courseID),
    FOREIGN KEY (classID) REFERENCES class(classID)
);

CREATE TABLE IF NOT EXISTS studentData (
    RollNo VARCHAR(20) PRIMARY KEY,
    StdName VARCHAR(255) NOT NULL,
    classID INT,
    isActive CHAR(1) NOT NULL DEFAULT '1',
    FOREIGN KEY (classID) REFERENCES class(classID)
);

CREATE TABLE IF NOT EXISTS Slots (
    slotID INT AUTO_INCREMENT PRIMARY KEY,
    classID INT,
    periodNo INT NOT NULL,
    isActive CHAR(1) NOT NULL DEFAULT '1',
    FOREIGN KEY (classID) REFERENCES class(classID)
);

CREATE TABLE IF NOT EXISTS attendance (
    RollNo VARCHAR(20),
    attdStatus CHAR(1) NOT NULL,
    AttDateTime TIMESTAMP NOT NULL,
    slotID INT NOT NULL,
    courseID INT NOT NULL,
    PRIMARY KEY (RollNo, AttDateTime,slotID),
    FOREIGN KEY (RollNo) REFERENCES studentData(RollNo),
    FOREIGN KEY (slotID) REFERENCES Slots(slotID),
    FOREIGN KEY (courseID) REFERENCES course(courseID)
);

CREATE TABLE IF NOT EXISTS USERREGISTER (
    id INT NOT NULL AUTO_INCREMENT,
    email VARCHAR(255) NOT NULL,
    otp VARCHAR(6) NOT NULL,
    createdAt TIMESTAMP NOT NULL,
    PRIMARY KEY (id)
);


INSERT INTO course (courseName) VALUES ('Mathematics');
INSERT INTO course (courseName) VALUES ('Social Studies');
INSERT INTO course (courseName) VALUES ('Data Structures and Algorithms');
INSERT INTO course (courseName) VALUES ('Computer Architecture');
INSERT INTO course (courseName) VALUES ('Physics');
INSERT INTO course (courseName) VALUES ('Chemistry');
INSERT INTO course (courseName) VALUES ('Biology');
INSERT INTO course (courseName) VALUES ('History');
INSERT INTO course (courseName) VALUES ('Geography');
INSERT INTO course (courseName) VALUES ('Computer Science');
INSERT INTO course (courseName) VALUES ('Artificial Intelligence');
INSERT INTO course (courseName) VALUES ('Economics');
INSERT INTO course (courseName) VALUES ('Psychology');
INSERT INTO course (courseName) VALUES ('Sociology');
INSERT INTO course (courseName) VALUES ('Political Science');
INSERT INTO course (courseName) VALUES ('Environmental Science');
INSERT INTO course (courseName) VALUES ('English Literature');
INSERT INTO course (courseName) VALUES ('Digital Marketing');
INSERT INTO course (courseName) VALUES ('Finance');
INSERT INTO course (courseName) VALUES ('Human Resource Management');


INSERT INTO Department (DeptName) VALUES ('Computer Science');
INSERT INTO Department (DeptName) VALUES ('Electrical Engineering');
INSERT INTO Department (DeptName) VALUES ('Mechanical Engineering');
INSERT INTO Department (DeptName) VALUES ('Civil Engineering');
INSERT INTO Department (DeptName) VALUES ('Chemical Engineering');
INSERT INTO Department (DeptName) VALUES ('Biomedical Engineering');
INSERT INTO Department (DeptName) VALUES ('Aerospace Engineering');
INSERT INTO Department (DeptName) VALUES ('Industrial Engineering');
INSERT INTO Department (DeptName) VALUES ('Software Engineering');
INSERT INTO Department (DeptName) VALUES ('Data Science');
INSERT INTO Department (DeptName) VALUES ('Information Technology');
INSERT INTO Department (DeptName) VALUES ('Computer Engineering');
INSERT INTO Department (DeptName) VALUES ('Environmental Engineering');
INSERT INTO Department (DeptName) VALUES ('Petroleum Engineering');
INSERT INTO Department (DeptName) VALUES ('Materials Science');
INSERT INTO Department (DeptName) VALUES ('Nuclear Engineering');
INSERT INTO Department (DeptName) VALUES ('Robotics');
INSERT INTO Department (DeptName) VALUES ('Biotechnology');
INSERT INTO Department (DeptName) VALUES ('Telecommunication Engineering');

INSERT INTO USERDATA (email, password, profName, userRole) VALUES
('thanuskumaara@gmail.com','2a27ad2744e860e4dcf47b191a2afb795abc2bc800a8833f73d90f50ffa69383','Thanus Kumaar','1'),
('psuman1406@gmail.com', '735701f285cb9253fcff9649a0f7a09f27e5b5967030ded8baba4c5731683636', 'P Suman', '1'),
('kalyanguru18@gmail.com', '15e2b0d3c33891ebb0f1ef609ec419420c20e320ce94c65fbc8c3312448eb225', 'Kalyan', '0'),
('prof2@example.com', 'password2', 'Professor 2', '0'),
('prof3@example.com', 'password3', 'Professor 3', '0'),
('staff1@example.com', 'password4', 'Staff 1', '0'),
('staff2@example.com', 'password5', 'Staff 2', '0'),
('student1@example.com', 'password6', 'Student 1', '0'),
('student2@example.com', 'password7', 'Student 2', '0'),
('student3@example.com', 'password8', 'Student 3', '0'),
('admin@example.com', 'adminpass', 'Administrator', '1'),
('guest@example.com', 'guestpass', 'Guest', '0'),
('demo@example.com', 'demopass', 'Demo User', '0'),
('test@example.com', 'testpass', 'Test User', '0'),
('teacher1@example.com', 'teacherpass1', 'Teacher 1', '0'),
('teacher2@example.com', 'teacherpass2', 'Teacher 2', '0'),
('teacher3@example.com', 'teacherpass3', 'Teacher 3', '0'),
('teacher4@example.com', 'teacherpass4', 'Teacher 4', '0'),
('teacher5@example.com', 'teacherpass5', 'Teacher 5', '0'),
('teacher6@example.com', 'teacherpass6', 'Teacher 6', '1'),
('teacher7@example.com', 'teacherpass7', 'Teacher 7', '1'),
('teacher8@example.com', 'teacherpass8', 'Teacher 8', '1'),
('teacher9@example.com', 'teacherpass9', 'Teacher 9', '1'),
('teacher10@example.com', 'teacherpass10', 'Teacher 10', '1');



INSERT INTO class (batchYear, DeptID, Section, Semester) VALUES (2022, 1, 'A', 1);
INSERT INTO class (batchYear, DeptID, Section, Semester) VALUES (2022, 2, 'B', 1);
INSERT INTO class (batchYear, DeptID, Section, Semester) VALUES (2023, 3, 'C', 1);
INSERT INTO class (batchYear, DeptID, Section, Semester) VALUES (2023, 1, 'A', 2);
INSERT INTO class (batchYear, DeptID, Section, Semester) VALUES (2024, 2, 'B', 2);
INSERT INTO class (batchYear, DeptID, Section, Semester) VALUES (2024, 3, 'C', 2);
INSERT INTO class (batchYear, DeptID, Section, Semester) VALUES (2025, 1, 'A', 3);
INSERT INTO class (batchYear, DeptID, Section, Semester) VALUES (2025, 2, 'B', 3);
INSERT INTO class (batchYear, DeptID, Section, Semester) VALUES (2026, 3, 'C', 3);
INSERT INTO class (batchYear, DeptID, Section, Semester) VALUES (2026, 1, 'A', 4);
INSERT INTO class (batchYear, DeptID, Section, Semester) VALUES (2027, 2, 'B', 4);
INSERT INTO class (batchYear, DeptID, Section, Semester) VALUES (2027, 3, 'C', 4);
INSERT INTO class (batchYear, DeptID, Section, Semester) VALUES (2028, 1, 'A', 5);
INSERT INTO class (batchYear, DeptID, Section, Semester) VALUES (2028, 2, 'B', 5);
INSERT INTO class (batchYear, DeptID, Section, Semester) VALUES (2029, 3, 'C', 5);
INSERT INTO class (batchYear, DeptID, Section, Semester) VALUES (2029, 1, 'A', 6);
INSERT INTO class (batchYear, DeptID, Section, Semester) VALUES (2030, 2, 'B', 6);
INSERT INTO class (batchYear, DeptID, Section, Semester) VALUES (2030, 3, 'C', 6);
INSERT INTO class (batchYear, DeptID, Section, Semester) VALUES (2031, 1, 'A', 7);
INSERT INTO class (batchYear, DeptID, Section, Semester) VALUES (2031, 2, 'B', 7);


INSERT INTO ProfessorClass (professorID, classID) VALUES (1, 1);
INSERT INTO ProfessorClass (professorID, classID) VALUES (2, 2);
INSERT INTO ProfessorClass (professorID, classID) VALUES (3, 3);
INSERT INTO ProfessorClass (professorID, classID) VALUES (4, 4);
INSERT INTO ProfessorClass (professorID, classID) VALUES (5, 5);
INSERT INTO ProfessorClass (professorID, classID) VALUES (6, 6);
INSERT INTO ProfessorClass (professorID, classID) VALUES (7, 7);
INSERT INTO ProfessorClass (professorID, classID) VALUES (8, 8);
INSERT INTO ProfessorClass (professorID, classID) VALUES (9, 9);
INSERT INTO ProfessorClass (professorID, classID) VALUES (10, 10);
INSERT INTO ProfessorClass (professorID, classID) VALUES (11, 11);
INSERT INTO ProfessorClass (professorID, classID) VALUES (12, 12);
INSERT INTO ProfessorClass (professorID, classID) VALUES (13, 13);
INSERT INTO ProfessorClass (professorID, classID) VALUES (14, 14);
INSERT INTO ProfessorClass (professorID, classID) VALUES (15, 15);
INSERT INTO ProfessorClass (professorID, classID) VALUES (16, 16);
INSERT INTO ProfessorClass (professorID, classID) VALUES (17, 17);
INSERT INTO ProfessorClass (professorID, classID) VALUES (18, 18);
INSERT INTO ProfessorClass (professorID, classID) VALUES (19, 19);
INSERT INTO ProfessorClass (professorID, classID) VALUES (20, 20);


INSERT INTO ProfCourse (professorID, courseID) VALUES (1, 1);
INSERT INTO ProfCourse (professorID, courseID) VALUES (2, 2);
INSERT INTO ProfCourse (professorID, courseID) VALUES (3, 3);
INSERT INTO ProfCourse (professorID, courseID) VALUES (4, 4);
INSERT INTO ProfCourse (professorID, courseID) VALUES (5, 5);
INSERT INTO ProfCourse (professorID, courseID) VALUES (6, 6);
INSERT INTO ProfCourse (professorID, courseID) VALUES (7, 7);
INSERT INTO ProfCourse (professorID, courseID) VALUES (8, 8);
INSERT INTO ProfCourse (professorID, courseID) VALUES (9, 9);
INSERT INTO ProfCourse (professorID, courseID) VALUES (10, 10);
INSERT INTO ProfCourse (professorID, courseID) VALUES (11, 11);
INSERT INTO ProfCourse (professorID, courseID) VALUES (12, 12);
INSERT INTO ProfCourse (professorID, courseID) VALUES (13, 13);
INSERT INTO ProfCourse (professorID, courseID) VALUES (14, 14);
INSERT INTO ProfCourse (professorID, courseID) VALUES (15, 15);
INSERT INTO ProfCourse (professorID, courseID) VALUES (16, 16);
INSERT INTO ProfCourse (professorID, courseID) VALUES (17, 17);
INSERT INTO ProfCourse (professorID, courseID) VALUES (18, 18);
INSERT INTO ProfCourse (professorID, courseID) VALUES (19, 19);
INSERT INTO ProfCourse (professorID, courseID) VALUES (20, 20);


-- Insert Statements for the `ClassCourse` Table
INSERT INTO ClassCourse (courseID, classID) VALUES (1, 1);
INSERT INTO ClassCourse (courseID, classID) VALUES (2, 2);
INSERT INTO ClassCourse (courseID, classID) VALUES (3, 3);
INSERT INTO ClassCourse (courseID, classID) VALUES (4, 4);
INSERT INTO ClassCourse (courseID, classID) VALUES (5, 5);
INSERT INTO ClassCourse (courseID, classID) VALUES (6, 1);
INSERT INTO ClassCourse (courseID, classID) VALUES (7, 2);
INSERT INTO ClassCourse (courseID, classID) VALUES (8, 3);
INSERT INTO ClassCourse (courseID, classID) VALUES (9, 4);
INSERT INTO ClassCourse (courseID, classID) VALUES (10, 5);
INSERT INTO ClassCourse (courseID, classID) VALUES (11, 1);
INSERT INTO ClassCourse (courseID, classID) VALUES (12, 2);
INSERT INTO ClassCourse (courseID, classID) VALUES (13, 3);
INSERT INTO ClassCourse (courseID, classID) VALUES (14, 4);
INSERT INTO ClassCourse (courseID, classID) VALUES (15, 5);
INSERT INTO ClassCourse (courseID, classID) VALUES (16, 1);
INSERT INTO ClassCourse (courseID, classID) VALUES (17, 2);
INSERT INTO ClassCourse (courseID, classID) VALUES (18, 3);
INSERT INTO ClassCourse (courseID, classID) VALUES (19, 4);
INSERT INTO ClassCourse (courseID, classID) VALUES (20, 5);


-- Insert Statements for the `studentData` Table
INSERT INTO studentData (RollNo, StdName, classID) VALUES ('A001', 'Student 1', 1);
INSERT INTO studentData (RollNo, StdName, classID) VALUES ('A002', 'Student 2', 2);
INSERT INTO studentData (RollNo, StdName, classID) VALUES ('A003', 'Student 3', 3);
INSERT INTO studentData (RollNo, StdName, classID) VALUES ('A004', 'Student 4', 4);
INSERT INTO studentData (RollNo, StdName, classID) VALUES ('A005', 'Student 5', 5);
INSERT INTO studentData (RollNo, StdName, classID) VALUES ('A006', 'Student 6', 1);
INSERT INTO studentData (RollNo, StdName, classID) VALUES ('A007', 'Student 7', 2);
INSERT INTO studentData (RollNo, StdName, classID) VALUES ('A008', 'Student 8', 3);
INSERT INTO studentData (RollNo, StdName, classID) VALUES ('A009', 'Student 9', 4);
INSERT INTO studentData (RollNo, StdName, classID) VALUES ('A010', 'Student 10', 5);
INSERT INTO studentData (RollNo, StdName, classID) VALUES ('A011', 'Student 11', 1);
INSERT INTO studentData (RollNo, StdName, classID) VALUES ('A012', 'Student 12', 2);
INSERT INTO studentData (RollNo, StdName, classID) VALUES ('A013', 'Student 13', 3);
INSERT INTO studentData (RollNo, StdName, classID) VALUES ('A014', 'Student 14', 4);
INSERT INTO studentData (RollNo, StdName, classID) VALUES ('A015', 'Student 15', 5);
INSERT INTO studentData (RollNo, StdName, classID) VALUES ('A016', 'Student 16', 1);
INSERT INTO studentData (RollNo, StdName, classID) VALUES ('A017', 'Student 17', 2);
INSERT INTO studentData (RollNo, StdName, classID) VALUES ('A018', 'Student 18', 3);
INSERT INTO studentData (RollNo, StdName, classID) VALUES ('A019', 'Student 19', 4);
INSERT INTO studentData (RollNo, StdName, classID) VALUES ('A020', 'Student 20', 5);


-- Insert Statements for the `Slots` Table
INSERT INTO Slots (classID, periodNo) VALUES (1, 1);
INSERT INTO Slots (classID, periodNo) VALUES (2, 2);
INSERT INTO Slots (classID, periodNo) VALUES (3, 3);
INSERT INTO Slots (classID, periodNo) VALUES (4, 4);
INSERT INTO Slots (classID, periodNo) VALUES (5, 5);
INSERT INTO Slots (classID, periodNo) VALUES (1, 2);
INSERT INTO Slots (classID, periodNo) VALUES (2, 3);
INSERT INTO Slots (classID, periodNo) VALUES (3, 4);
INSERT INTO Slots (classID, periodNo) VALUES (4, 5);
INSERT INTO Slots (classID, periodNo) VALUES (5, 1);
INSERT INTO Slots (classID, periodNo) VALUES (1, 3);
INSERT INTO Slots (classID, periodNo) VALUES (2, 4);
INSERT INTO Slots (classID, periodNo) VALUES (3, 5);
INSERT INTO Slots (classID, periodNo) VALUES (4, 1);
INSERT INTO Slots (classID, periodNo) VALUES (5, 2);
INSERT INTO Slots (classID, periodNo) VALUES (1, 4);
INSERT INTO Slots (classID, periodNo) VALUES (2, 5);
INSERT INTO Slots (classID, periodNo) VALUES (3, 1);
INSERT INTO Slots (classID, periodNo) VALUES (4, 2);
INSERT INTO Slots (classID, periodNo) VALUES (5, 3);


-- Insert Statements for the `attendance` Table
INSERT INTO attendance (RollNo, attdStatus, AttDateTime, slotID, courseID) VALUES ('A001', '1', '2023-01-01 08:00:00', 1,1);
INSERT INTO attendance (RollNo, attdStatus, AttDateTime, slotID, courseID) VALUES ('A002', '0', '2023-01-01 08:00:00', 2,1);
INSERT INTO attendance (RollNo, attdStatus, AttDateTime, slotID, courseID) VALUES ('A003', '1', '2023-01-01 08:00:00', 3,1);
INSERT INTO attendance (RollNo, attdStatus, AttDateTime, slotID, courseID) VALUES ('A004', '0', '2023-01-01 08:00:00', 4,1);
INSERT INTO attendance (RollNo, attdStatus, AttDateTime, slotID, courseID) VALUES ('A005', '1', '2023-01-01 08:00:00', 5,1);
INSERT INTO attendance (RollNo, attdStatus, AttDateTime, slotID, courseID) VALUES ('A006', '0', '2023-01-01 08:00:00', 1,1);
INSERT INTO attendance (RollNo, attdStatus, AttDateTime, slotID, courseID) VALUES ('A007', '1', '2023-01-01 08:00:00', 2,1);
INSERT INTO attendance (RollNo, attdStatus, AttDateTime, slotID, courseID) VALUES ('A008', '0', '2023-01-01 08:00:00', 3,1);
INSERT INTO attendance (RollNo, attdStatus, AttDateTime, slotID, courseID) VALUES ('A009', '1', '2023-01-01 08:00:00', 4,1);
INSERT INTO attendance (RollNo, attdStatus, AttDateTime, slotID, courseID) VALUES ('A010', '0', '2023-01-01 08:00:00', 5,1);
INSERT INTO attendance (RollNo, attdStatus, AttDateTime, slotID, courseID) VALUES ('A011', '1', '2023-01-01 08:00:00', 1,1);
INSERT INTO attendance (RollNo, attdStatus, AttDateTime, slotID, courseID) VALUES ('A012', '0', '2023-01-01 08:00:00', 2,1);
INSERT INTO attendance (RollNo, attdStatus, AttDateTime, slotID, courseID) VALUES ('A013', '1', '2023-01-01 08:00:00', 3,1);
INSERT INTO attendance (RollNo, attdStatus, AttDateTime, slotID, courseID) VALUES ('A014', '0', '2023-01-01 08:00:00', 4,1);
INSERT INTO attendance (RollNo, attdStatus, AttDateTime, slotID, courseID) VALUES ('A015', '1', '2023-01-01 08:00:00', 5,1);
INSERT INTO attendance (RollNo, attdStatus, AttDateTime, slotID, courseID) VALUES ('A016', '0', '2023-01-01 08:00:00', 1,1);
INSERT INTO attendance (RollNo, attdStatus, AttDateTime, slotID, courseID) VALUES ('A017', '1', '2023-01-01 08:00:00', 2,1);
INSERT INTO attendance (RollNo, attdStatus, AttDateTime, slotID, courseID) VALUES ('A018', '0', '2023-01-01 08:00:00', 3,1);
INSERT INTO attendance (RollNo, attdStatus, AttDateTime, slotID, courseID) VALUES ('A019', '1', '2023-01-01 08:00:00', 4,1);
INSERT INTO attendance (RollNo, attdStatus, AttDateTime, slotID, courseID) VALUES ('A020', '0', '2023-01-01 08:00:00', 5,1);
