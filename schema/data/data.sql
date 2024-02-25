CREATE DATABASE IF NOT EXISTS quick_attendance;
USE quick_attendance;

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

INSERT INTO USERDATA (email, password, profName, userRole) VALUES
('thanuskumaara@gmail.com','2a27ad2744e860e4dcf47b191a2afb795abc2bc800a8833f73d90f50ffa69383','Thanus Kumaar','1'),
('psuman1406@gmail.com', '735701f285cb9253fcff9649a0f7a09f27e5b5967030ded8baba4c5731683636', 'P Suman', '1');