-- DROP TABLE IF EXISTS USERDATA;
-- DROP TABLE IF EXISTS studentData;
-- DROP TABLE IF EXISTS class;
-- DROP TABLE IF EXISTS Slots;
-- DROP TABLE IF EXISTS attendance;
CREATE TABLE USERDATA (
    profID INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    profName VARCHAR(255) NOT NULL,
    userRole CHAR(1) NOT NULL,
    isActive CHAR(1) NOT NULL DEFAULT '1'
);
CREATE TABLE studentData (
    StdID INT AUTO_INCREMENT PRIMARY KEY,
    RollNo VARCHAR(20) NOT NULL UNIQUE,
    StdName VARCHAR(255) NOT NULL,
    batchYear INT NOT NULL,
    Dept VARCHAR(255) NOT NULL,
    Section VARCHAR(10) NOT NULL,
    isActive CHAR(1) NOT NULL DEFAULT '1',
    INDEX(batchYear),
    INDEX(Dept),
    INDEX(Section),
    PRIMARY KEY (StdID, batchYear, Dept, Section)
);
CREATE TABLE class (
    classID INT AUTO_INCREMENT PRIMARY KEY,
    batchYear INT NOT NULL,
    Dept VARCHAR(255) NOT NULL,
    Section VARCHAR(10) NOT NULL,
    profID INT,
    Semester INT NOT NULL,
    FOREIGN KEY (profID) REFERENCES USERDATA(profID),
    FOREIGN KEY (batchYear, Dept, Section) REFERENCES studentData(batchYear, Dept, Section)
);
CREATE TABLE Slots (
    slotID INT AUTO_INCREMENT PRIMARY KEY,
    classID INT,
    periodNo INT NOT NULL,
    FOREIGN KEY (classID) REFERENCES class(classID)
);
CREATE TABLE attendance (
    StdID INT,
    attdStatus CHAR(1) NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    slotID INT NOT NULL,
    PRIMARY KEY (StdID, timestamp),
    FOREIGN KEY (StdID) REFERENCES studentData(StdID),
    FOREIGN KEY (slotID) REFERENCES Slots(slotID)
);
-- Insert data into USERDATA table
INSERT INTO USERDATA (email, password, profName, userRole, isActive)
VALUES (
        'psuman1406@gmail.com',
        'firstproject',
        'Suman Panigrahi',
        '1',
        '1'
    );
-- Insert data into studentData table
INSERT INTO studentData (RollNo, StdName, batchYear, Dept, Section)
VALUES ('001', 'John Doe', 2022, 'Computer Science', 'A'),
    (
        '002',
        'Jane Smith',
        2023,
        'Electrical Engineering',
        'B'
    ),
    (
        '003',
        'Bob Johnson',
        2023,
        'Mechanical Engineering',
        'C'
    );
-- Insert data into class table
INSERT INTO class (batchYear, Dept, Section, profID, Semester)
VALUES (2022, 'Computer Science', 'A', 1, 1),
    (2023, 'Electrical Engineering', 'B', 1, 1),
    (2023, 'Mechanical Engineering', 'C', 1, 1);
CREATE TABLE studentData (
    StdID INT AUTO_INCREMENT,
    RollNo VARCHAR(20) NOT NULL UNIQUE,
    StdName VARCHAR(255) NOT NULL,
    batchYear INT NOT NULL,
    Dept VARCHAR(255) NOT NULL,
    Section VARCHAR(10) NOT NULL,
    isActive CHAR(1) NOT NULL DEFAULT '1',
    PRIMARY KEY (StdID, batchYear, Dept, Section)
);
CREATE TABLE studentData (
    StdID INT AUTO_INCREMENT,
    RollNo VARCHAR(20) NOT NULL UNIQUE,
    StdName VARCHAR(255) NOT NULL,
    batchYear INT NOT NULL,
    Dept VARCHAR(255) NOT NULL,
    Section VARCHAR(10) NOT NULL,
    isActive CHAR(1) NOT NULL DEFAULT '1',
    PRIMARY KEY (StdID, batchYear, Dept, Section)
);
-- Insert data into Slots table
INSERT INTO Slots (classID, periodNo)
VALUES (1, 1),
    (2, 2),
    (3, 3);
-- Insert data into attendance table
INSERT INTO attendance (StdID, attdStatus, timestamp, slotID)
VALUES (1, 'P', '2023-01-01 08:00:00', 1),
    (2, 'A', '2023-01-01 09:00:00', 2),
    (3, 'P', '2023-01-01 10:00:00', 3);