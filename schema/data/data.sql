-- DROP TABLE IF EXISTS USERDATA;
-- DROP TABLE IF EXISTS studentData;
-- DROP TABLE IF EXISTS class;
-- DROP TABLE IF EXISTS Slots;
-- DROP TABLE IF EXISTS attendance;
CREATE TABLE course (
    courseID INT AUTO_INCREMENT PRIMARY KEY,
    courseName VARCHAR(255) NOT NULL,
    UNIQUE (courseName)
);
CREATE TABLE USERDATA (
    profID INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    profName VARCHAR(255) NOT NULL,
    userRole CHAR(1) NOT NULL,
    isActive CHAR(1) NOT NULL DEFAULT '1',
    courseID INT,
    FOREIGN KEY (courseID) REFERENCES course(courseID);
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
    courseID INT,
    -- Add a reference to the course table
    Semester INT NOT NULL,
    FOREIGN KEY (profID) REFERENCES USERDATA(profID),
    FOREIGN KEY (batchYear, Dept, Section) REFERENCES studentData(batchYear, Dept, Section),
    FOREIGN KEY (courseID) REFERENCES course(courseID) -- Add this line
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