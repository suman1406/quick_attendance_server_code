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
-- Create the USERDATA table
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
-- Create the class table
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
-- Create the ProfessorClass table for the many-to-many relationship
CREATE TABLE IF NOT EXISTS ProfessorClass (
    professorID INT,
    classID INT,
    FOREIGN KEY (professorID) REFERENCES USERDATA(profID),
    FOREIGN KEY (classID) REFERENCES class(classID)
);
-- Create the studentData table
CREATE TABLE IF NOT EXISTS studentData (
    RollNo VARCHAR(20) NOT NULL UNIQUE,
    StdName VARCHAR(255) NOT NULL,
    classID INT,
    isActive CHAR(1) NOT NULL DEFAULT '1',
    FOREIGN KEY (classID) REFERENCES class(classID)
);
-- Create the Slots table
CREATE TABLE IF NOT EXISTS Slots (
    slotID INT AUTO_INCREMENT PRIMARY KEY,
    classID INT,
    periodNo INT NOT NULL,
    isActive CHAR(1) NOT NULL DEFAULT '1',
    FOREIGN KEY (classID) REFERENCES class(classID)
);
-- Create the attendance table
CREATE TABLE IF NOT EXISTS attendance (
    RollNo VARCHAR(20),
    attdStatus CHAR(1) NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    slotID INT NOT NULL,
    PRIMARY KEY (RollNo, timestamp),
    FOREIGN KEY (RollNo) REFERENCES studentData(RollNo),
    FOREIGN KEY (slotID) REFERENCES Slots(slotID)
);
-- Create the userregister table
CREATE TABLE IF NOT EXISTS USERREGISTER (
    id INT NOT NULL AUTO_INCREMENT,
    email VARCHAR(255) NOT NULL,
    otp VARCHAR(6) NOT NULL,
    createdAt TIMESTAMP NOT NULL,
    PRIMARY KEY (id)
);

-- Insert sample data into the course table
INSERT INTO course (courseName)
VALUES ('Mathematics'),
    ('Physics'),
    ('Biology'),
    ('History'),
    ('English'),
    ('Chemistry'),
    ('Artificial Intelligence'),
    ('Economics'),
    ('Psychology'),
    ('Sociology'),
    ('Mechanical Engineering'),
    ('Electrical Engineering'),
    ('Medicine'),
    ('Law'),
    ('Business Administration'),
    ('Political Science'),
    ('Environmental Science'),
    ('Information Technology'),
    ('Data Science');
-- Insert sample data into the USERDATA table
INSERT INTO USERDATA (email, password, profName, userRole, courseID)
VALUES (
        'saisimhadri2207@gmail.com',
        'goodluck',
        'Prasad S',
        '0',
        1
    ),
    (
        'prof2@example.com',
        'password456',
        'Professor Johnson',
        '0',
        2
    ),
    (
        'admin@example.com',
        'adminpass',
        'Administrator',
        '1',
        NULL
    ),
    (
        'prof3@example.com',
        'password789',
        'Professor White',
        '0',
        3
    ),
    (
        'prof4@example.com',
        'password987',
        'Professor Black',
        '0',
        4
    ),
    (
        'prof5@example.com',
        'password654',
        'Professor Green',
        '0',
        5
    ),
    (
        'prof6@example.com',
        'password321',
        'Professor Red',
        '0',
        6
    ),
    (
        'prof7@example.com',
        'password012',
        'Professor Blue',
        '0',
        7
    ),
    (
        'prof8@example.com',
        'password876',
        'Professor Yellow',
        '0',
        8
    ),
    (
        'prof9@example.com',
        'password543',
        'Professor Orange',
        '0',
        9
    ),
    (
        'psuman1406@gmail.com',
        'goodluck',
        'Suman',
        '1',
        9
    );
-- Insert sample data into the class table
INSERT INTO class (batchYear, Dept, Section, courseID, Semester)
VALUES (2023, 'Computer Science', 'A', 1, 1),
    (2023, 'Mathematics', 'B', 2, 1),
    (2023, 'Physics', 'C', 3, 1),
    (2023, 'Biology', 'D', 4, 1),
    (2023, 'History', 'E', 5, 1),
    (2023, 'English', 'F', 6, 1),
    (2023, 'Chemistry', 'G', 7, 1),
    (2023, 'Artificial Intelligence', 'H', 8, 1),
    (2023, 'Economics', 'I', 9, 1),
    (2023, 'Psychology', 'J', 10, 1),
    (2023, 'Sociology', 'A', 11, 2),
    (2023, 'Mechanical Engineering', 'B', 12, 2),
    (2023, 'Electrical Engineering', 'C', 13, 2),
    (2023, 'Medicine', 'D', 14, 2),
    (2023, 'Law', 'E', 15, 2),
    (2023, 'Business Administration', 'F', 16, 2),
    (2023, 'Political Science', 'G', 17, 2),
    (2023, 'Environmental Science', 'H', 18, 2),
    (2023, 'Information Technology', 'I', 19, 2);
-- Insert sample data into the studentData table
INSERT INTO studentData (RollNo, StdName, classID)
VALUES ('CB.EN.U4CSE22401', 'John Doe', 1),
    ('CB.EN.U4CSE22402', 'Jane Doe', 2),
    ('CB.EN.U4CSE22403', 'Bob Smith', 3),
    ('CB.EN.U4CSE22404', 'Alice Johnson', 4),
    ('CB.EN.U4CSE22405', 'Charlie White', 5),
    ('CB.EN.U4CSE22406', 'David Black', 6),
    ('CB.EN.U4CSE22407', 'Eva Green', 7),
    ('CB.EN.U4CSE22408', 'Frank Red', 8),
    ('CB.EN.U4CSE22409', 'Grace Blue', 9),
    ('CB.EN.U4CSE22410', 'Henry Yellow', 10);
-- Insert sample data into the Slots table
INSERT INTO Slots (classID, periodNo)
VALUES (1, 1),
    (2, 2),
    (3, 3),
    (4, 4),
    (5, 5),
    (6, 6),
    (7, 7),
    (8, 8),
    (9, 9),
    (10, 10),
    (11, 1),
    (12, 2),
    (13, 3),
    (14, 4),
    (15, 5),
    (16, 6),
    (17, 7),
    (18, 8),
    (19, 9);
-- Insert sample data into the attendance table
INSERT INTO attendance (RollNo, attdStatus, timestamp, slotID)
VALUES (
        'CB.EN.U4CSE22401',
        '1',
        '2023-01-01 08:00:00',
        1
    ),
    (
        'CB.EN.U4CSE22402',
        '1',
        '2023-01-01 09:00:00',
        2
    ),
    (
        'CB.EN.U4CSE22403',
        '1',
        '2023-01-01 10:00:00',
        3
    ),
    (
        'CB.EN.U4CSE22404',
        '1',
        '2023-01-01 11:00:00',
        4
    ),
    (
        'CB.EN.U4CSE22405',
        '1',
        '2023-01-01 12:00:00',
        5
    ),
    (
        'CB.EN.U4CSE22406',
        '1',
        '2023-01-01 13:00:00',
        6
    ),
    (
        'CB.EN.U4CSE22407',
        '1',
        '2023-01-01 14:00:00',
        7
    ),
    (
        'CB.EN.U4CSE22408',
        '1',
        '2023-01-01 15:00:00',
        8
    ),
    (
        'CB.EN.U4CSE22409',
        '1',
        '2023-01-01 16:00:00',
        9
    ),
    (
        'CB.EN.U4CSE22410',
        '1',
        '2023-01-01 17:00:00',
        10
    );