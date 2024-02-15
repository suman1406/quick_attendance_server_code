# Quick Attendance Application User Documentation

Welcome to the Quick Attendance Application! This guide will walk you through the features and functionality of the application, helping you make the most of its capabilities. If you encounter any issues or have questions, refer to the troubleshooting section or contact our support team.

<details>
  <summary>Table of Contents</summary>

  1. [Introduction](#introduction)
  2. [Installation and Configuration](#installation-and-configuration)
  3. [User Roles](#user-roles)
    - [Professor (User Role: 0)](#professor-user-role-0)
    - [Administrator (User Role: 1)](#administrator-user-role-1)
  4. [Features and Functionality](#features-and-functionality)
    - [QR Code-Based Attendance](#qr-code-based-attendance)
    - [Admin/Professor Functionality](#adminprofessor-functionality)
    - [Real-time Attendance Tracking](#real-time-attendance-tracking)
  5. [Security Measures](#security-measures)
    - [Data Security](#data-security)
    - [User Authentication](#user-authentication)
  6. [Database Design](#database-design)
    - [Entity-Relationship Diagram](#entity-relationship-diagram)
    - [Database Schema](#database-schema)
  7. [Excel Sheet Automation](#excel-sheet-automation)
    - [Data Export to Excel](#data-export-to-excel)
    - [Excel Sheet Format](#excel-sheet-format)
  8. [Scalability](#scalability)
    - [Design for Scalability](#design-for-scalability)
    - [Performance Considerations](#performance-considerations)
  9. [User Guide](#user-guide)
    - [Getting Started](#getting-started)
    - [Adding Students](#adding-students)
    - [QR Code Scanning](#qr-code-scanning)
    - [Managing Classes](#managing-classes)
    - [Viewing Reports](#viewing-reports)
    - [Troubleshooting](#troubleshooting)
  10. [Conclusion](#conclusion)
    - [Project Summary](#project-summary)
    - [Lessons Learned](#lessons-learned)
  11. [Appendices](#appendices)

</details>

## 1. Introduction

The Quick Attendance Application modernizes student attendance management at Amrita Vishwa Vidyapeetham. Utilizing Flutter technology, this application combines precision, efficiency, and user-friendliness in attendance tracking.

## 2. Installation and Configuration

### Installation

To install Quick Attendance:

1. Download the latest release APK from the Playstore (Link will be shared soon).
2. Install the APK on your Android device.

### Configuration

Upon the first launch, enter a secret token provided by the server administrator. Follow the on-screen instructions to configure the app.

## 3. User Roles

### Professor (User Role: 0)

Professors have access to the following features:

- Adding students
- Fetching student data
- Recording attendance

### Administrator (User Role: 1)

Administrators enjoy full access to all features, including:

- Adding students
- Excel upload
- Fetching student data
- Deleting students
- Recording attendance

## 4. Features and Functionality

### QR Code-Based Attendance

The application utilizes QR code scanning for attendance capture. Professors scan student ID cards or mobile devices.

### Admin/Professor Functionality

Manage classes, students, and access attendance reports through the web dashboard.

### Real-time Attendance Tracking

Attendance records update in real time, ensuring accuracy and timely data.

## 5. Security Measures

### Data Security

The app employs data encryption to secure information during transmission.

### User Authentication

Bearer Tokens are used for secure and token-based user authentication.

## 6. Database Design

### Entity-Relationship Diagram

[Insert ER Diagram]

### Database Schema

[Insert Schema Diagram]

## 7. Excel Sheet Automation

### Data Export to Excel

[Insert Screenshot/Flowchart]

### Excel Sheet Format

[Insert Example Sheet]

## 8. Scalability

### Design for Scalability

[Insert Scalability Strategy]

### Performance Considerations

[Insert Performance Metrics]

## 9. User Guide

### Getting Started

1. **Login:**
    - Enter your credentials to access the dashboard.

2. **Navigation:**
    - Explore the menu for various features.

### Adding Students

1. **Navigate to "Add Student."**
2. **Enter Student Details:**
    - Roll Number, Name, Batch Year, Department, Section, Semester.
3. **Tap "Add Student" to Save.**

### QR Code Scanning

1. **Navigate to "Record Attendance."**
2. **Scan QR Codes:**
    - Record attendance by scanning student QR codes.

### Managing Classes

1. **Navigate to "Manage Classes."**
2. **Add/Edit Classes:**
    - Specify course details and manage classes.

### Viewing Reports

1. **Navigate to "View Reports."**
2. **Select Criteria:**
    - Choose Batch Year, Department, Section, and Semester.
3. **Tap "View Report" to Display Data.**

### Troubleshooting

- Ensure an active internet connection.
- Verify the secret token during configuration.

## 10. Conclusion

### Project Summary

The Quick Attendance Application transforms attendance management, providing accuracy, efficiency, and a modern user experience.

### Lessons Learned

Reflecting on the project journey, we've gained insights that contribute to ongoing improvement and future projects.

## 11. Appendices

### Appendix A: Glossary
- **QR Code:** A two-dimensional barcode that contains information about the item to which it is attached.

### Appendix B: Team Members
- **Suman Panigrahi:** Team Leader and Computer Science and Engineering student (2022-2026 batch).
- **Thanus Kumaar:** Project collaborator.

### Appendix C: Mentors
- **Dr. Senthil Kumar T:** Mentor
- **B. Senthil Kumar:** Mentor

### Appendix D: Frontend Code Repository
- For the frontend code repository, visit [Frontend Code Repository](https://github.com/suman1406/QuickAttendance_Frontend).

---
