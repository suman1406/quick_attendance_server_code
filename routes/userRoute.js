const express = require('express')
const router = express.Router();
const userController = require('../controller/userController');
const studentController = require('../controller/studentController');
const courseController = require('../controller/courseController');
const attendanceController = require('../controller/attendanceController');
const linkTablesController = require('../controller/linkTablesController');
const slotController = require('../controller/slotController');
const classController = require('../controller/classController');
const authController = require('../controller/authController');
const DepartmentController = require('../controller/departmentController');

// Test route
router.get('/test', userController.test);

// User authentication routes
router.post('/login', authController.userLogin); //done
router.post('/loginVerify', authController.loginVerify); //done
router.get('/allUserRoles', authController.allUserRoles);

// Admin routes
router.post('/add-admin', userController.addAdmin); //done
router.delete('/delete-admin/', userController.deleteAdmin); //done
router.post('/activate-user', userController.activateUser);

// Faculty routes
router.post('/add-faculty', userController.addFaculty); //done
router.delete('/delete-faculty/', userController.deleteFaculty); //done
router.get('/all-profs', userController.getAllProfEmails);

// Common route
router.put('/edit-user', userController.editUser); //done
router.get('/users/all', userController.getAllUsers); //done
router.get('/fetchUser', userController.fetchUSERDATA); //done

// Password reset routes
router.post('/forgot-password', authController.forgotPassword); //done
router.post('/reset-verify', authController.resetVerify); //done
router.post('/reset-password', authController.resetPassword); //done

// Student routes
router.post('/add-student', studentController.addStudent); //done
router.put('/edit-student', studentController.editStudent); //done
router.delete('/delete-student', studentController.deleteStudent); //done
router.post('/activate-student', studentController.activateStudent); //done
router.get('/all-students', studentController.allStudents); //done
router.get('/fetchStudent', studentController.fetchstudentData);
router.post('/add-students', studentController.addStudents); //done

// Class routes
router.post('/add-class', classController.createClass); //done
router.get('/my-classes', classController.myClasses); //done
router.get('/all-semesters', classController.allSemesters);
router.get('/all-BatchYears', classController.allBatchYears);
router.get('/all-sections', classController.allSections);
router.delete('/delete-class', classController.deleteClass);

// Slot routes
router.post('/add-slot', slotController.createSlot); //done
router.delete('/delete-slot', slotController.deleteSlot); //done

// Course routes
router.post('/add-course', courseController.createCourse); //done
router.delete('/delete-course', courseController.deleteCourse); //done
router.get('/all-courses', courseController.allCourses);
router.get('/my-courses', courseController.myCourses);

//Department routes
router.post('/add-dept', DepartmentController.createDept);
router.delete('/delete-dept', DepartmentController.deleteDept);
router.get('/all-dept', DepartmentController.allDepts)

//many to many operation routes
router.post('/add-prof-course', linkTablesController.addProfCourse);
router.post('/add-class-course-prof', linkTablesController.addClassCourseProf);
router.delete('/delete-prof-course', linkTablesController.deleteProfCourse);
router.delete('/delete-class-course-prof', linkTablesController.deleteClassCourseProf);

router.post('/req-slotID', attendanceController.returnSlotID);
router.post('/add-attendance', attendanceController.addAttendance);
router.get('/get-attd-slot', attendanceController.getAttendanceForSlot);
router.post('/attendance/:id/:date', attendanceController.updateAttendanceStatus);
router.post('/attd-coursewise', attendanceController.getAttendanceForCourse);

module.exports = router;