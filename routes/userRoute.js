const express = require('express')
const router = express.Router();
const userWebController = require('../controller/userController');

// Test route
router.get('/test', userWebController.test);

// User authentication routes
router.post('/login', userWebController.userLogin); //done
router.post('/loginVerify', userWebController.loginVerify); //done

// Admin routes
router.post('/add-admin', userWebController.addAdmin); //done
router.delete('/delete-admin/', userWebController.deleteAdmin); //done

// Faculty routes
router.post('/add-faculty', userWebController.addFaculty); //done
router.delete('/delete-faculty/', userWebController.deleteFaculty); //done

// Common route
router.put('/edit-user', userWebController.editUser); //done
router.get('/users/all', userWebController.getAllUsers); //done

// Password reset routes
router.post('/forgot-password', userWebController.forgotPassword); //done
router.post('/reset-verify', userWebController.resetVerify); //done
router.post('/reset-password', userWebController.resetPassword); //done

// Student routes
router.post('/add-student', userWebController.addStudent); //done
router.put('/edit-student', userWebController.editStudent); //done
router.delete('/delete-student', userWebController.deleteStudent); //done
router.post('/activate-student', userWebController.activateStudent); //done
router.get('/all-students', userWebController.allStudents); //done
router.post('/add-students', userWebController.addStudents); //done

// Class routes
router.post('/add-class', userWebController.createClass);
router.get('/my-classes', userWebController.myClasses);
router.delete('/delete-class', userWebController.deleteClass);

// Slot routes
router.post('/add-slot', userWebController.createSlots);
router.delete('/delete-slot', userWebController.deleteSlot);

// Course routes
router.post('/add-course', userWebController.createCourse);
router.delete('/delete-slot', userWebController.deleteSlot);

router.post('/add-attendance', userWebController.addAttendance);
router.get('/attendance/:id', userWebController.getAttendanceForSlot);
router.post('/attendance/:id/:date', userWebController.updateAttendanceStatus);

module.exports = router;