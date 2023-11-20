const express = require('express')
const router = express.Router();
const userWebController = require('../controller/userController');

// Test route
router.get('/test', userWebController.test);

// User authentication routes
router.post('/login', userWebController.userLogin); //done
router.post('/loginVerify', userWebController.loginVerify);

// Admin routes
router.post('/add-admin', userWebController.addAdmin); //done
router.delete('/delete-admin/:id', userWebController.deleteAdmin); //done

// Faculty routes
router.post('/add-faculty', userWebController.addFaculty); //done
router.delete('/delete-faculty/:id', userWebController.deleteFaculty); //done

// Edit route
router.put('/edit-user/:id', userWebController.editUser); //done
router.get('/users/all', userWebController.getAllUsers); //done

// Password reset routes
router.post('/forgot-password', userWebController.forgotPassword);
router.post('/reset-password', userWebController.resetPassword);
router.post('/reset-verify', userWebController.resetVerify);

// Student routes
router.post('/add-student', userWebController.addStudent); //done
router.put('/edit-student/:id', userWebController.editStudent); //done
router.delete('/delete-student/:id', userWebController.deleteStudent); //done
router.post('/activate-student/:id', userWebController.activateStudent); //done
router.get('/all-students', userWebController.allStudents); //done
router.post('/add-students', userWebController.addStudents); //done || should add validations

// Class routes
router.post('/add-class', userWebController.createClass); //done
router.get('/my-classes/:id', userWebController.myClasses); //done
router.delete('/delete-class/:id', userWebController.deleteClass); //done

// Slot routes
router.post('/add-slots', userWebController.createSlots); //done
router.delete('/delete-slot/:id', userWebController.deleteSlot); //done

router.post('/add-attendance', userWebController.addAttendance);
router.get('/attendance/:id', userWebController.getAttendanceForSlot);
router.get('/attendance/:id/:date', userWebController.updateAttendanceStatus);

module.exports = router;