const express = require('express')
const router = express.Router();
const userWebController = require('../controller/userController');

// Test route
router.get('/test', userWebController.test);

// User authentication routes
router.post('/login', userWebController.userLogin);
router.post('/loginVerify', userWebController.loginVerify);

// Admin routes
router.post('/admin', userWebController.addAdmin);
router.put('/admin/:id', userWebController.editAdmin);
router.delete('/admin/:id', userWebController.deleteAdmin);

// Faculty routes
router.post('/faculty', userWebController.addFaculty);
router.put('/faculty/:id', userWebController.editFaculty);
router.delete('/faculty/:id', userWebController.deleteFaculty);
router.get('/faculty/all', userWebController.allFaculty);

// Password reset routes
router.post('/forgot-password', userWebController.forgotPassword);
router.post('/reset-password', userWebController.resetPassword);
router.post('/reset-verify', userWebController.resetVerify);

// Student routes
router.post('/student', userWebController.addStudent);
router.put('/student/:id', userWebController.editStudent);
router.delete('/student/:id', userWebController.deleteStudent);
router.get('/students', userWebController.allStudents);
router.post('/students', userWebController.addStudents);

// Class routes
router.post('/class', userWebController.createClass);
router.get('/my-classes/:id', userWebController.myClasses);
router.delete('/class/:id', userWebController.deleteClass);

// Slot routes
router.post('/slots', userWebController.createSlots);
router.delete('/slot/:id', userWebController.deleteSlot);

module.exports = router;