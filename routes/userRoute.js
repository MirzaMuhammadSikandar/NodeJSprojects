const router = require('express').Router();
const {registration, login, updateuser, forgetPassword, resetPassword, getUser, verifyOTP , googleLogin, googleCallBack, protected, failure} = require('../controllers/userController.js')
// const {googleLogin, googleCallBack, protected, failure} = require('../controllers/userController.js')
const upload = require('../middleware/multermiddleware.js')
const {authenticateToken, isLoggedIn, forgetPasswordAuthToken} = require('../middleware/auth.js')

router.post('/register', upload.single('image'), registration);
router.post('/login', login);
router.put('/update-user', authenticateToken, isLoggedIn, upload.single('image'), updateuser);
router.post('/forgetpassword', forgetPassword);
router.post('/resetpassword',forgetPasswordAuthToken, resetPassword);
router.get('/record', authenticateToken, isLoggedIn, getUser);
router.post('/verify-otp', verifyOTP);
// router.get('/auth/google', googleLogin);
// router.get('/google/callback', googleCallBack);
// router.get('/protected', isLoggedIn, protected);
// router.get('/auth/failure', failure);

module.exports = router;