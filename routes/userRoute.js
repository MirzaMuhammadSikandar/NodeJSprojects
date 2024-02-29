const router = require('express').Router();
const {registration, login, updateuser, forgetPassword, resetPassword, googleLogin, googleCallBack, protected, failure} = require('../controllers/userController.js')
// const {googleLogin, googleCallBack, protected, failure} = require('../controllers/userController.js')
const upload = require('../middleware/multermiddleware.js')
const {authenticateToken, isLoggedIn} = require('../middleware/auth.js')

router.post('/register', upload.single('image'), registration);
router.post('/login', login);
router.put('/update-user', authenticateToken, isLoggedIn, upload.single('image'), updateuser)
router.post('/forget-password', forgetPassword);
router.post('/reset-password/:id/:token', resetPassword);
// router.get('/auth/google', googleLogin);
// router.get('/google/callback', googleCallBack);
// router.get('/protected', isLoggedIn, protected);
// router.get('/auth/failure', failure);

module.exports = router;