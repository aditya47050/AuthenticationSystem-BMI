const express = require('express');
const router = express.Router();
const { sendOTP, verifyOTP, registerUser , loginUser, forgotPassword, resetPassword, updateUserHealth} = require('../controllers/authController');
const protect = require('../middleware/authMiddleware');

router.post('/send-otp', sendOTP);
router.post('/verify-otp', verifyOTP);
router.post('/register', registerUser);
router.post('/login', loginUser);
router.post('/forgot-password', forgotPassword);
router.post('/reset-password', resetPassword);
router.post('/update-health',updateUserHealth);


router.get('/profile', protect, (req, res) => {
  res.status(200).json({
    success: true,
    message: 'Protected route accessed',
    user: req.user,
  });
});


module.exports = router;
