const User = require('../models/User');
const generateOTP = require('../utils/generateOTP');
const sendEmailOTP = require('../mailTest');
const sendSMSOTP = require('../services/twilioService');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// SEND OTP
exports.sendOTP = async (req, res, next) => {
  try {
    const { email, phone } = req.body;

    if (!email && !phone) {
      return res.status(400).json({ success: false, message: 'Email or phone is required' });
    }

    const normalizedEmail = email ? email.trim().toLowerCase() : null;
    const normalizedPhone = phone ? phone.trim() : null;

    const conditions = [];
    if (normalizedEmail) conditions.push({ email: normalizedEmail });
    if (normalizedPhone) conditions.push({ phone: normalizedPhone });

    let user = await User.findOne({ $or: conditions });

    // Check if user is fully registered (has username and password)
    if (user && user.username && user.password) {
      return res.status(400).json({ success: false, message: 'User already registered. Please login.' });
    }

    const otp = generateOTP();
    const otpExpires = Date.now() + 10 * 60 * 1000;

    // Create a new user if not found, or update existing user
    if (!user) {
      user = new User({});
      if (normalizedEmail) user.email = normalizedEmail;
      if (normalizedPhone) user.phone = normalizedPhone;
      user.isVerified = false;
    }

    user.otp = otp;
    user.otpExpires = otpExpires;
    await user.save();

    if (normalizedEmail) await sendEmailOTP(normalizedEmail, otp);
    if (normalizedPhone) await sendSMSOTP(normalizedPhone, otp);

    console.log('OTP:', otp); // For development only

    res.status(200).json({
      success: true,
      message: `OTP sent successfully to ${normalizedEmail || normalizedPhone}`,
    });
  } catch (error) {
    console.error('Error sending OTP:', error);
    next(error);
  }
};

// VERIFY OTP
exports.verifyOTP = async (req, res, next) => {
  try {
    const { email, phone, otp } = req.body;

    if (!otp || (!email && !phone)) {
      return res.status(400).json({ message: 'OTP and email or phone are required' });
    }

    const normalizedEmail = email ? email.trim().toLowerCase() : null;
    const normalizedPhone = phone ? phone.trim() : null;

    const user = await User.findOne({
      $or: [
        normalizedEmail ? { email: normalizedEmail } : null,
        normalizedPhone ? { phone: normalizedPhone } : null
      ].filter(Boolean)
    });

    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    if (user.otp !== otp) {
      return res.status(400).json({ success: false, message: 'Invalid OTP' });
    }

    if (user.otpExpires < Date.now()) {
      return res.status(400).json({ success: false, message: 'OTP expired' });
    }

    user.isVerified = true;
    user.otp = null;
    user.otpExpires = null;
    await user.save();

    // Generate a temporary token for registration
    const token = jwt.sign(
      { userId: user._id, verified: true },
      process.env.JWT_SECRET,
      { expiresIn: '15m' }
    );

    res.status(200).json({
      success: true,
      message: 'OTP verified successfully',
      token,
      isNewUser: !user.isRegistered, // Indicate if user needs to register
    });
  } catch (err) {
    console.error('Error verifying OTP:', err);
    next(err);
  }
};

// REGISTER USER
exports.registerUser = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
      return res.status(401).json({ message: 'Authorization token required' });
    }

    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (err) {
      return res.status(401).json({ message: 'Invalid or expired token' });
    }

    const user = await User.findById(decoded.userId);

    if (!user || !user.isVerified) {
      return res.status(400).json({ message: 'Please verify OTP first' });
    }

    const { username, birthdate, password } = req.body;

    if (!username) {
      return res.status(400).json({ message: 'Username is required' });
    }

    if (!birthdate) {
      return res.status(400).json({ message: 'Birthdate is required' });
    }

    if (!password || password.length < 6) {
      return res.status(400).json({ message: 'Password must be at least 6 characters' });
    }

    if (user.username && user.password) {
      return res.status(400).json({ message: 'User already registered. Please login.' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    user.username = username;
    user.birthdate = birthdate;
    user.password = hashedPassword;
    user.isRegistered = true;

    await user.save();

    res.status(201).json({ success: true, message: 'User registered successfully' });
  } catch (err) {
    console.error('Error registering user:', err);
    next(err);
  }
};

// LOGIN USER
exports.loginUser = async (req, res, next) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ message: 'Username and password are required' });
    }

    const user = await User.findOne({ username });

    if (!user) {
      return res.status(400).json({ message: 'Invalid username or password' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid username or password' });
    }

    const token = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );

    res.status(200).json({
      success: true,
      message: 'Login successful',
      token,
    });
  } catch (err) {
    console.error('Error logging in:', err);
    next(err);
  }
};

// FORGOT PASSWORD
exports.forgotPassword = async (req, res, next) => {
  try {
    const { email, phone } = req.body;

    if (!email && !phone) {
      return res.status(400).json({ success: false, message: 'Email or phone is required' });
    }

    const normalizedEmail = email ? email.trim().toLowerCase() : null;
    const normalizedPhone = phone ? phone.trim() : null;

    const conditions = [];
    if (normalizedEmail) conditions.push({ email: normalizedEmail });
    if (normalizedPhone) conditions.push({ phone: normalizedPhone });

    const user = await User.findOne({ $or: conditions });

    if (!user || !user.isVerified || !user.username || !user.password) {
      return res.status(404).json({ success: false, message: 'User not found or not registered' });
    }

    const otp = generateOTP();
    const otpExpires = Date.now() + 10 * 60 * 1000;

    user.otp = otp;
    user.otpExpires = otpExpires;
    await user.save();

    if (normalizedEmail) await sendEmailOTP(normalizedEmail, otp);
    if (normalizedPhone) await sendSMSOTP(normalizedPhone, otp);

    console.log('Reset OTP:', otp); // For development only

    const resetToken = jwt.sign(
      { userId: user._id, reset: true },
      process.env.JWT_SECRET,
      { expiresIn: '15m' }
    );

    res.status(200).json({
      success: true,
      message: `OTP sent to ${normalizedEmail || normalizedPhone}`,
      resetToken,
    });
  } catch (error) {
    console.error('Error in forgot password:', error);
    next(error);
  }
};

// RESET PASSWORD
exports.resetPassword = async (req, res, next) => {
  try {
    const { email, phone, otp, password } = req.body;
    const token = req.headers.authorization?.split(' ')[1];

    if (!email && !phone) {
      return res.status(400).json({ success: false, message: 'Email or phone is required' });
    }

    if (!otp || !password) {
      return res.status(400).json({ success: false, message: 'OTP and new password are required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ success: false, message: 'Password must be at least 6 characters' });
    }

    if (!token) {
      return res.status(401).json({ success: false, message: 'Reset token required' });
    }

    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (err) {
      return res.status(401).json({ success: false, message: 'Invalid or expired reset token' });
    }

    if (!decoded.reset) {
      return res.status(401).json({ success: false, message: 'Invalid reset token' });
    }

    const normalizedEmail = email ? email.trim().toLowerCase() : null;
    const normalizedPhone = phone ? phone.trim() : null;

    const user = await User.findOne({
      _id: decoded.userId,
      $or: [
        normalizedEmail ? { email: normalizedEmail } : null,
        normalizedPhone ? { phone: normalizedPhone } : null
      ].filter(Boolean)
    });

    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    if (user.otp !== otp) {
      return res.status(400).json({ success: false, message: 'Invalid OTP' });
    }

    if (user.otpExpires < Date.now()) {
      return res.status(400).json({ success: false, message: 'OTP expired' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    user.password = hashedPassword;
    user.otp = null;
    user.otpExpires = null;
    await user.save();

    res.status(200).json({
      success: true,
      message: 'Password reset successfully',
    });
  } catch (error) {
    console.error('Error resetting password:', error);
    next(error);
  }
};

// UPDATE USER HEALTH DATA
exports.updateUserHealth = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ message: 'Authorization token required' });
    }

    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (err) {
      return res.status(401).json({ message: 'Invalid or expired token' });
    }

    const user = await User.findById(decoded.userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const { height, weight, gender, activityLevel } = req.body;
    if (!height || !weight || !gender || !activityLevel) {
      return res.status(400).json({ message: 'Height, weight, gender, and activity level are required' });
    }

    user.height = height;
    user.weight = weight;
    user.gender = gender;
    user.activityLevel = activityLevel;
    await user.save();

    res.status(200).json({ success: true, message: 'Health data updated successfully' });
  } catch (err) {
    console.error('Error updating health data:', err);
    next(err);
  }
};

// GET USER PROFILE
exports.getUserProfile = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ message: 'Authorization token required' });
    }

    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_SECRET);
    } catch (err) {
      return res.status(401).json({ message: 'Invalid or expired token' });
    }

    const user = await User.findById(decoded.userId).select('-password -otp -otpExpires');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.status(200).json({ success: true, user });
  } catch (err) {
    console.error('Error fetching user profile:', err);
    next(err);
  }
};
