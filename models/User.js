const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    unique: true,
    sparse: true,
    lowercase: true,
    trim: true,
  },
  phone: {
    type: String,
    unique: true,
    sparse: true,
  },
  username: { type: String, unique: true, sparse: true },
  birthdate: Date,
  password: String,
  isVerified: {
    type: Boolean,
    default: false,
  },
  isRegistered: { type: Boolean, default: false },
  otp: String,
  otpExpires: Date,
  height: { type: Number }, // in cm
  weight: { type: Number }, // in kg
  gender: { type: String, enum: ['male', 'female', 'other'] },
  activityLevel: { type: String, enum: ['sedentary', 'light', 'moderate', 'active', 'very_active'] },
}, { timestamps: true });

module.exports = mongoose.model('User', userSchema);
