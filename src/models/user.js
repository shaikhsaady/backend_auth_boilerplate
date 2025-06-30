import { Schema, model } from "mongoose";
import validator from "validator";
import bcrypt from "bcrypt";
import crypto from "crypto";

// BCRYPT_SALT_ROUNDS
const BCRYPT_SALT_ROUNDS = parseInt(process.env.BCRYPT_SALT_ROUNDS || "12");

// OTP_EXPIRY_MINUTES
const OTP_EXPIRY_MINUTES = parseInt(process.env.OTP_EXPIRY_MINUTES || "15");

// OTP_LENGTH
const OTP_LENGTH = parseInt(process.env.OTP_LENGTH || "6");

// user schema
const userSchema = new Schema(
  {
    firstName: {
      type: String,
      trim: true,
      minLength: [3, "First name must be at least 3 characters"],
      maxLength: [50, "First name cannot exceed 50 characters"],
    },
    lastName: {
      type: String,
      trim: true,
      minLength: [3, "Last name must be at least 3 characters"],
      maxLength: [50, "Last name cannot exceed 50 characters"],
    },
    profilePic: {
      type: {
        url: String,
        publicId: String,
      },
      default: null,
    },
    phoneNo: {
      type: String,
      trim: true,
      index: true,
      validate: {
        validator: (value) =>
          validator.isMobilePhone(value, "any", { strictMode: false }),
        message: "Invalid phone number",
      },
    },
    email: {
      type: String,
      required: [true, "Email is required"],
      unique: true,
      trim: true,
      lowercase: true,
      validate: {
        validator: (value) => validator.isEmail(value),
        message: "Please provide a valid email address",
      },
      index: true, // Add index for faster queries
    },
    password: {
      type: String,
      required: function () {
        return !this.provider;
      },
      minLength: [8, "Password must be at least 8 characters"],
      validate: {
        validator: (value) =>
          validator.isStrongPassword(value, {
            minLength: 8,
            minLowercase: 1,
            minUppercase: 1,
            minNumbers: 1,
            minSymbols: 1,
          }),
        message:
          "Password must be at least 8 characters with 1 uppercase, 1 lowercase, 1 number, and 1 symbol",
      },
      select: false, // Never return password in queries
    },
    isVerified: {
      type: Boolean,
      default: false,
    },
    lastVerified: {
      type: Date,
      default: null,
    },
    provider: {
      type: String,
      select: false,
    },
    socialInfo: {
      type: [
        {
          provider: {
            type: String,
          },
          socialId: {
            type: String,
          },
        },
      ],
      select: false,
    },
    deviceTokens: [
      {
        type: String,
        select: false,
      },
    ],
    otpVerification: {
      otp: {
        type: String,
        select: false,
      },
      expiry: {
        type: Date,
        select: false,
      },
      attempts: {
        type: Number,
        select: false,
      },
    },
    passwordResetToken: {
      type: String,
      select: false,
    },
    passwordResetTokenExpiry: {
      type: Date,
      select: false,
    },
    jti: {
      type: String, // JWT ID
      unique: true,
      select: false,
    },
  },
  {
    timestamps: true,
    toJSON: {
      virtuals: true,
      transform: (doc, ret) => {
        delete ret.password; // Ensure password is never serialized
        delete ret.__v; // Remove version key
        delete ret.id; // Remove id key
        return ret;
      },
    },
  }
);

// Virtual for full name
userSchema.virtual("fullName").get(function () {
  return `${this.firstName} ${this.lastName}`;
});

// Pre-save hook for password hashing
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();

  try {
    // Hash new password
    const salt = await bcrypt.genSalt(BCRYPT_SALT_ROUNDS);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Password comparison method (async)
userSchema.methods.comparePassword = async function (candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

// OTP generation method
userSchema.methods.generateOTP = function () {
  const otp = crypto
    .randomInt(10 ** (OTP_LENGTH - 1), 10 ** OTP_LENGTH)
    .toString()
    .padStart(OTP_LENGTH, "0");

  this.otpVerification = {
    otp,
    expiry: new Date(Date.now() + OTP_EXPIRY_MINUTES * 60000),
    attempts: 0,
  };

  return otp;
};

// OTP verification method
userSchema.methods.verifyOTP = function (otp) {
  // Check if OTP exists
  if (!this.otpVerification) {
    return {
      success: false,
      status: 401,
      message: "The OTP you entered is incorrect. Please try again.",
    };
  }

  // Check attempts
  if (this.otpVerification.attempts >= 3) {
    return {
      success: false,
      status: 429,
      message: "Too many failed attempts. Please request a new OTP.",
    };
  }

  // Check expiry
  if (this.otpVerification.expiry < new Date()) {
    return {
      success: false,
      status: 403,
      message: "The OTP has expired. Please request a new one.",
    };
  }

  // Compare OTP
  if (parseInt(this.otpVerification.otp) !== parseInt(otp)) {
    return {
      success: false,
      status: 401,
      message: "The OTP you entered is incorrect. Please try again.",
    };
  }

  // Reset OTP on successful verification
  this.otpVerification = undefined;
  return {
    success: true,
    status: 200,
    message: "OTP verified successfully",
  };
};

export const User = model("User", userSchema);
