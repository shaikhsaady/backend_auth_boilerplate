import mongoose from "mongoose";
import { generateAuthToken } from "../middleware/jwtToken.js";
import { User } from "../models/user.js";
import validator from "validator";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import { promisify } from "util";
import { deleteAsset } from "../config/cloudinary.js";
import { sendEmail } from "../middleware/emailService.js";
import { verifySocialToken } from "../validators/verifySocial.js";

const verifyAsync = promisify(jwt.verify);

// Environment configuration with validation
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET;
const JWT_ISSUER = process.env.JWT_ISSUER;
const JWT_AUDIENCE = process.env.JWT_AUDIENCE;

/**
 * Register a new user
 * - Validates input data
 * - Checks for existing user
 * - Creates user with hashed password
 * - Sends verification email
 */
export const register = async (req, res, next) => {
  try {
    // Destructure request body
    const { firstName, lastName, email, password, deviceToken } = req.body;

    // Validate required fields
    const requiredFields = ["firstName", "lastName", "email", "password"];
    const missingFields = requiredFields.filter((field) => !req.body[field]);

    if (missingFields.length > 0) {
      return res.status(400).json({
        success: false,
        message: `Missing required fields: ${missingFields.join(", ")}`,
      });
    }

    // Validate email format
    if (!validator.isEmail(email)) {
      return res.status(400).json({
        success: false,
        message: "Please provide a valid email address",
      });
    }

    // Validate password strength
    if (
      !validator.isStrongPassword(password, {
        minLength: 8,
        minLowercase: 1,
        minUppercase: 1,
        minNumbers: 1,
        minSymbols: 1,
      })
    ) {
      return res.status(400).json({
        success: false,
        message:
          "Password must be at least 8 characters with 1 uppercase, 1 lowercase, 1 number, and 1 symbol",
      });
    }

    // Check for existing user
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: "Email address is already registered",
      });
    }

    // Create user with OTP
    const user = new User({
      firstName: validator.escape(firstName),
      lastName: validator.escape(lastName),
      email: email,
      password,
      deviceTokens: deviceToken ? [deviceToken] : [],
    });

    // Generate and save OTP
    const otp = user.generateOTP();

    // Save user
    await user.save();

    // Subject and message
    const subject = "Please verify your email address.";
    const text = `Thanks for signing up! Here is your OTP: ${otp}`;

    // Send email
    sendEmail({ to: user.email, subject, text });

    // Successful response
    res.status(201).json({
      success: true,
      message: "Verification OTP sent to your email",
      // Return minimal user info without sensitive data
      userData: {
        _id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
      },
    });
  } catch (error) {
    // Pass to error middleware
    next(error);
  }
};

/**
 * Verify OTP and activate user account
 * - Validates OTP format
 * - Checks OTP validity and expiration
 * - Activates user account
 * - Generates authentication token
 */
export const otpVerify = async (req, res, next) => {
  try {
    // Destructure request body
    const { email, otp, purpose } = req.body;

    // Validate input presence
    if (!email || !otp || !purpose) {
      return res.status(400).json({
        success: false,
        message: "Email, OTP and purpose are required",
      });
    }

    // Validate OTP format
    if (!otp || !/^\d{6}$/.test(otp)) {
      return res.status(400).json({
        success: false,
        message: "Invalid OTP format. Must be 6 digits",
      });
    }

    // Validate email format
    if (!validator.isEmail(email)) {
      return res.status(400).json({
        success: false,
        message: "Please provide a valid email address",
      });
    }

    // Validate purpose
    const validPurposes = ["account_verification", "password_reset"];
    if (!validPurposes.includes(purpose)) {
      return res.status(400).json({
        success: false,
        message: "Invalid verification purpose",
      });
    }

    // Find user by email (exact match)
    const user = await User.findOne({ email }).select(
      "otpVerification _id isVerified"
    );

    // User not found
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "Email not registered",
      });
    }

    // Account already verified
    if (user.isVerified && purpose === "account_verification") {
      return res.status(400).json({
        success: false,
        message: "Account already verified",
      });
    }

    // Update attempts atomically
    await User.findByIdAndUpdate(user._id, {
      $inc: { "otpVerification.attempts": 1 },
    });

    // Verify OTP
    const { success, status, message } = user.verifyOTP(otp);
    if (!success) {
      return res.status(status).json({
        success,
        message,
      });
    }

    // Password reset purpose
    if (purpose === "password_reset" && user.isVerified) {
      // Generate reset token and hash it
      const resetToken = crypto.randomBytes(32).toString("hex");
      const tokenHash = crypto
        .createHash("sha256")
        .update(resetToken)
        .digest("hex");
      const resetTokenExpiry = Date.now() + 15 * 60000; // 15 minutes

      // Update user with reset token and expiry
      await User.findByIdAndUpdate(
        user._id,
        {
          $unset: { otpVerification: 1 },
          $set: {
            passwordResetToken: tokenHash,
            passwordResetTokenExpiry: resetTokenExpiry,
          },
        },
        { new: true, select: "-password -__v" }
      );

      // Successful response
      const response = {
        success: true,
        message: "OTP verified. You can now reset your password",
        resetToken,
        resetTokenExpiry,
      };
      return res.status(200).json(response);
    }

    // Get current time
    const currentTime = Date.now();

    // Successful verification - update user and generate token
    const { accessToken, refreshToken, jti } = await generateAuthToken({
      _id: user._id,
    });

    // Update user with last verified and jti
    const updatedUser = await User.findByIdAndUpdate(
      user._id,
      {
        $unset: { otpVerification: 1 },
        $set: { isVerified: true, lastVerified: currentTime },
        $push: { jti },
      },
      { new: true, select: "-password -__v" }
    ).lean();

    // Add virtual fullName
    const userResponse = {
      ...updatedUser,
      fullName: `${updatedUser.firstName} ${updatedUser.lastName}`,
    };

    // tokens
    const token = {
      accessToken,
      refreshToken,
    };

    return res.status(200).json({
      success: true,
      message: "Account verified successfully",
      user: userResponse,
      token,
    });
  } catch (error) {
    // Pass to error middleware
    next(error);
  }
};

/**
 * Send OTP to user's email
 * - Validates email format
 * - Checks if user is already verified
 * - Generates new OTP
 * - Sends email asynchronously
 */
export const sendOtp = async (req, res, next) => {
  try {
    // Destructure request body
    const { email } = req.body;

    // Validate input
    if (!email) {
      return res.status(400).json({
        success: false,
        message: "Email is required",
      });
    }

    // Validate email format
    if (!validator.isEmail(email)) {
      return res.status(400).json({
        success: false,
        message: "Please provide a valid email address",
      });
    }

    // Find user with optimized projection
    const user = await User.findOne({ email });

    // User not found
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "Email not registered",
      });
    }

    // Generate new OTP using schema method
    const newOtp = user.generateOTP();

    // Subject and message
    const subject = "New OTP";
    const text = `Here is your new OTP: ${newOtp}`;

    // Send email
    sendEmail({ to: user.email, subject, text });

    // Save the updated user document
    await user.save();

    return res.status(200).json({
      success: true,
      message: "OTP sent to your email",
    });
  } catch (error) {
    // Pass to error middleware
    next(error);
  }
};

/**
 * Login user
 * - Validates input data
 * - Checks if user exists
 * - Validates password
 * - Generates authentication token
 * - Handles verification status
 * - Handles device token
 */
export const login = async (req, res, next) => {
  try {
    // Destructure request body
    const { email, password, deviceToken } = req.body;

    // Validate required fields
    const requiredFields = ["email", "password"];
    const missingFields = requiredFields.filter((field) => !req.body[field]);

    if (missingFields.length > 0) {
      return res.status(400).json({
        success: false,
        message: `Missing required fields: ${missingFields.join(", ")}`,
      });
    }

    // Validate email format
    if (!validator.isEmail(email)) {
      return res.status(400).json({
        success: false,
        message: "Please provide a valid email address",
      });
    }

    // Find user by email with password
    const user = await User.findOne({ email }).select("+password +jti");

    // User not found
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "Email not registered",
      });
    }

    if (user.jti.length >= 4) {
      return res.status(401).json({
        success: false,
        message: "You can only login on max 4 devices.",
      });
    }
    // check if password is not exists
    if (!user.password) {
      return res.status(401).json({
        success: false,
        message: "The password you provided is incorrect.",
      });
    }

    // Check if password is correct
    const isPasswordCorrect = await user.comparePassword(password);
    if (!isPasswordCorrect) {
      return res.status(401).json({
        success: false,
        message: "The password you provided is incorrect.",
      });
    }

    // If user is not verified
    if (!user.isVerified) {
      // Generate new OTP using schema method
      const newOtp = user.generateOTP();

      // Save the updated user document
      await user.save();

      return res.status(200).json({
        success: true,
        message: "Please Check Your Email For Confirmation.",
      });
    }

    // If user is verified then generate token
    const { accessToken, refreshToken, jti } = await generateAuthToken({
      _id: user._id,
    });

    // Update user with device token
    const updatedUser = await User.findByIdAndUpdate(
      user._id,
      {
        $push: { deviceTokens: deviceToken, jti },
      },
      {
        new: true,
        select: "-password -__v",
      }
    ).lean();

    // Add virtual fullName
    const userResponse = {
      ...updatedUser,
      fullName: `${updatedUser.firstName} ${updatedUser.lastName}`,
    };

    // tokens
    const token = {
      accessToken,
      refreshToken,
    };

    return res.status(200).json({
      success: true,
      message: "Login successful",
      user: userResponse,
      token,
    });
  } catch (error) {
    // Pass to error middleware
    next(error);
  }
};

/**
 * Change password
 * - Validates input data
 * - Checks if reset token is valid
 * - Validates new password
 * - Updates user password
 * - Clears reset token
 * - Returns success message
 */
export const changePassword = async (req, res, next) => {
  try {
    // Destructure request body
    const { resetToken, newPassword } = req.body;

    // Validate required fields
    const requiredFields = ["resetToken", "newPassword"];
    const missingFields = requiredFields.filter((field) => !req.body[field]);

    if (missingFields.length > 0) {
      return res.status(400).json({
        success: false,
        message: `Missing required fields: ${missingFields.join(", ")}`,
      });
    }

    // Hash reset token
    const tokenHash = crypto
      .createHash("sha256")
      .update(resetToken)
      .digest("hex");

    // Find user by reset token
    const user = await User.findOne({
      passwordResetToken: tokenHash,
      passwordResetTokenExpiry: { $gt: Date.now() },
    });

    // User not found
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "Invalid or expired reset token",
      });
    }

    // Check if new password is strong
    if (!validator.isStrongPassword(newPassword)) {
      return res.status(400).json({
        success: false,
        message:
          "New password must be at least 8 characters with 1 uppercase, 1 lowercase, 1 number, and 1 symbol",
      });
    }

    // Update user password
    user.password = newPassword;
    user.passwordResetToken = undefined;
    user.passwordResetTokenExpiry = undefined;
    await user.save();

    return res.status(200).json({
      success: true,
      message: "Password Changed! Login Again",
    });
  } catch (error) {
    // Pass to error middleware
    next(error);
  }
};

/**
 * Logout user
 * - Validates input data
 * - Clears device token
 * - Returns success message
 */
export const logout = async (req, res, next) => {
  try {
    // Destructure request body
    const { deviceToken } = req.body;

    // check if user is authenticated
    if (!req.user._id) {
      return res.status(401).json({
        success: false,
        message: "User not authenticated.",
      });
    }
    
    // find user by id
    await User.findByIdAndUpdate(
      req.user._id,
      {
        $pull: { deviceTokens: { $in: [deviceToken] }, jti: req.user.jti },
      },
      { new: true }
    );

    return res.status(200).json({
      success: true,
      message: "Logout successful",
    });
  } catch (error) {
    // Pass to error middleware
    next(error);
  }
};

/**
 * Refresh access token
 * - Validates refresh token
 * - Checks if user exists
 * - Generates new access token
 * - Returns new access token
 */
export const refreshAccessToken = async (req, res, next) => {
  try {
    // Destructure request body
    const { refresh_token } = req.body;

    // Validate refresh_token
    if (!refresh_token) {
      return res.status(400).json({
        success: false,
        message: "Refresh token is required",
      });
    }

    // 3. Verify token and handle errors
    const decoded = await verifyAsync(refresh_token, REFRESH_TOKEN_SECRET, {
      algorithms: ["HS256"], // Prevent algorithm switching attacks
      issuer: JWT_ISSUER, // Validate issuer if set
      audience: JWT_AUDIENCE, // Validate audience if set
      clockTolerance: 15, // 15-second grace period for clock skew
    });

    // Verify if token is valid
    if (!decoded) {
      return res.status(401).json({
        success: false,
        message: "Invalid refresh token or expired login again",
      });
    }

    // check if user exists
    const user = await User.findOne({
      _id: decoded._id,
      jti: { $in: [decoded.jti] },
    });

    //  user not found
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "Invalid refresh token or expired login again",
      });
    }

    // If user is verified then generate token
    const { accessToken, refreshToken, jti } = await generateAuthToken({
      _id: user._id,
    });

    // Update user
    await User.findByIdAndUpdate(
      user._id,
      {
        $pull: { jti: decoded.jti }, // Remove the old 'decoded.jti' from the array
        $push: { jti: jti },
      },
      { new: true, select: "-password -__v" }
    );

    // tokens
    const token = {
      accessToken,
      refreshToken,
    };

    return res.status(200).json({
      success: true,
      message: "Token refreshed successfully",
      token,
    });
  } catch (error) {
    // Pass to error middleware
    next(error);
  }
};

/**
 * Social login
 * - Validates input data
 * - Checks if user exists
 * - Generates authentication token
 * - Handles verification status
 * - Handles device token
 */
export const socialLogin = async (req, res, next) => {
  try {
    // Destructure request body
    const { provider, token, deviceToken } = req.body;

    // Validate required fields
    const requiredFields = ["provider", "token"];
    const missingFields = requiredFields.filter((field) => !req.body[field]);

    if (missingFields.length > 0) {
      return res.status(400).json({
        success: false,
        message: `Missing required fields: ${missingFields.join(", ")}`,
      });
    }

    // Verify social token
    const verifiedToken = await verifySocialToken(provider, token);

    // if social token is invalid
    if (!verifiedToken.email) {
      return res.status(404).json({
        success: false,
        message: "Invalid social token",
      });
    }

    // find user by email
    let user = await User.findOne({
      email: verifiedToken.email,
    }).select("+socialInfo +jti");

    // if user is not found
    if (!user) {
      // create new user
      const newUser = new User({
        firstName: verifiedToken.firstName,
        lastName: verifiedToken.lastName,
        email: verifiedToken.email,
        isVerified: verifiedToken.email_verified,
        provider: verifiedToken.provider,
        deviceTokens: deviceToken ? [deviceToken] : [],
        lastVerified: Date.now(),
        profilePic: verifiedToken.profilePic
          ? {
              url: verifiedToken.profilePic,
              publicId: "",
            }
          : null,
        socialInfo: [
          {
            provider: verifiedToken.provider,
            socialId: verifiedToken.social_id,
          },
        ],
      });

      // save user
      await newUser.save();

      // update user
      user = newUser;
    }

    if (user.jti.length >= 4) {
      return res.status(400).json({
        success: false,
        message: "You can only login on max 4 devices.",
      });
    }
    // generate token
    const { accessToken, refreshToken, jti } = await generateAuthToken({
      _id: user._id,
    });

    // Prepare update operations
    const updateOps = {
      $set: {
        provider: verifiedToken.provider,
      },
      $push: {
        jti: jti,
      },
    };

    // Add device token if new
    if (deviceToken) {
      updateOps.$addToSet = { deviceTokens: deviceToken };
    }

    // Check if provider exists
    const providerExists = user.socialInfo.some(
      (info) => info.provider === verifiedToken.provider
    );

    // Add new provider if not exists
    if (!providerExists) {
      updateOps.$push.socialInfo = {
        provider: verifiedToken.provider,
        socialId: verifiedToken.social_id,
      };
    }

    // update user
    const updatedUser = await User.findByIdAndUpdate(user._id, updateOps, {
      new: true,
      select: "-password -__v",
    }).lean();

    // add virtual fullName and profilePic
    const userResponse = {
      ...updatedUser,
      profilePic: updatedUser.profilePic?.url,
      fullName: `${updatedUser.firstName} ${updatedUser.lastName}`,
    };

    // tokens
    const tokens = {
      accessToken,
      refreshToken,
    };

    // return response
    return res.status(200).json({
      success: true,
      message: "Login successful",
      user: userResponse,
      token: tokens,
    });
  } catch (error) {
    // Pass to error middleware
    next(error);
  }
};

/**
 * Delete user account
 * - Validates input data
 * - Deletes user account
 * - Returns success message
 */
export const deleteAccount = async (req, res, next) => {
  // mongoose session
  const session = await mongoose.startSession();

  try {
    // Destructure user id
    const userId = req.user._id;

    // Destructure old public id
    const oldPublicId = req.user.profilePic?.publicId || null;

    // check if user is authenticated
    if (!userId) {
      return res.status(401).json({
        success: false,
        message: "User not authenticated.",
      });
    }

    // delete old profile pic from cloudinary
    if (oldPublicId) {
      await deleteAsset(oldPublicId);
    }

    // start transaction
    session.startTransaction();

    // delete another collection data
    // await collection_name.deleteMany({ user: userId }).session(session);

    // Delete user account
    const deleteResult = await User.deleteOne({ _id: userId }).session(session);

    // if user not found
    if (deleteResult.deletedCount === 0) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    // commit transaction
    await session.commitTransaction();

    // return success message
    return res.status(200).json({
      success: true,
      message: "Account deleted successfully",
    });
  } catch (error) {
    // rollback transaction
    await session.abortTransaction();

    // Pass to error middleware
    next(error);
  } finally {
    // end session
    session.endSession();
  }
};
