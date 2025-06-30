import { Router } from "express";
import { asyncHandler } from "../middleware/errorMiddleware.js";
import {
  login,
  otpVerify,
  register,
  sendOtp,
  changePassword,
  logout,
  refreshAccessToken,
  deleteAccount,
  socialLogin,
} from "../controller/auth.controller.js";
import passportMiddleware from "../middleware/passportMiddleware.js";

// auth routes
export const authRoutes = Router();

// Register
authRoutes.post("/register", asyncHandler(register));

// otpVerify otp
authRoutes.post("/otpVerify", asyncHandler(otpVerify));

// sendOtp
authRoutes.post("/sendOtp", asyncHandler(sendOtp));

// Login
authRoutes.post("/login", asyncHandler(login));

// change-password
authRoutes.post("/change-password", asyncHandler(changePassword));

// refresh-token
authRoutes.post("/refresh-token", asyncHandler(refreshAccessToken));

// social-login
authRoutes.post("/social-login", asyncHandler(socialLogin));

// logout
authRoutes.post("/logout", passportMiddleware, asyncHandler(logout));

// delete-account
authRoutes.delete(
  "/delete-account",
  passportMiddleware,
  asyncHandler(deleteAccount)
);
