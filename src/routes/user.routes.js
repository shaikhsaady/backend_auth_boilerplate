import { Router } from "express";
import { asyncHandler } from "../middleware/errorMiddleware.js";
import passportMiddleware from "../middleware/passportMiddleware.js";
import { getUser, updateProfile } from "../controller/user.controller.js";
import { profileImageUpload } from "../middleware/uploadMiddleware.js";

// auth routes
export const userRoutes = Router();

// get-user
userRoutes.get("/getUser", passportMiddleware, asyncHandler(getUser));

// update-profile
userRoutes.put(
  "/updateProfile",
  passportMiddleware,
  profileImageUpload,
  asyncHandler(updateProfile)
);
