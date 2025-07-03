import jwt from "jsonwebtoken";
import { promisify } from "util";
import { User } from "../models/user.js";

const verifyAsync = promisify(jwt.verify);
const TAG = "PassportMiddleware";

// Environment Variables
const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET;
const JWT_ISSUER = process.env.JWT_ISSUER;
const JWT_AUDIENCE = process.env.JWT_AUDIENCE;
const ENVIRONMENT = process.env.NODE_ENV;

/**
 * Authentication middleware for Express applications
 * - Verifies JWT tokens in Authorization header
 * - Attaches decoded user payload to request object
 * - Handles various token verification errors appropriately
 */
export default async function passportMiddleware(req, res, next) {
  try {
    // 1. Extract and validate Authorization header
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      return res.status(401).json({
        status: false,
        message: "Authorization token required",
      });
    }

    // 2. Validate token structure
    const [scheme, token] = authHeader.split(" ");

    // Validate scheme and token presence
    if (!scheme || scheme.toLowerCase() !== "bearer") {
      return res.status(401).json({
        status: false,
        message: "Invalid authentication scheme. Use 'Bearer'",
      });
    }

    if (!token || token === "undefined") {
      return res.status(401).json({
        status: false,
        message: "Malformed authentication token",
      });
    }

    // 3. Verify token and handle errors
    const decoded = await verifyAsync(token, ACCESS_TOKEN_SECRET, {
      algorithms: ["HS256"], // Prevent algorithm switching attacks
      issuer: JWT_ISSUER, // Validate issuer if set
      audience: JWT_AUDIENCE, // Validate audience if set
      clockTolerance: 15, // 15-second grace period for clock skew
    });

    // check if _id is present in the decoded
    if (!decoded._id) {
      return res.status(401).json({
        success: false,
        message: "Invalid session. Please log in again.",
      });
    }
    
    // 4. Check if jti is present in the database
    const user = await User.findById(decoded._id).select("+jti -password -__v");

    // check if user exists
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found.",
      });
    }

    // check if jti is present in the user
    if (!user.jti) {
      return res.status(401).json({
        success: false,
        message: "Invalid session. Please log in again.",
      });
    }

    // replace jti from user with current jti
    user._doc.jti = decoded.jti;

    // 5. Attach user to request
    req.user = user;

    // 6. Continue to next middleware
    return next();
  } catch (error) {
    // Handle specific JWT errors
    let statusCode = 401;
    let message = "Authentication failed";

    switch (error.name) {
      case "TokenExpiredError":
        message = "Session expired. Please log in again";
        break;
      case "JsonWebTokenError":
        message = "Invalid authentication token";
        break;
      case "NotBeforeError":
        message = "Token not yet valid";
        break;
      default:
        statusCode = 500;
        message = "Authentication processing error";
        console.error(`${TAG}: Internal error`, error.stack);
    }

    return res.status(statusCode).json({
      status: false,
      message,
      // Include error details in development
      ...(ENVIRONMENT !== "production" && {
        error: error.name,
        stack: error.message,
      }),
    });
  }
}
