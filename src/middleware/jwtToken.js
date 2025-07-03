import jwt from "jsonwebtoken";
import { promisify } from "util";
import crypto from "crypto";

// Environment configuration with validation
const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET;
const ACCESS_TOKEN_EXPIRATION = process.env.ACCESS_TOKEN_EXPIRATION;
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET;
const REFRESH_TOKEN_EXPIRATION = process.env.REFRESH_TOKEN_EXPIRATION;
const JWT_ISSUER = process.env.JWT_ISSUER;
const JWT_AUDIENCE = process.env.JWT_AUDIENCE;

// Validate environment variables
[ACCESS_TOKEN_SECRET, REFRESH_TOKEN_SECRET].forEach((secret) => {
  if (!secret) throw new Error(`${secret} environment variable is not defined`);
});

/**
 * Generates a JWT authentication token for a user
 * @param {Object} user - User object to encode in the token
 * @param {string} user._id - User ID (required)
 * @returns {Promise<string>} Promise resolving to "Bearer <token>"
 * @throws {Error} If token generation fails or input is invalid
 */
export const generateAuthToken = async (user) => {
  // Validate user input
  if (!user || typeof user !== "object") {
    throw new TypeError("User object must be provided");
  }
  if (!user._id) {
    throw new Error("User object must contain id property");
  }

  try {
    // Generate unique jti for refresh token
    const jti = crypto.randomBytes(16).toString("hex");

    // Create promisified version of jwt.sign
    const signAsync = promisify(jwt.sign);

    // Generate token with essential claims
    const accessToken = await signAsync(
      {
        _id: user._id,
        jti,
      },
      ACCESS_TOKEN_SECRET,
      {
        expiresIn: ACCESS_TOKEN_EXPIRATION,
        algorithm: "HS256", // Explicitly specify algorithm
        // Add standard claims for security
        issuer: JWT_ISSUER, // Issuer
        audience: JWT_AUDIENCE, // Audience
      }
    );

    // Generate refresh token
    const refreshToken = jwt.sign(
      { _id: user._id, jti },
      REFRESH_TOKEN_SECRET,
      {
        expiresIn: REFRESH_TOKEN_EXPIRATION,
        algorithm: "HS256", // Explicitly specify algorithm
        // Add standard claims for security
        issuer: JWT_ISSUER, // Issuer
        audience: JWT_AUDIENCE, // Audience
      }
    );

    return {
      accessToken: `Bearer ${accessToken}`,
      refreshToken,
      jti,
    };
  } catch (error) {
    // Enhance error messages for better debugging
    const errorMessage = `Token generation failed: ${error.message}`;
    throw new Error(errorMessage);
  }
};
