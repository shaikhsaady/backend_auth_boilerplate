import { OAuth2Client } from "google-auth-library";
import axios from "axios";

// Environment configuration with validation
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const FB_APP_ID = process.env.FB_APP_ID;
const FB_APP_SECRET = process.env.FB_APP_SECRET;

// Validate environment variables
[GOOGLE_CLIENT_ID, FB_APP_ID, FB_APP_SECRET].forEach((secret) => {
  if (!secret) throw new Error(`${secret} environment variable is not defined`);
});

// Google client
const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

// Verify social tokens
export async function verifySocialToken(provider, token) {
  switch (provider.toLowerCase()) {
    // Google
    case "google": {
      // Verify token with Google
      const ticket = await googleClient.verifyIdToken({
        idToken: token,
        audience: GOOGLE_CLIENT_ID,
      });

      // Validate ticket
      if (!ticket) {
        throw new Error("Invalid Google token");
      }

      // Get payload
      const payload = ticket.getPayload();

      // Validate payload
      if (!payload) {
        throw new Error("Invalid Google token");
      }

      // Validate issuer
      if (
        !["accounts.google.com", "https://accounts.google.com"].includes(
          payload.iss
        )
      ) {
        throw new Error("Invalid Google token");
      }

      // Format name
      const parts = payload.name.trim().split(/\s+/);

      // Return payload
      return {
        social_id: payload.sub,
        email: payload.email,
        email_verified: payload.email_verified,
        fullName: payload.name,
        profilePic: payload.picture,
        provider: provider.toLowerCase(),
        firstName: parts[0],
        lastName: parts.slice(1).join(" "),
      };
    }

    // Facebook
    case "facebook": {
      // Validate with FB Debug API
      const appToken = `${FB_APP_ID}|${FB_APP_SECRET}`;

      // Verify token with Facebook
      const { data: debug } = await axios.get(
        `https://graph.facebook.com/debug_token?input_token=${token}&access_token=${appToken}`
      );

      // Validate token
      if (!debug.data || !debug.data.is_valid) {
        throw new Error("Invalid Facebook token");
      }

      // Get profile
      const { data: profile } = await axios.get(
        `https://graph.facebook.com/me?fields=id,name,email,picture&access_token=${token}`
      );

      // Validate profile
      if (!profile) {
        throw new Error("Invalid Facebook token");
      }

      // Format name
      const parts = profile.name.trim().split(/\s+/);

      // Return profile
      return {
        social_id: profile.id,
        email: profile.email,
        email_verified: true,
        fullName: profile.name,
        profilePic: profile.picture.data.url,
        provider: provider.toLowerCase(),
        firstName: parts[0],
        lastName: parts.slice(1).join(" "),
      };
    }

    default:
      throw new Error(`Unsupported provider ${provider}`);
  }
}
