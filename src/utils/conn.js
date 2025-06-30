import mongoose from "mongoose";

// Maintain a cached connection to prevent repeated connections
let cachedConnection = null;

// Environment Variables
const DB_URI = process.env.DB_URI;
const DB_NAME = process.env.DB_NAME;

/**
 * Establishes a connection to MongoDB with optimized settings
 * @returns {Promise<void>} Resolves when connected or rejects on error
 */
export async function connectDB() {
  // Return cached connection if available
  if (cachedConnection) {
    return cachedConnection;
  }

  // Validate environment variable
  if (!DB_URI) {
    throw new Error("DB_URI environment variable is not defined");
  }

  // Configure global Mongoose settings
  mongoose.set("strictQuery", false); // Prepare for Mongoose 7 changes
  mongoose.set("bufferCommands", false); // Fail fast when not connected
  mongoose.set("autoIndex", true); // Optimized for development (disable in prod)

  try {
    // Create connection promise and cache it
    cachedConnection = mongoose.connect(DB_URI, {
      serverSelectionTimeoutMS: 5000, // 5s server selection timeout
      maxPoolSize: 10, // Maximum connection pool size
      minPoolSize: 2, // Maintain minimum connections
      socketTimeoutMS: 45000, // Close sockets after 45s inactivity
      family: 4, // Use IPv4, skip IPv6
      dbName: DB_NAME, // Database name
    });

    await cachedConnection;
    console.log("DATABASE CONNECTED SUCCESSFULLY 🚀");

    // Setup event listeners for connection management
    mongoose.connection.on("error", (err) => {
      console.error(`Database connection error: ${err.message}`);
    });

    mongoose.connection.on("disconnected", () => {
      console.warn("Database connection lost");
      cachedConnection = null; // Reset cache for reconnection
    });

    return cachedConnection;
  } catch (error) {
    // Reset cache on failure
    cachedConnection = null;
    console.error(`DATABASE CONNECTION FAILED: ${error.message}`);
    throw new Error(`Database connection failed: ${error.message}`);
  }
}
