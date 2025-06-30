import "dotenv/config";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import passport from "passport";
import morgan from "morgan";
import compression from "compression";
import rateLimit from "express-rate-limit";
import { connectDB } from "./utils/conn.js";
import { notFoundHandler, errorHandler } from "./middleware/errorMiddleware.js";
import { authRoutes } from "./routes/auth.routes.js";
import { userRoutes } from "./routes/user.routes.js";

// Environment Variables
const PORT = process.env.PORT || 4000;
const ENVIRONMENT = process.env.NODE_ENV || "development";
const BODY_LIMIT = process.env.BODY_LIMIT || "200mb";
const CORS_ORIGIN = process.env.CORS_ORIGIN || "*";

// Initialize Express app
const app = express();

// ======================
// Trust Proxy Configuration
// ======================
app.set("trust proxy", 1);

// ======================
// Security Middleware
// ======================
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:"],
      },
    },
    hsts: { maxAge: 31536000, includeSubDomains: true },
  })
);

app.use(
  cors({
    origin: CORS_ORIGIN,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  })
);

// ======================
// Rate Limiting
// ======================
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 500, // Max requests per window
  standardHeaders: true,
  legacyHeaders: false,
  message: "Too many requests from this IP, please try again later",
});

app.use(limiter);

// ======================
// Request Parsing
// ======================
app.use(
  express.json({
    limit: BODY_LIMIT,
    verify: (req, res, buf) => {
      req.rawBody = buf; // Preserve raw body for signature verification
    },
  })
);

app.use(
  express.urlencoded({
    limit: BODY_LIMIT,
    extended: true,
  })
);

// ======================
// Compression
// ======================
app.use(compression({ level: 6 }));

// ======================
// Logging
// ======================
const logFormat = ENVIRONMENT === "development" ? "dev" : "combined";
app.use(
  morgan(logFormat, {
    skip: (req, res) => ENVIRONMENT !== "development" && res.statusCode < 400,
  })
);

// ======================
// Authentication
// ======================
app.use(passport.initialize());

// Simplified session handling - Consider Redis for production
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

// ======================
// Routes
// ======================
// Health check (minimal middleware)
app.get("/health", (req, res) =>
  res.status(200).json({
    status: "ok",
    timestamp: new Date().toISOString(),
    environment: ENVIRONMENT,
  })
);

// Add this favicon handler here
app.get("/favicon.ico", (req, res) => res.status(204).end());

// Root route
app.use("/api/auth", authRoutes);
app.use("/api/user", userRoutes);
app.get("/", (req, res) => {
  res.json({
    success: true,
    data: "Server is running successfully!",
    environment: ENVIRONMENT,
  });
});

// ======================
// Error Handling
// ======================
app.use(notFoundHandler);
app.use(errorHandler);

// ======================
// Server Initialization
// ======================
const startServer = async () => {
  try {
    await connectDB();

    const server = app.listen(PORT, () => {
      console.log(`
        🚀 Server running in ${ENVIRONMENT} mode
        🔗 http://localhost:${PORT}
        📅 ${new Date().toLocaleString()}
      `);
    });

    // Graceful shutdown
    const shutdown = async () => {
      console.log("\n🛑 Received shutdown signal. Closing server...");
      server.close(async () => {
        console.log("✅ HTTP server closed");
        process.exit(0);
      });

      // Force shutdown after timeout
      setTimeout(() => {
        console.log("❌ Forcing shutdown after timeout");
        process.exit(1);
      }, 10000).unref();
    };

    process.on("SIGINT", shutdown);
    process.on("SIGTERM", shutdown);
  } catch (error) {
    console.log("⛔ Server startup failed:", error);
    process.exit(1);
  }
};

// Unhandled error prevention
process.on("uncaughtException", (err) => {
  console.log("Uncaught Exception:", err);
  process.exit(1);
});

process.on("unhandledRejection", (reason, promise) => {
  console.log("Unhandled Rejection at:", promise, "Reason:", reason);
});

startServer();
