/**
 * Middleware to handle 404 Not Found errors
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 */
export const notFoundHandler = (req, res, next) => {
  res.status(404);
  const error = new Error(`🔍 Not Found - ${req.method} ${req.originalUrl}`);
  next(error);
};

/**
 * Central error handling middleware
 * @param {Error} err - Error object
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 */
export const errorHandler = (err, req, res, next) => {
  // Determine status code: use existing or default to 500
  const statusCode = res.statusCode >= 400 ? res.statusCode : 500;

  // Prepare error response
  const errorResponse = {
    success: false,
    message: err.message,
    type: err.name,
  };

  // Add stack trace in development environment
  if (process.env.NODE_ENV !== "production") {
    errorResponse.stack = err.stack;

    // Detailed error logging for debugging
    console.error(`[${new Date().toISOString()}] Error: ${err.message}`);
    console.error(`Path: ${req.method} ${req.originalUrl}`);
    if (err.stack) console.error(`Stack: ${err.stack}`);
  }

  // Special handling for production errors
  if (statusCode >= 500 && process.env.NODE_ENV === "production") {
    // Obfuscate server errors in production
    errorResponse.message = "Internal Server Error";
    // Log full production errors internally
    console.error(
      `[PROD ERROR] ${err.name}: ${err.message} at ${req.originalUrl}`
    );
  }

  // Send JSON response
  res.status(statusCode).json(errorResponse);
};

/**
 * Asynchronous error wrapper for Express routes
 * @param {Function} fn - Async route handler function
 * @returns {Function} Wrapped middleware function
 */
export const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};
