import multer from "multer";

// Multer storage
const storage = multer.memoryStorage();

// Multer upload
const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
  fileFilter: (req, file, cb) => {
    const validMimes = ["image/jpeg", "image/png", "image/webp"];
    if (validMimes.includes(file.mimetype)) cb(null, true);
    else cb(new Error("Invalid file type. Only images are allowed"), false);
  },
});

// Single file middleware with error handling
export const profileImageUpload = (req, res, next) => {
  upload.single("profileImage")(req, res, (err) => {
    if (err) {
      let message = err.message;
      if (err instanceof multer.MulterError) {
        message = `File too large. Max ${Math.floor(
          upload.limits.fileSize / 1024 / 1024
        )}MB allowed`;
      }
      return res.status(400).json({ success: false, message });
    }
    next();
  });
};
