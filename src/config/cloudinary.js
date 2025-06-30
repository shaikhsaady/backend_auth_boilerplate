import { v2 as cloudinary } from "cloudinary";
import streamifier from "streamifier";

// Environment configuration with validation
const CLOUDINARY_CLOUD_NAME = process.env.CLOUDINARY_CLOUD_NAME;
const CLOUDINARY_API_KEY = process.env.CLOUDINARY_API_KEY;
const CLOUDINARY_API_SECRET = process.env.CLOUDINARY_API_SECRET;

// Validate environment variables
[CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, CLOUDINARY_API_SECRET].forEach(
  (secret) => {
    if (!secret)
      throw new Error(`${secret} environment variable is not defined`);
  }
);

// cloudinary config
cloudinary.config({
  cloud_name: CLOUDINARY_CLOUD_NAME,
  api_key: CLOUDINARY_API_KEY,
  api_secret: CLOUDINARY_API_SECRET,
  secure: true,
});

// Upload buffer to Cloudinary
export const uploadStream = (buffer, folder) => {
  return new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream(
      { folder, resource_type: "auto" },
      (error, result) => {
        if (result) resolve(result);
        else reject(error);
      }
    );
    streamifier.createReadStream(buffer).pipe(stream);
  });
};

// Delete existing Cloudinary asset
export const deleteAsset = async (publicId) => {
  if (!publicId) return;
  try {
    await cloudinary.uploader.destroy(publicId);
  } catch (error) {
    let errorMessage = `Cloudinary deletion error: ${publicId} ${error.message}`;
    throw new Error(errorMessage);
  }
};

export default cloudinary;
