import { deleteAsset, uploadStream } from "../config/cloudinary.js";
import { User } from "../models/user.js";

/**
 * Get user
 * - Validates if user is authenticated
 * - Finds user by id
 * - Returns user data
 */
export const getUser = async (req, res, next) => {
  try {
    // check if user is authenticated
    if (!req.user._id) {
      return res.status(401).json({
        success: false,
        message: "User not authenticated.",
      });
    }

    // return user
    return res.status(200).json({
      success: true,
      user: req.user,
    });
  } catch (error) {
    // Pass to error middleware
    next(error);
  }
};

/**
 * Update user profile
 * - Validates if user is authenticated
 * - Updates user profile
 * - Returns updated user data
 */
export const updateProfile = async (req, res, next) => {
  try {
    // Destructure request body
    const { firstName, lastName, phoneNo } = req.body;

    // Destructure user id
    const userId = req.user._id;

    // Check if user id is present
    if (!userId) {
      return res.status(401).json({
        success: false,
        message: "User not authenticated.",
      });
    }

    // Initialize old public id
    let oldPublicId = null;

    // Initialize new image data
    let newImageData = null;

    // Initialize update data
    const updateData = {
      ...(firstName && { firstName }),
      ...(lastName && { lastName }),
      ...(phoneNo && { phoneNo }),
    };

    // Handle file upload transactionally
    if (req.file) {
      // 1. Upload new image first
      const uploadResult = await uploadStream(req.file.buffer, "user-profiles");

      newImageData = {
        url: uploadResult.secure_url,
        publicId: uploadResult.public_id,
      };

      // 2. Get old public ID for cleanup
      const currentUser = await User.findById(userId).select("profilePic");

      oldPublicId = currentUser?.profilePic?.publicId || null;

      // 3. Add to update
      updateData.profilePic = newImageData;
    }

    // 4. Update user document
    const updatedUser = await User.findByIdAndUpdate(userId, updateData, {
      new: true,
      runValidators: true,
      context: "query", // Required for proper validation
    })
      .select("-password -deviceTokens -jti -__v")
      .lean();

    if (!updatedUser) {
      // Rollback image upload if user update fails
      if (newImageData?.publicId) {
        await deleteAsset(newImageData.publicId);
      }
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    // 5. Delete old image AFTER successful update
    if (oldPublicId) {
      await deleteAsset(oldPublicId);
    }

    // 6. Return response
    let response = {
      ...updatedUser,
      profilePic: updatedUser.profilePic?.url || null,
      fullName: `${updatedUser.firstName} ${updatedUser.lastName}`,
      ...(req.file && { imageChanged: true }),
    };

    return res.status(200).json({
      success: true,
      message: "Profile updated successfully",
      user: response,
    });
  } catch (error) {
    next(error);
  }
};
