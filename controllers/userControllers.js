const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const Users = require("../model/userModel");
const { User } = require("../model/userModel");
const { sendEmail } = require("../middleware/sendMail");
const crypto = require("crypto");

const createUser = async (req, res) => {
  console.log(req.body);
  const { firstName, lastName, email, password } = req.body;
  if (!firstName || !lastName || !email || !password) {
    return res.json({
      success: false,
      message: "Please enter all the fields.",
    });
  }
  try {
    const existingUser = await User.findOne({ email: email });
    if (existingUser) {
      return res.json({
        success: false,
        message: "User already exists.",
      });
    }
    const randomSalt = await bcrypt.genSalt(10);
    const encryptedPassword = await bcrypt.hash(password, randomSalt);
    const newUser = new User({
      firstName: firstName,
      lastName: lastName,
      email: email,
      password: encryptedPassword,
    });
    await newUser.save();
    res.status(200).json({
      success: true,
      message: "User created successfully.",
    });
  } catch (error) {
    console.log(error);
    res.status(500).json("Server Error");
  }
};

const loginUser = async (req, res) => {
  console.log(req.body);
  const { email, password } = req.body;
  if (!email || !password) {
    return res.json({ success: false, message: "Please enter all fields" });
  }
  try {
    const user = await User.findOne({ email: email });
    if (!user) {
      return res.json({
        success: false,
        message: "User Not Found",
      });
    }
    const databasePassword = user.password;
    const isMatched = await bcrypt.compare(password, databasePassword);
    if (!isMatched) {
      return res.json({
        success: false,
        message: "Invalid Credentials",
      });
    }
    const token = await jwt.sign(
      { id: user._id, isAdmin: user.isAdmin },
      process.env.JWT_SECRET
    );
    res.status(200).json({
      success: true,
      message: "User Logged in successfully",
      token: token,
      userData: user,
      userId: user._id
    });
  } catch (error) {
    console.error(error);
    res.json({
      success: false,
      message: "Server error",
      error: error,
    });
  }
};

const getProfile = async (req, res) => {
  try {
    const user = await Users.findById(req.user.id).select("-password");
    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }
    res.json({ success: true, user });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

const editProfile = async (req, res) => {
  const { firstName, lastName, email } = req.body;
  let userFields = {};
  if (firstName) userFields.firstName = firstName;
  if (lastName) userFields.lastName = lastName;
  if (email) userFields.email = email;
  try {
    let user = await Users.findById(req.user.id);
    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }
    user = await Users.findByIdAndUpdate(
      req.user.id,
      { $set: userFields },
      { new: true }
    );
    res.json({ success: true, message: "Profile updated successfully", user });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

const getUsers = async (req, res) => {
  try {
    const allUsers = await User.find({});
    res.json({
      success: true,
      message: "All users fetched successfully!",
      products: allUsers,
    });
  } catch (error) {
    console.log(error);
    res.send("Internal server error");
  }
};

const getSingleUser = async (req, res) => {
  const userId = req.params.id;
  try {
    const singleUser = await User.findById(userId);
    res.json({
      success: true,
      message: "Single user fetched successfully!",
      product: singleUser,
    });
  } catch (error) {
    console.log(error);
    res.send("Internal server error");
  }
};

const getMyProfile = async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password");
    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }
    res.json({ success: true, user });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};

const updateMyProfile = async (req, res) => {
  const { firstName, lastName, email } = req.body;
  const userFields = { firstName, lastName, email };
  try {
    let user = await User.findById(req.user.id);
    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "User not found" });
    }
    user = await User.findByIdAndUpdate(
      req.user.id,
      { $set: userFields },
      { new: true }
    ).select("-password");
    res.json({ success: true, message: "Profile updated successfully", user });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Server error" });
  }
};



const forgotPassword = async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email });

    if (!user) {
      return res.json({
        success: false,
        message: "Email not found.",
      });
    }

    const resetPasswordToken = user.getResetPasswordToken();
    console.log(user.resetPasswordToken, user.resetPasswordExpire);

    await user.save();

    // Assuming you have a configuration variable for the frontend URL
    const frontendBaseUrl =
      process.env.FRONTEND_BASE_URL || "http://localhost:3000";
    const resetUrl = `${frontendBaseUrl}/password/reset/${resetPasswordToken}`;

    const message = `Reset Your Password by clicking on the link below: \n\n ${resetUrl}`;

    try {
      await sendEmail({
        email: user.email,
        subject: "Reset Password",
        message,
      });

      res.status(200).json({
        success: true,
        message: `Email sent to ${user.email}`,
      });
    } catch (error) {
      user.resetPasswordToken = undefined;
      user.resetPasswordExpire = undefined;
      await user.save();

      res.json({
        success: false,
        message: error.message,
      });
    }
  } catch (error) {
    console.log(error);
    res.json({
      success: false,
      message: error.message,
    });
  }
};

const resetPassword = async (req, res) => {
  console.log(req.params.token);
  try {
    const resetPasswordToken = crypto
      .createHash("sha256")
      .update(req.params.token)
      .digest("hex");

    console.log(resetPasswordToken);

    const user = await User.findOne({
      resetPasswordToken,
      resetPasswordExpire: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Token is invalid or has expired",
      });
    }

    
    const randomSalt = await bcrypt.genSalt(10);
    const encryptedPassword = await bcrypt.hash(req.body.password, randomSalt);
    user.password = encryptedPassword;

    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;
    await user.save();

    res.status(200).json({
      success: true,
      message: "Password Updated",
    });
  } catch (error) {
    console.log(error);
    res.status(500).json({
      success: false,
      message: error.message,
    });
  }
};


module.exports = {
  createUser,
  loginUser,
  getProfile,
  editProfile,
  getSingleUser,
  getUsers,
  getMyProfile,
  updateMyProfile,
forgotPassword,
resetPassword
};
