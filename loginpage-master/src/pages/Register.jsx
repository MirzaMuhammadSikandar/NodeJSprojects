import React, { useState } from "react";
import toast, { Toaster } from "react-hot-toast";

import axios from "axios";
import {
  FiUser,
  FiMail,
  FiLock,
  FiCalendar,
  FiMapPin,
  FiCamera,
  FiEye,
  FiEyeOff,
} from "react-icons/fi";
import { SiGoogle, SiGithub } from "react-icons/si"; // Importing Google and GitHub icons

export const Register = (props) => {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [pass, setPass] = useState("");
  const [dob, setDob] = useState("");
  const [address, setAddress] = useState("");
  const [profilePic, setProfilePic] = useState("null");
  const [passwordVisible, setPasswordVisible] = useState(false);
  const [error, setError] = useState("");

  const togglePasswordVisibility = () => {
    setPasswordVisible(!passwordVisible);
  };
  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!name || !email || !pass || !dob || !address) {
      setError("All fields are required.");
      return;
    }
    if (!/\S+@\S+\.\S+/.test(email)) {
      setError("Invalid email format.");
      return;
    }
    try {
      const formData = new FormData();
      formData.append("email", email);
      formData.append("name", name);
      formData.append("password", pass);
      formData.append("dateofbirth", dob);
      formData.append("address", address);
      formData.append("image", profilePic);

      const response = await axios.post(
        "http://192.168.100.171:3000/user/register",
        formData,
        {
          headers: {
            "Content-Type": "multipart/form-data",
          },
        }
      );
      props.onFormSwitch("login");
      toast.success("Registration successful!");
      console.log("Registration Successful", response.data);
      // window.alert("Registration Successful");
    } catch (error) {
      console.error("Registration Error", error);
      window.alert("Registration Error");
    }
  };

  const handleFileChange = (e) => {
    const file = e.target.files[0];
    setProfilePic(file);
  };

  const empty = () => {
    setName("");
    setEmail("");
    setPass("");
    setDob("");
    setAddress("");
    setProfilePic("");
  };

  return (
    <div className="min-h-screen flex justify-center items-center">
      <div className="bg-gray-200 shadow-md rounded-lg px-8 py-12 max-w-screen-xl w-full sm:w-[800px]">
        <h2 className="text-3xl mb-6 font-bold text-center text-gray-800">
          User Register
        </h2>
        <form className="register-form" onSubmit={handleSubmit}>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div className="mb-4">
              <label
                htmlFor="name"
                className=" text-gray-700 flex items-center"
              >
                <FiUser className="text-gray-500 mr-2" />
                Full Name <span className="text-red-500">*</span>
              </label>
              <input
                className="form-input mt-1 w-full bg-gray-100 hover:bg-blue-100 focus:bg-white px-4 py-2 rounded"
                value={name}
                onChange={(e) => setName(e.target.value)}
                id="name"
                placeholder="Full Name"
              />
            </div>
            <div className="mb-4">
              <label
                htmlFor="email"
                className=" text-gray-700 flex items-center"
              >
                <FiMail className="text-gray-500 mr-2" />
                Email <span className="text-red-500">*</span>
              </label>
              <input
                className="form-input mt-1 w-full bg-gray-100 hover:bg-blue-100 focus:bg-white px-4 py-2 rounded"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                type="email"
                placeholder="youremail@gmail.com"
                id="email"
                name="email"
              />
            </div>
            <div className="mb-4">
              <label
                htmlFor="password"
                className=" text-gray-700 flex items-center"
              >
                <FiLock className="text-gray-500 mr-2" />
                Password <span className="text-red-500">*</span>
              </label>
              <div className="relative">
                <input
                  value={pass}
                  onChange={(e) => setPass(e.target.value)}
                  type={passwordVisible ? "text" : "password"}
                  placeholder="********"
                  id="password"
                  name="password"
                  className="form-input mt-1 w-full bg-gray-100 hover:bg-blue-100 focus:bg-white px-4 py-2 rounded"
                />
                <button
                  type="button"
                  onClick={togglePasswordVisibility}
                  className="absolute inset-y-0 right-0 flex items-center px-3 text-gray-600"
                >
                  {passwordVisible ? <FiEyeOff /> : <FiEye />}
                </button>
              </div>
            </div>
            <div className="mb-4">
              <label htmlFor="dob" className=" text-gray-700 flex items-center">
                <FiCalendar className="text-gray-500 mr-2" />
                Date of Birth <span className="text-red-500">*</span>
              </label>
              <input
                className="form-input mt-1 w-full bg-gray-100 hover:bg-blue-100 focus:bg-white px-4 py-2 rounded"
                value={dob}
                onChange={(e) => setDob(e.target.value)}
                type="date"
                id="dob"
                name="dob"
              />
            </div>
            <div className="mb-4">
              <label
                htmlFor="address"
                className=" text-gray-700 flex items-center"
              >
                <FiMapPin className="text-gray-500 mr-2" />
                Address <span className="text-red-500">*</span>
              </label>
              <textarea
                className="form-textarea mt-1 w-full bg-gray-100 hover:bg-blue-100 focus:bg-white px-4 py-2 rounded"
                value={address}
                onChange={(e) => setAddress(e.target.value)}
                id="address"
                name="address"
                rows="3"
                placeholder="Your address..."
              ></textarea>
            </div>
            <div className="mb-4">
              <label
                htmlFor="profilePic"
                className=" text-gray-700 flex items-center"
              >
                <FiCamera className="text-gray-500 mr-2" />
                Profile Picture
              </label>
              <input
                type="file"
                id="profilePic"
                name="profilePic"
                onChange={handleFileChange}
              />
              {profilePic && (
                <img
                  src={
                    profilePic !== "null"
                      ? URL.createObjectURL(profilePic)
                      : "Add Image"
                  }
                  alt="Add"
                  className="mt-2 rounded-full w-14 h-14 object-cover"
                />
              )}
            </div>
          </div>
          <div className="flex flex-col sm:flex-row justify-between">
            <button
              onClick={empty}
              type="submit"
              className="bg-blue-500 hover:bg-blue-600 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline w-full sm:w-auto mb-2 sm:mb-0"
            >
              Reset
            </button>
            <button
              type="submit"
              className="bg-blue-500 hover:bg-blue-600 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline w-full sm:w-auto mb-2 sm:mb-0"
            >
              Register
            </button>
            <button
              onClick={() => props.onFormSwitch("login")}
              type="submit"
              className="bg-blue-500 hover:bg-blue-600 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline w-full sm:w-auto mb-2 sm:mb-0"
            >
              Back To Login
            </button>
          </div>
          {error && <p className="text-red-500 text-sm mb-4">{error}</p>}
        </form>
        <div className="mt-4 text-center">
          <button
            className="flex items-center justify-center bg-red-600 hover:bg-red-700 text-white font-bold py-2 px-4 rounded-full focus:outline-none focus:shadow-outline w-full sm:w-auto"
            onClick={() => props.onFormSwitch("login")}
          >
            <SiGoogle className="text-white mr-2" />
            Continue with Google
          </button>
        </div>
      </div>
    </div>
  );
};

export default Register;
