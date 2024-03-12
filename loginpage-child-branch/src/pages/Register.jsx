import React, { useState, useEffect } from "react";
import toast, { Toaster } from "react-hot-toast";
import axios from "axios";
import { useFormik } from "formik";
import { SiGoogle } from "react-icons/si";
import { RegisterSchema } from "../schemas";
import { Button } from "../components/buttons/Button";
import { useSearchParams, useNavigate } from "react-router-dom";
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

import {
  spanStyles,
  iconStyles,
  labelStyles,
  inputField,
  addressField,
  imageStyle,
} from "../utils/commonStyles";

export const Register = () => {
  const [profilePic, setProfilePic] = useState(null);
  const [passwordVisible, setPasswordVisible] = useState(false);
  const [searchParams] = useSearchParams();
  const token = searchParams.get("token");
  const error = searchParams.get("error");
  const navigate = useNavigate();
  const initialValues = {
    name: "",
    email: "",
    password: "",
    dob: "",
    address: "",
    profilePic: null,
  };
  const handleSubmit = async (values) => {
    try {
      const formData = new FormData();
      formData.append("email", values.email);
      formData.append("name", values.name);
      formData.append("password", values.password);
      formData.append("dateofbirth", values.dob);
      formData.append("address", values.address);
      formData.append("image", values.profilePic);

      const response = await axios.post(
        "http://localhost:3000/user/register",
        formData,
        {
          headers: {
            "Content-Type": "multipart/form-data",
          },
        }
      );
      console.log(response.data);
      if (response.data && response.data.status === "error") {
        if (response.data.error === "email already in use") {
          window.alert("Email already exists in the database.");
        } else {
          throw new Error(response.data.error); // Throw Error for Unexpected errors
        }
      } else {
        navigate("/login");
        toast.success("Registration successful!");
      }
    } catch (error) {
      console.error("Registration Error:", error);
      window.alert("Registration Error: " + error.message);
    }
  };
  const formik = useFormik({
    initialValues: initialValues,
    validationSchema: RegisterSchema,
    onSubmit: handleSubmit,
  });
  console.log(formik);
  const handleFileChange = (e) => {
    formik.setFieldValue("profilePic", e.target.files[0]);
    setProfilePic(e);
  };

  const togglePasswordVisibility = () => {
    formik.setFieldValue("passwordVisible", !formik.values.passwordVisible);
    setPasswordVisible(!passwordVisible);
  };
  const handleGoogleLogin = async (e) => {
    e.preventDefault();
    try {
      window.open("http://localhost:3000/auth/google", "_self");
      navigate("/dashboard");
    } catch (error) {
      console.error(error);
    }
  };

  useEffect(() => {
    if (token) {
      localStorage.setItem("accessToken", token);
      navigate("/dashboard");
    }
  }, [token]);

  let message = null;
  if (token !== null) {
    message = <h2>Token = {token}</h2>;
  } else if (error !== null) {
    message = <h2>Error = {error}</h2>;
  }
  const handleReset = () => {
    formik.resetForm();
  };
  return (
    <div className="min-h-screen flex justify-center items-center">
      <div className="bg-gray-200 opacity-100 shadow-md rounded-lg px-8 py-12 max-w-screen-xl w-full sm:w-[800px]">
        <h2 className="text-3xl mb-6 font-bold text-center text-gray-800">
          User Register
          {message}
        </h2>
        <form className="register-form" onSubmit={formik.handleSubmit}>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div className="mb-4">
              <label htmlFor="name" className={labelStyles.label}>
                <FiUser className={iconStyles.icon} />
                Full Name<span className={spanStyles.required}>*</span>
              </label>
              <input
                className={inputField.field}
                value={formik.values.name}
                onChange={formik.handleChange}
                id="name"
                placeholder="Full Name"
              />
              {formik.touched.name && formik.errors.name ? (
                <div className="text-red-500">{formik.errors.name}</div>
              ) : null}
            </div>
            <div className="mb-4">
              <label htmlFor="email" className={labelStyles.label}>
                <FiMail className={iconStyles.icon} />
                Email <span className={spanStyles.required}>*</span>
              </label>
              <input
                className={inputField.field}
                value={formik.values.email}
                onChange={formik.handleChange}
                type="email"
                placeholder="youremail@gmail.com"
                id="email"
                name="email"
              />
              {formik.touched.email && formik.errors.email ? (
                <div className="text-red-500">{formik.errors.email}</div>
              ) : null}
            </div>
            <div className="mb-4">
              <label htmlFor="password" className={labelStyles.label}>
                <FiLock className={iconStyles.icon} />
                Password <span className={spanStyles.required}>*</span>
              </label>
              <div className="relative">
                <input
                  value={formik.values.password}
                  onChange={formik.handleChange}
                  type={passwordVisible ? "text" : "password"}
                  placeholder="********"
                  id="password"
                  name="password"
                  className={inputField.field}
                />
                {formik.touched.password && formik.errors.password ? (
                  <div className="text-red-500">{formik.errors.password}</div>
                ) : null}
                <button
                  type="button"
                  onClick={togglePasswordVisibility}
                  className="absolute top-[1rem] right-1 flex items-center px-3 text-gray-600"
                >
                  {passwordVisible ? <FiEyeOff /> : <FiEye />}
                </button>
              </div>
            </div>
            <div className="mb-4">
              <label htmlFor="dob" className={labelStyles.label}>
                <FiCalendar className={iconStyles.icon} />
                Date of Birth <span className={spanStyles.required}>*</span>
              </label>
              <input
                className={inputField.field}
                value={formik.values.dob}
                onChange={formik.handleChange}
                type="date"
                id="dob"
                name="dob"
              />
              {formik.touched.dob && formik.errors.dob ? (
                <div className="text-red-500">{formik.errors.dob}</div>
              ) : null}
            </div>
            <div className="mb-4">
              <label htmlFor="address" className={labelStyles.label}>
                <FiMapPin className={iconStyles.icon} />
                Address <span className={spanStyles.required}>*</span>
              </label>
              <textarea
                className={addressField.addressStyle}
                value={formik.values.address}
                onChange={formik.handleChange}
                id="address"
                name="address"
                rows="3"
                placeholder="Your address..."
              ></textarea>
              {formik.touched.address && formik.errors.address ? (
                <div className="text-red-500">{formik.errors.address}</div>
              ) : null}
            </div>
            <div className="mb-4">
              <label htmlFor="profilePic" className={labelStyles.label}>
                <FiCamera className={iconStyles.icon} />
                Profile Picture <span className={spanStyles.required}>*</span>
              </label>
              <input
                type="file"
                id="profilePic"
                name="profilePic"
                onChange={handleFileChange}
              />
              {formik.touched.profilePic && formik.errors.profilePic ? (
                <div className="text-red-500">{formik.errors.profilePic}</div>
              ) : null}
              {formik.values.profilePic && (
                <img
                  src={
                    profilePic !== "null"
                      ? URL.createObjectURL(formik.values.profilePic)
                      : "Add Image"
                  }
                  alt="Add"
                  className={imageStyle.image}
                />
              )}
            </div>
          </div>
          <div className="flex flex-col sm:flex-row justify-between">
            <Button type="button" onClick={handleReset}>
              Reset
            </Button>
            <Button type="submit">Register</Button>
            <Button onClick={() => navigate("/login")}>Back To Login</Button>
          </div>
        </form>
        <div className="mt-4 flex justify-center">
          <Button
            className="flex items-center bg-red-600 hover:bg-red-700 text-white font-bold py-2 px-4 rounded-full focus:outline-none focus:shadow-outline sm:w-auto"
            onClick={handleGoogleLogin}
          >
            <SiGoogle className="text-white mr-2" />
            Continue with Google
          </Button>
        </div>
      </div>
    </div>
  );
};
export default Register;
