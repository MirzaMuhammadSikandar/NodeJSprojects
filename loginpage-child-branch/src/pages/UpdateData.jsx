import React, { useState, useEffect } from "react";
import axios from "axios";
import { useFormik } from "formik";
import { updateSchema } from "../schemas";
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
import toast from "react-hot-toast";
import { Navigate } from "react-router";
const UpdateData = () => {
  const [image, setProfilePic] = useState();
  const [newImage, setNewimage] = useState(null);
  const [passwordVisible, setPasswordVisible] = useState(false);

  useEffect(() => {
    const fetchUserDetails = async () => {
      try {
        const { data } = await axios.get("http://localhost:3000/user/record/", {
          headers: {
            Authorization: `Bearer ${localStorage.getItem("accessToken")}`,
          },
        });
        const userDetails = data[0].user;
        formik.setValues({
          newName: userDetails.name,
          newEmail: userDetails.email,
          newPassword: "", // Password Hide for security
          newDateofbirth: userDetails.dateofbirth,
          newAddress: userDetails.address,
          image: userDetails.image,
        });
        setProfilePic(userDetails.image);
      } catch (error) {
        console.error("Error fetching user details:", error);
      }
    };

    fetchUserDetails();
  }, []);

  const togglePasswordVisibility = () => {
    setPasswordVisible(!passwordVisible);
  };

  const handleSubmit = async (values) => {
    try {
      const formData = new FormData();
      formData.append("newEmail", values.newEmail);
      formData.append("newName", values.newName);
      formData.append("newPassword", values.newPassword);
      formData.append("newDateofbirth", values.newDateofbirth);
      formData.append("newAddress", values.newAddress);
      formData.append("image", values.image);

      const response = await axios.put(
        "http://localhost:3000/user/update-user",
        formData,
        {
          headers: {
            "Content-Type": "multipart/form-data",
            Authorization: `Bearer ${localStorage.getItem("accessToken")}`,
          },
        }
      );

      console.log("Update Successful", response.data);
      // window.alert("Update Successful");
      toast.success("Update successful");
      Navigate("/");
    } catch (error) {
      console.error("Update Error", error);
      // window.alert("Update Error");
      toast.error("Update Error");
    }
  };

  const handleFileChange = (e) => {
    const file = e.target.files[0];
    formik.setFieldValue("image", file);
    setNewimage(file);
  };

  const formik = useFormik({
    initialValues: {
      newName: "",
      newEmail: "",
      newPassword: "",
      newDateofbirth: "",
      newAddress: "",
      image: null,
    },
    validationSchema: updateSchema,
    onSubmit: handleSubmit,
  });

  return (
    <div className="flex justify-center items-center min-h-screen sm:ml-20">
      <div className="bg-white shadow-md rounded-lg px-5 py-8 max-w-screen-md w-full">
        <h2 className="text-3xl mb-6 font-bold text-center text-gray-800">
          Update Details
        </h2>
        <form className="register-form" onSubmit={formik.handleSubmit}>
          <div className="flex flex-wrap -mx-3 mb-4">
            <div className="w-full md:w-1/2 px-3 mb-4 md:mb-0">
              <label htmlFor="newName" className={labelStyles.label}>
                <FiUser className={iconStyles.icon} />
                Full Name <span className={spanStyles.required}>*</span>
              </label>
              <input
                className={inputField.field}
                value={formik.values.newName}
                onChange={formik.handleChange}
                id="newName"
                name="newName"
                placeholder="Update Full Name"
              />
              {formik.touched.newName && formik.errors.newName ? (
                <div className="text-red-500">{formik.errors.newName}</div>
              ) : null}
            </div>
            <div className="w-full md:w-1/2 px-3">
              <label htmlFor="newEmail" className={labelStyles.label}>
                <FiMail className={iconStyles.icon} />
                Email <span className={spanStyles.required}>*</span>
              </label>
              <input
                className={inputField.field}
                value={formik.values.newEmail}
                onChange={formik.handleChange}
                type="email"
                id="newEmail"
                name="newEmail"
                placeholder="Update youremail@gmail.com"
              />
              {formik.touched.newEmail && formik.errors.newEmail ? (
                <div className="text-red-500">{formik.errors.newEmail}</div>
              ) : null}
            </div>
          </div>
          <div className="flex flex-wrap -mx-3 mb-4">
            <div className="w-full md:w-1/2 px-3 mb-4 md:mb-0">
              <label htmlFor="password" className={labelStyles.label}>
                <FiLock className={iconStyles.icon} />
                Password <span className={spanStyles.required}>*</span>
              </label>
              <div className="relative">
                <input
                  value={formik.values.newPassword}
                  onChange={formik.handleChange}
                  type={passwordVisible ? "text" : "password"}
                  placeholder="Update Password"
                  id="newPassword"
                  name="newPassword"
                  className={inputField.field}
                />
                {formik.touched.newPassword && formik.errors.newPassword ? (
                  <div className="text-red-500">
                    {formik.errors.newPassword}
                  </div>
                ) : null}

                <button
                  type="button"
                  onClick={togglePasswordVisibility}
                  className="absolute inset-y-0 right-0 flex items-center px-3 text-gray-600"
                >
                  {passwordVisible ? <FiEyeOff /> : <FiEye />}
                </button>
              </div>
            </div>
            <div className="w-full md:w-1/2 px-3">
              <label htmlFor="newDateofbirth" className={labelStyles.label}>
                <FiCalendar className={iconStyles.icon} />
                Date of Birth <span className={spanStyles.required}>*</span>
              </label>
              <input
                className="form-input mt-1 w-full bg-gray-100 hover:bg-blue-100 focus:bg-white px-4 py-2 rounded"
                value={formik.values.newDateofbirth}
                onChange={formik.handleChange}
                type="date"
                id="newDateofbirth"
                name="newDateofbirth"
              />
              {formik.touched.newDateofbirth && formik.errors.newDateofbirth ? (
                <div className="text-red-500">
                  {formik.errors.newDateofbirth}
                </div>
              ) : null}
            </div>
          </div>
          <div className="mb-4">
            <label htmlFor="newAddress" className={labelStyles.label}>
              <FiMapPin className={iconStyles.icon} />
              Address <span className={spanStyles.required}>*</span>
            </label>
            <textarea
              className={addressField.addressStyle}
              value={formik.values.newAddress}
              onChange={formik.handleChange}
              id="newAddress"
              name="newAddress"
              rows="3"
              placeholder="Update Your address..."
            ></textarea>
            {formik.touched.newAddress && formik.errors.newAddress ? (
              <div className="text-red-500">{formik.errors.newAddress}</div>
            ) : null}
          </div>
          <div className="mb-4">
            <label htmlFor="profilePic" className={labelStyles.label}>
              <FiCamera className={iconStyles.icon} />
              Profile Picture
            </label>
            <input
              type="file"
              id="profilePic"
              name="profilePic"
              onChange={handleFileChange}
            />
            {formik.touched.image && formik.errors.image ? (
              <div className="text-red-500">{formik.errors.image}</div>
            ) : null}
            {newImage ? (
              <img
                src={URL.createObjectURL(newImage)}
                alt="image"
                className={imageStyle.image}
              />
            ) : (
              <img
                key={image}
                src={`http://localhost:3001/images/${image}`}
                alt="image"
                className={imageStyle.image}
              />
            )}
          </div>

          <button
            type="submit"
            className="bg-blue-500 hover:bg-blue-600 text-white py-2 px-4 font-bold rounded focus:outline-none focus:shadow-outline w-full sm:w-auto sm:ml-[19rem]"
          >
            Update
          </button>
        </form>
      </div>
    </div>
  );
};

export default UpdateData;
