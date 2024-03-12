import React, { useState } from "react";
import { useFormik } from "formik";
import * as Yup from "yup";
import { FiEye, FiEyeOff } from "react-icons/fi";
import { Button } from "../components/buttons/Button";

const ResetPassword = () => {
  const [passwordVisible, setPasswordVisible] = useState(false);

  const formik = useFormik({
    initialValues: {
      resetPassword: "",
    },
    validationSchema: Yup.object({
      resetPassword: Yup.string()
        .required("Password is required")
        .matches(
          /^(?=.*[a-z])(?=.*[A-Z])/,
          "Password must contain at least one uppercase letter and one lowercase letter"
        )
        .min(6, "Password must be at least 6 characters long"),
    }),
    onSubmit: (values) => {
      console.log(values);
    },
  });

  const togglePasswordVisibility = () => {
    setPasswordVisible((prev) => !prev);
  };

  return (
    <div className="container mx-auto">
      <form onSubmit={formik.handleSubmit} className="w-64 mx-auto">
        <div className="relative">
          <h1 className="text-center font-bold max-sm:mt-48 sm:mt-48">
            Reset Your Password
          </h1>
          <input
            value={formik.values.resetPassword}
            onChange={formik.handleChange}
            onBlur={formik.handleBlur}
            type={passwordVisible ? "text" : "password"}
            placeholder="Please Reset Password"
            id="resetPassword"
            name="resetPassword"
            className={`border border-gray-400 rounded px-3 py-2 mt-6 w-full ${
              formik.touched.resetPassword && formik.errors.resetPassword
                ? "border-red-500"
                : ""
            }`}
          />
          <button
            type="button"
            onClick={togglePasswordVisibility}
            className="absolute top-[4rem] right-1 flex items-center px-3 text-gray-600"
          >
            {passwordVisible ? <FiEyeOff /> : <FiEye />}
          </button>
          {formik.touched.resetPassword && formik.errors.resetPassword && (
            <div className="text-red-500 text-xs mt-1">
              {formik.errors.resetPassword}
            </div>
          )}
        </div>

        <div className="text-center mt-6">
          <Button type="submit">Reset Password</Button>
        </div>
      </form>
    </div>
  );
};

export default ResetPassword;
