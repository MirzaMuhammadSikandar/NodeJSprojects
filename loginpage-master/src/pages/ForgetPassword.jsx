import React, { useState } from "react";
import { FiMail } from "react-icons/fi";
import axios from "axios";
import { useNavigate } from "react-router-dom";
// import ResetPassword from "./ResetPassword";
const ForgotPassword = () => {
  const [resetEmail, setResetEmail] = useState("");
  const [resetToken, setResetToken] = useState("");
  const navigate = useNavigate(); // Use the useNavigate hook to get navigation functions

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      console.log(resetEmail);
      const response = await axios.post(
        "http://192.168.100.171:3000/user/forgetpassword",
        { email: resetEmail }
      );

      console.log(response.data);
      setResetToken(response.data.token); // Set the reset token received from the server
      alert("Reset password email sent successfully");
    } catch (error) {
      alert("Service Error");
      console.error(error);
    }
  };

  // Redirect to reset password page if token exists
  if (resetToken) {
    navigate(`/reset-password?token=${resetToken}`); // Use navigate function to redirect
  }

  return (
    <div className="mb-6">
      <form onSubmit={handleSubmit}>
        <div className="relative">
          <span className="text-gray-400">
            <FiMail />
          </span>
          <input
            type="email"
            placeholder="Email"
            value={resetEmail}
            onChange={(e) => setResetEmail(e.target.value)}
            className="pl-5 pr-3 py-2 w-80 border-2 rounded-md focus:outline-none focus:border-blue-500"
          />
        </div>
        <button
          type="submit"
          className="bg-blue-500 hover:bg-blue-600 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline w-full"
        >
          Send Email
        </button>
      </form>
    </div>
  );
};

export default ForgotPassword;
