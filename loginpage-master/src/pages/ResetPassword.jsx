import React, { useState, useEffect } from "react";
import axios from "axios";

const ResetPassword = () => {
  const [resetPassword, setResetPassword] = useState("");
  const [resetToken, setResetToken] = useState("");

  useEffect(() => {
    const handleResetPasswordToken = () => {
      const urlParams = new URLSearchParams(window.location.search);
      const token = urlParams.get("token");

      if (token) {
        localStorage.setItem("resetToken", token);
        setResetToken(token);
      }
    };

    handleResetPasswordToken();
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      console.log(resetPassword);
      console.log(localStorage.getItem("resetToken"));
      const token = localStorage.getItem("resetToken");
      const response = await axios.post(
        "http://192.168.100.171:3000/user/resetpassword",
        { token, newpassword: resetPassword },
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );

      console.log(response.data);
      alert("Reset password successful");
      window.location.href = "/";
    } catch (error) {
      alert("Service Error");
      console.error(error);
    }
  };

  return (
    <div className="container">
      <form onSubmit={handleSubmit}>
        <input
          type="password"
          placeholder="Password"
          value={resetPassword}
          onChange={(e) => setResetPassword(e.target.value)}
        />
        <button type="submit">Reset Password</button>
      </form>
    </div>
  );
};

export default ResetPassword;
