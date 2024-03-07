// GoogleSignInButton.js
import React from "react";
import GoogleLogin from "react-google-login";
import axios from "axios";
const GoogleSignInButton = () => {
  const responseGoogle = async (response) => {
    try {
      const { code } = response;
      const serverResponse = await axios.post(
        "http://192.168.100.171:3000/google/callback",
        { code }
      );
      console.log(serverResponse.data);
      // Redirect to success page or handle the response accordingly
    } catch (error) {
      console.error("Google sign-in error:", error);
    }
  };
  return (
    <GoogleLogin
      clientId="YOUR_CLIENT_ID"
      buttonText="Continue with Google"
      onSuccess={responseGoogle}
      onFailure={responseGoogle}
      cookiePolicy={"single_host_origin"}
    />
  );
};
export default GoogleSignInButton;