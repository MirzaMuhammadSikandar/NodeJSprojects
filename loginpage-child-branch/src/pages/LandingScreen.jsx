import React from "react";
import { TypeAnimation } from "react-type-animation";
import { Button } from "../components/buttons/Button";
import { useNavigate } from "react-router-dom";
// import "..styles/LandingScreen.css"; // Import CSS file for styling
import "../styles/LandingScreen.css";
const LandingScreen = () => {
  const navigate = useNavigate();

  return (
    <div className="landing-screen-container">
      <div className="landing-screen-content">
        <TypeAnimation
          sequence={[
            "Welcome",
            1000,
            "To",
            1000,
            "Cherry Byte Technology",
            1000,
          ]}
          wrapper="span"
          speed={50}
          style={{
            fontSize: "2em",
            display: "inline-block",
            fontWeight: "bold",
          }}
          repeat={Infinity}
        />

        <div>
          <Button onClick={() => navigate("/login")}>Login</Button>
        </div>
      </div>
    </div>
  );
};

export default LandingScreen;
