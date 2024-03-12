import React from "react";
import { Routes, Route } from "react-router-dom";
import { Toaster } from "react-hot-toast";
import Dashboard from "./pages/Dashboard";
import UpdateData from "./pages/UpdateData";
import ForgotPassword from "./pages/ForgetPassword";
import ResetPassword from "./pages/ResetPassword";
import { Login } from "./pages/Login";
import Register from "./pages/Register";
import ParticleBackground from "./components/ParticleBackground/ParticleBackground";
import LandingScreen from "./pages/LandingScreen";
import Protected from "./pages/Protected";
import Page404 from "./pages/PageError";
function App() {
  return (
    <div className="container">
      <ParticleBackground />
      <Toaster />
      <Routes>
        <Route path="/" element={<LandingScreen />} />
        <Route path="/login" element={<Login />} />
        <Route
          path="/dashboard"
          element={<Protected Component={Dashboard} />}
        />
        <Route
          path="/updatedata"
          element={<Protected Component={UpdateData} />}
        />
        <Route path="/forgotpassword" element={<ForgotPassword />} />
        <Route
          path="/resetpassword"
          element={<Protected Component={ResetPassword} />}
        />
        <Route path="/register" element={<Register />} />
        <Route path="/*" element={<Page404 />} />
      </Routes>
    </div>
  );
}

export default App;
