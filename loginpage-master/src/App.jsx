import React from "react";
import { Routes, Route } from "react-router-dom";
import { Toaster } from "react-hot-toast";
import Home from "./pages/Home";
import Dashboard from "./pages/Dashboard";
import UpdateData from "./pages/UpdateData";
import ForgotPassword from "./pages/ForgetPassword";
import ResetPassword from "./pages/ResetPassword";
import { Login } from "./pages/Login";
// import Navbar from "./navbar";

function App() {
  return (
    <div className="container">
      <Toaster />
      {/* <Navbar /> */}
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/login" element={<Login />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/updatedata" element={<UpdateData />} />
        <Route path="/forgotpassword" element={<ForgotPassword />} />
        <Route path="/resetpassword" element={<ResetPassword />} />
        <Route path="/success" element={<Login />} />
        <Route path="/error" element={<Error />} />
      </Routes>
    </div>
  );
}

export default App;