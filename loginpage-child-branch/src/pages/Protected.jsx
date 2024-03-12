import React, { useEffect } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import toast from "react-hot-toast";

const Protected = (props) => {
  const { Component } = props;
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    let login = localStorage.getItem("login");
    let resetpassword = localStorage.getItem("resetpassword");
    let updateData = localStorage.getItem("updatedata");
    const path = location.pathname;

    if (path === "/dashboard" && !login) {
      toast.error("Please Login First to Access this Page");
      navigate("/login");
    }
    if (path === "/updateData" && !updateData) {
      toast.error("Please Login First to Access this Page");
      navigate("/login");
    }
    if (path === "/resetpassword" && !resetpassword) {
      toast.error("Please Forget Password to access this page");
      navigate("/forgotpassword");
    }
  }, [navigate, location.pathname]);

  return (
    <div>
      <Component />
    </div>
  );
};

export default Protected;
