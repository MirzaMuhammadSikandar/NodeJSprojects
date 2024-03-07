import React, { useEffect } from "react";
import { useNavigate } from "react-router-dom";
const Dashboard = () => {
  const navigate = useNavigate();

  useEffect(() => {
    if (!localStorage.getItem("accessToken")) {
      navigate("/");
    }
  }, []);

  return (
    <div>
      <h1>Welcome to Home Page</h1>
      <button onClick={() => navigate("/updateData")}>UpdateData</button>
    </div>
  );
};

export default Dashboard;
