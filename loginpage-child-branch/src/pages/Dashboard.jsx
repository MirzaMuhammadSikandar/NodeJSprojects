import React, { useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { Button } from "../components/buttons/Button";
const Dashboard = () => {
  const navigate = useNavigate();

  useEffect(() => {
    if (!localStorage.getItem("accessToken")) {
      navigate("/");
    }
  }, []);

  return (
    <div>
      <h1 className=" font-bold text-4xl text-center max-sm:mt-40 md:mt-44">
        Welcome to Dashboard
      </h1>
      <div className="justify-center text-center mt-6">
        <Button onClick={() => navigate("/updateData")}>Update Details</Button>
      </div>
    </div>
  );
};

export default Dashboard;
