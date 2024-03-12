import React from "react";
import { Link } from "react-router-dom";

const Page404 = () => {
  return (
    <div>
      <h1 className=" text-2xl">Page 404 </h1>
      <p>This URL is not Present</p>
      <Link to="/"> go to home page</Link>
    </div>
  );
};

export default Page404;
