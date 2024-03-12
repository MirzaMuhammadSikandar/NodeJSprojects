import React from "react";

const Navbar = () => {
  return (
    <div className="fixed top-0 bg-gray-500 pb-5 z-30 w-full flex justify-between px-6 lg:px-24 py-4 text-center">
      <ul className="text-white flex">
        <li className="px-3">Home</li>
        <li className="px-3">Sigin</li>
        <li className="px-3">Signout</li>
      </ul>
    </div>
  );
};

export default Navbar;
