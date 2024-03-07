import React, { useState, useEffect } from "react";
import axios from "axios";
import {
  FiUser,
  FiMail,
  FiLock,
  FiCalendar,
  FiMapPin,
  FiCamera,
  FiEye,
  FiEyeOff,
} from "react-icons/fi";
const UpdateData = () => {
  // const [oldDetails, setOldDetails] = useState({});
  const [newName, setName] = useState("");
  const [newEmail, setEmail] = useState("");
  const [newPassword, setPass] = useState("");
  const [newDateofbirth, setDob] = useState("");
  const [newAddress, setAddress] = useState("");
  const [image, setProfilePic] = useState();
  const [newImage, setNewimage] = useState(null);
  const [passwordVisible, setPasswordVisible] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    const fetchUserDetails = async () => {
      try {
        const { data } = await axios.get(
          "http://192.168.100.171:3000/user/record/",
          {
            headers: {
              Authorization: `Bearer ${localStorage.getItem("accessToken")}`,
            },
          }
        );
        const userDetails = data[0].user; // Assuming the response contains the user details in the "user" object
        setName(userDetails.name);
        setEmail(userDetails.email);
        // setPass(userDetails.password);
        setDob(userDetails.dateofbirth);
        setAddress(userDetails.address);
        setProfilePic(userDetails.image);
      } catch (error) {
        console.error("Error fetching user details:", error);
      }
    };

    fetchUserDetails();
  }, []);
  const togglePasswordVisibility = () => {
    setPasswordVisible(!passwordVisible);
  };
  const handleSubmit = async (e) => {
    e.preventDefault();
    if (
      !newName ||
      !newEmail ||
      !newPassword ||
      !newDateofbirth ||
      !newAddress
    ) {
      setError("All fields are required.");
      return;
    }
    // if (!/\S+@\S+\.\S+/.test(email)) {
    //   setError("Invalid email format.");
    //   return;
    // }
    try {
      const formData = new FormData();
      formData.append("newEmail", newEmail);
      formData.append("newName", newName);
      formData.append("newPassword", newPassword);
      formData.append("newDateofbirth", newDateofbirth);
      formData.append("newAddress", newAddress);
      formData.append("image", image);

      const response = await axios.put(
        "http://192.168.100.171:3000/user/update-user",
        formData,
        {
          headers: {
            "Content-Type": "multipart/form-data",
            Authorization: `Bearer ${localStorage.getItem("accessToken")}`,
          },
        }
      );

      console.log("Update Successful", response.data);
      window.alert("Update Successful");
    } catch (error) {
      console.error("Update Error", error);
      window.alert("Update Error");
    }
  };

  const handleFileChange = (e) => {
    const file = e.target.files[0];
    setNewimage(file);
  };

  return (
    <div className="min-h-screen flex justify-center items-center">
      <div className="bg-gray-200 shadow-md rounded-lg px-8 py-12 max-w-screen-xl w-full sm:w-[800px]">
        <h2 className="text-3xl mb-6 font-bold text-center text-gray-800">
          Update
        </h2>
        <form className="register-form" onSubmit={handleSubmit}>
          <div className="flex flex-wrap -mx-3 mb-4">
            <div className="w-full md:w-1/2 px-3 mb-4 md:mb-0">
              <label
                htmlFor="name"
                className=" text-gray-700 flex items-center"
              >
                <FiUser className="text-gray-500 mr-2" />
                Full Name <span className="text-red-500">*</span>
              </label>
              <input
                className="form-input mt-1 w-full bg-gray-100 hover:bg-blue-100 focus:bg-white px-4 py-2 rounded"
                value={newName}
                onChange={(e) => setName(e.target.value)}
                id="name"
                placeholder="Update Full Name"
              />
            </div>
            <div className="w-full md:w-1/2 px-3">
              <label
                htmlFor="email"
                className=" text-gray-700 flex items-center"
              >
                <FiMail className="text-gray-500 mr-2" />
                Email <span className="text-red-500">*</span>
              </label>
              <input
                className="form-input mt-1 w-full bg-gray-100 hover:bg-blue-100 focus:bg-white px-4 py-2 rounded"
                value={newEmail}
                onChange={(e) => setEmail(e.target.value)}
                type="email"
                placeholder="Update youremail@gmail.com"
                id="email"
                name="email"
              />
            </div>
          </div>
          <div className="flex flex-wrap -mx-3 mb-4">
            <div className="w-full md:w-1/2 px-3 mb-4 md:mb-0">
              <label
                htmlFor="password"
                className=" text-gray-700 flex items-center"
              >
                <FiLock className="text-gray-500 mr-2" />
                Password <span className="text-red-500">*</span>
              </label>
              <div className="relative">
                <input
                  value={newPassword}
                  onChange={(e) => setPass(e.target.value)}
                  type={passwordVisible ? "text" : "password"}
                  placeholder="Update Password"
                  id="password"
                  name="password"
                  className="form-input mt-1 w-full bg-gray-100 hover:bg-blue-100 focus:bg-white px-4 py-2 rounded"
                />
                <button
                  type="button"
                  onClick={togglePasswordVisibility}
                  className="absolute inset-y-0 right-0 flex items-center px-3 text-gray-600"
                >
                  {passwordVisible ? <FiEyeOff /> : <FiEye />}
                </button>
              </div>
            </div>
            <div className="w-full md:w-1/2 px-3">
              <label htmlFor="dob" className=" text-gray-700 flex items-center">
                <FiCalendar className="text-gray-500 mr-2" />
                Date of Birth <span className="text-red-500">*</span>
              </label>
              <input
                className="form-input mt-1 w-full bg-gray-100 hover:bg-blue-100 focus:bg-white px-4 py-2 rounded"
                value={newDateofbirth}
                onChange={(e) => setDob(e.target.value)}
                type="date"
                id="dob"
                name="dob"
              />
            </div>
          </div>
          <div className="mb-4">
            <label
              htmlFor="address"
              className=" text-gray-700 flex items-center"
            >
              <FiMapPin className="text-gray-500 mr-2" />
              Address <span className="text-red-500">*</span>
            </label>
            <textarea
              className="form-textarea mt-1 w-full bg-gray-100 hover:bg-blue-100 focus:bg-white px-4 py-2 rounded"
              value={newAddress}
              onChange={(e) => setAddress(e.target.value)}
              id="address"
              name="address"
              rows="3"
              placeholder="Update Your address..."
            ></textarea>
          </div>
          <div className="mb-4">
            <label
              htmlFor="profilePic"
              className=" text-gray-700 flex items-center"
            >
              <FiCamera className="text-gray-500 mr-2" />
              Profile Picture
            </label>
            <input
              type="file"
              id="profilePic"
              name="profilePic"
              onChange={handleFileChange}
            />
            {newImage ? (
              <img
                src={URL.createObjectURL(newImage)}
                alt="image"
                className="mt-2 rounded-full w-14 h-14 object-cover"
              />
            ) : (
              <img
                key={image}
                src={`http://192.168.100.171:3000/images/${image}`}
                alt="image"
                className="mt-2 rounded-full w-14 h-14 object-cover"
              />
            )}
          </div>
          {error && <p className="text-red-500 text-sm mb-4">{error}</p>}
          <button
            type="submit"
            className="bg-blue-500 hover:bg-blue-600 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline w-full sm:w-auto sm:ml-[19rem]"
          >
            Update
          </button>
        </form>
      </div>
    </div>
  );
};

export default UpdateData;
