import * as yup from "yup";

export const RegisterSchema = yup.object({
  name: yup.string().min(2).max(30).required("Please enter your Name"),
  email: yup.string().required("Please enter your Email"),
  password: yup
    .string()
    .required("Please enter your Password")
    .matches(
      /^(?=.*?[A-Z])(?=.*?[^\w\s]).{1,}$/,
      "Password at least 1 capital letter and 1 special character"
    ),
  dob: yup.string().required("Please enter your Date of Birth"),
  address: yup.string().required("Please enter your Address"),
  profilePic: yup.mixed().required("Please upload your profile picture"),
});

export const updateSchema = yup.object({
  newName: yup
    .string()
    .min(2, "Name must be at least 2 characters")
    .max(30, "Name must be at most 30 characters")
    .required("Please enter your Name"),
  newEmail: yup
    .string()
    .email("Invalid email")
    .required("Please update your Email"),
  newPassword: yup
    .string()
    .required("Please enter your Password")
    .matches(
      /^(?=.*?[A-Z])(?=.*?[^\w\s]).{1,}$/,
      "Password must contain at least 1 capital letter and 1 special character"
    ),
  newDateofbirth: yup.string().required("Please update your Date of Birth"),
  newAddress: yup.string().required("Please update your Address"),
  image: yup.mixed().required("Please update your profile picture"),
});

export const resetSchema = yup.object({});
