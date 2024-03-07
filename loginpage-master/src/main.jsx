import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App.jsx";
// import reportWebVitals from './reportWebVitals.js'
import "./index.css";
import { BrowserRouter } from "react-router-dom";

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <BrowserRouter>
      <App />
    </BrowserRouter>
  </React.StrictMode>
);
