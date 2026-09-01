import React from "react";
import ReactDOM from "react-dom/client";
import { registerSW } from "virtual:pwa-register";
import { WebApp } from "./WebApp";
import "./styles.css";

const updateSW = registerSW({ immediate: true, onNeedRefresh() { window.dispatchEvent(new Event('edy-update-ready')); } });
window.addEventListener('edy-apply-update', () => { void updateSW(true); });
const root = document.getElementById("root");
if (!root) throw new Error("Application root was not found.");
ReactDOM.createRoot(root).render(
  <React.StrictMode>
    <WebApp />
  </React.StrictMode>,
);
