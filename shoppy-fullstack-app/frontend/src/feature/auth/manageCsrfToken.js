import axios from "./axiosSetup.js";

// ✅ 최초 XSRF-TOKEN 쿠키 발급
export const createCsrfToken = async() => {
  try {
    await axios.get("/csrf/create");   // 쿠키 XSRF-TOKEN이 생김
    console.log("✔ 토큰 최초 발급 ---------> csrf 쿠키 생성 완료");
  } catch (e) {
    console.error("CSRF init failed", e);
  }
}

// ✅ 로그인/로그아웃 시 XSRF-TOKEN 쿠키 재발급
export const refreshCsrfToken = async() => {
  try {
    await axios.post("/csrf/refresh", {});   // 쿠키 XSRF-TOKEN이 생김
    console.log("✔ 토큰 재발급 ---------> csrf 쿠키 생성 완료");
  } catch (e) {
    console.error("CSRF init failed", e);
  }
}