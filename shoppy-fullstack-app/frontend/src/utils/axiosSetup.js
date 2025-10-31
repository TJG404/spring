/**
    전역으로 사용되는 axios 설정
*/
import axios from "axios";

// ✅ 쿠키를 보내야 하므로
axios.defaults.withCredentials = true;

// (선택) CRA proxy 사용하는 경우 baseURL 불필요
// axios.defaults.baseURL = "http://localhost:8080";

export default axios;