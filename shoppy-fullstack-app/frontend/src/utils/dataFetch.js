//import axios from 'axios';
import axios from './axiosSetup.js';

/**
    Spring-Security 6.X : CSRF + SESSION 적용 환경
*/
//axios.defaults.withCredentials = true;
//await axios.get("/api/csrf"); // XSRF-TOKEN 쿠키 발급 유도
//const token = getCookie("XSRF-TOKEN");
//await axios.post("/member/login", data, { headers: { "X-XSRF-TOKEN": token } });
//



/**
 * axiosGet 함수를 이용하여 백엔드 연동 처리
 */
export const axiosGet = async (url) => {
    const response = await axios.get(url);
    return response.data;
}

/**
 * axiosPost 함수를 이용하여 백엔드 연동 처리
 */
export const axiosPost = async (url, formData) => {
    const response = await axios.post(url, formData
                        , { "Content-Type": "application/json" });
    return response.data;
}

/**
 * axios 함수를 이용하여 데이터 가져오기
 */
export const axiosData = async (url) => {
    const response = await axios.get(url);
    return response.data;
}

/**
 * fetch 함수를 이용하여 데이터 가져오기
 */
export const fetchData = async (url) => {
    const response = await fetch(url);
    const jsonData = await response.json(); 
    return jsonData;
}

/**
 * 배열의 rows 그룹핑
 */
export const groupByRows = (array, number) => {
    const rows = array.reduce((acc, cur, idx) => {
        if(idx % number === 0) acc.push([cur])
        else acc[acc.length-1].push(cur);
        return acc;
    }, []);

    return rows;
}
