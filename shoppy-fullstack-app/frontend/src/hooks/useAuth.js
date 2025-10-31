import React, { useContext } from 'react';
import { AuthContext } from '../context/AuthContext.js';

/**
 * AuthContext에 저장된 데이터를 제어하는 커스텀 훅 함수
 */
export function useAuth() {
    const { isLogin, setIsLogin } = useContext(AuthContext);

    //로그인
    const handleLogin = (userId) => {
        setIsLogin(!isLogin); 
        const loginInfo = {
                    "userId": userId,
                    "token": "dkfj122345dfdf"
                }
        // 로그인 정보를 브라우저 > Application Tab > Local Storage에 객체를 문자열로 저장
        localStorage.setItem("loginInfo", JSON.stringify(loginInfo)); 
    }

    //로그아웃
    const handleLogout = () => {
        alert("로그아웃 되었습니다.");
        setIsLogin(!isLogin);
        localStorage.removeItem("loginInfo");
    }


    return { handleLogin, handleLogout }
}

