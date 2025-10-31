import { useState, useRef, useContext } from 'react';
import { useNavigate } from 'react-router-dom';
import { FaRegUser } from "react-icons/fa6";
import { FaLock } from "react-icons/fa";
import { validateFormCheck } from '../utils/validate.js';
import { AuthContext } from '../context/AuthContext.js';
import { useDispatch} from 'react-redux';
import { getLogin } from '../feature/auth/authAPI.js';

export function Login() {
    const dispatch = useDispatch();
    const navigate = useNavigate();
    const idRef = useRef(null);
    const pwdRef = useRef(null);
    const [formData, setFormData] = useState({id:'', pwd:''});
    const [errors, setErrors] = useState({id:'', pwd:''});

    const handleFormChange = (e) => {
        const { name, value } = e.target; 
        setFormData({...formData, [name]:value});
        setErrors({id:'', pwd:''});
    }

    const handleLoginSubmit = async (e) => {
        e.preventDefault();
        const param = {
            idRef: idRef,
            pwdRef: pwdRef,
            setErrors: setErrors,
            errors: errors
        }
       
        const succ = await dispatch(getLogin(formData, param));

        if(succ) {
            alert("로그인에 성공하셨습니다.");
            navigate("/");
        } else {
            alert("로그인에 실패, 확인후 다시 진행해주세요.");
            setFormData({id:'', pwd:''});
            idRef.current.focus();
        }
    }
    
    return (
    <div className="content">
        <div className="center-layout login-form">
            <h1 className="center-title">로그인</h1>
            <form onSubmit={handleLoginSubmit}>
                <ul>
                    <li>
                        <p>아이디 비밀번호를 입력하신 후, 로그인 버튼을 클릭해 주세요.</p>
                    </li>
                    <li>
                        <div className="login-form-input">
                            <FaRegUser />
                            <input  type="text" 
                                    name="id" 
                                    value={formData.id}
                                    ref={idRef}
                                    onChange={handleFormChange}
                                    placeholder="아이디를 입력해주세요" />
                        </div>
                        <span style={{color:"red", fontSize:"0.8rem"}}>{errors.id}</span>
                    </li>
                    <li>
                        <div className="login-form-input">
                            <FaLock />
                            <input  type="password" 
                                    name="pwd" 
                                    value={formData.pwd}
                                    ref={pwdRef}
                                    onChange={handleFormChange}
                                    placeholder="패스워드를 입력해주세요" />
                        </div>
                        <span style={{color:"red", fontSize:"0.8rem"}}>{errors.pwd}</span>
                    </li>
                    <li>
                        <button type="submit"
                                className="btn-main-color"                                
                                >로그인</button>
                    </li>
                    <li>
                        <div>
                            <input type="checkbox" name="status" />
                            <label for="">아이디 저장</label>
                        </div>
                        <div>
                            <a href="#">아이디 찾기</a> 
                            <span>&gt;</span>
                            <a href="#">비밀번호 찾기</a> 
                            <span>&gt;</span>
                        </div>
                    </li>
                    <li>
                        <button className="btn-main-color-naver">네이버 로그인</button>
                    </li>
                </ul>
                <div>
                    <img src="https://adimg.cgv.co.kr//images/202206/loginplus/350x300.png" alt=""/>
                </div>
            </form>
        </div>
    </div>
    );
}