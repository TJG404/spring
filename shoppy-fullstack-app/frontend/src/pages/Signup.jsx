import React, { useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { useDispatch } from 'react-redux';
import { validateSignupFormCheck } from '../utils/validate.js';
import { initForm } from '../utils/init.js';
import { axiosPost } from '../utils/dataFetch.js';
import { getSignup, getIdCheck } from '../feature/auth/authAPI.js';

export function Signup() {
    const dispatch = useDispatch();
    const navigate = useNavigate();
    const initArray = ['id', 'pwd', 'cpwd', 'name', 'phone', 'emailName', 'emailDomain'];
    // const initForm = initArray.reduce((acc,cur) => {  //비동기
    //         acc[cur] = "";
    //         return acc;
    // }, {});

    const refs = useMemo(() => {  //Hooks 비동기식 처리 진행
        return initArray.reduce((acc,cur) => {
            acc[`${cur}Ref`] = React.createRef();         
            return acc;
        }, {});
    });   

    const [form, setForm] = useState(initForm(initArray));  //{id:"hong", ...}
    const [errors, setErrors] = useState({...initForm(initArray), emailDomain: ""});

    const handleChangeForm = (e) => {
        const { name, value } = e.target;
        setForm({ ...form, [name]: value});
        setErrors({...initForm(initArray), emailDomain: ""});
    }

    const handleResetForm = () => {
        setForm(initForm(initArray));       
    }

    const handleSubmit = async(e) => {
        e.preventDefault();
        const param = {  refs: refs,   setErrors: setErrors }
        const formData = { ...form, email: form.emailName.concat('@', form.emailDomain) }
        const result = await dispatch(getSignup(formData, param));
//         console.log('result------>> ', result);
        if(result) {
            alert("회원가입 성공!!");
            navigate("/login");
        }    else alert("회원가입 실패!!");
    }//handleSubmit

    /** 아이디 중복체크 */
    const handleDupulicateIdCheck = async() => {
        const result = await dispatch(getIdCheck(form.id));
        alert(result);
    }

    return (
    <div className="content">
        
        <div className="join-form center-layout">
            <h1 className="center-title">회원가입(React)</h1>
            <form onSubmit={handleSubmit}>
                <ul>
                    <li>
                        <label for="" ><b>아이디</b></label>
                        <span style={{color:"red", fontSize:"0.8rem"}}>{errors.id}</span>
                        <div>
                            <input type="text" 
                                    name="id"    
                                    value={form.id}    
                                    ref={refs.idRef} 
                                    onChange={handleChangeForm}               
                                    placeholder = "아이디 입력(6~20자)" />
                            <button type="button"
                                    onClick={handleDupulicateIdCheck}
                                  > 중복확인</button>
                            <input type="hidden" id="idCheckResult" value="default" />
                        </div>
                    </li>
                    <li>
                        <label for=""><b>비밀번호</b></label>
                        <div>
                            <input type="password" 
                                    name="pwd"
                                    ref={refs.pwdRef}
                                    value={form.pwd}     
                                    onChange={handleChangeForm} 
                                    placeholder="비밀번호 입력(문자,숫자,특수문자 포함 6~12자)"/>
                        </div>
                    </li>
                    <li>
                        <label for=""><b>비밀번호 확인</b></label>
                        <div>
                            <input type="password" 
                                    name="cpwd"
                                    value={form.cpwd}     
                                    ref={refs.cpwdRef}
                                    onChange={handleChangeForm} 
                                    placeholder="비밀번호 재입력"/>
                        </div>
                    </li>
                    <li>
                        <label for=""><b>이름</b></label>
                        <div>
                            <input type="text" 
                                    name="name"
                                    value={form.name}     
                                    ref={refs.nameRef}
                                    onChange={handleChangeForm} 
                                    placeholder="이름을 입력해주세요"/>
                        </div>
                    </li>
                    <li>
                        <label for=""><b>전화번호</b></label>
                        <div>
                            <input type="text" 
                                    name="phone"
                                    value={form.phone}   
                                    ref={refs.phoneRef}  
                                    onChange={handleChangeForm} 
                                    placeholder="휴대폰 번호 입력('-' 포함)"/>
                        </div>
                    </li>
                    <li>
                        <label for=""><b>이메일 주소</b></label>
                        <span style={{color:"red", fontSize:"0.8rem"}}>{errors.emailDomain}</span>
                        <div>
                            <input type="text" 
                                    name="emailName"
                                    value={form.emailName}    
                                    ref={refs.emailNameRef} 
                                    onChange={handleChangeForm} 
                                    placeholder="이메일 주소"/>
                            <span>@</span>       
                            <select name="emailDomain" 
                                    value={form.emailDomain}    
                                    ref={refs.emailDomainRef} 
                                    onChange={handleChangeForm} 
                                    >
                                <option value="default">선택</option>
                                <option value="naver.com">naver.com</option>
                                <option value="gmail.com">gmail.com</option>
                                <option value="daum.net">daum.net</option>
                            </select>
                        </div>
                    </li>
                    <li>
                        <button type="submit">가입하기</button>
                        <button type="reset"
                                onClick={handleResetForm}>다시쓰기</button>
                    </li>
                </ul>
            </form>
        </div>
    </div>
    );
}

