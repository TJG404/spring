import { createSlice } from '@reduxjs/toolkit'

const initialState = {
  isLogin: false
}

export const authSlice = createSlice({
  name: 'auth',
  initialState,
  reducers: {
        login(state, action) {
            state.isLogin = !state.isLogin;
            const { userId } = action.payload;
            const loginInfo = { "token": "123455dkfdf", "userId": userId};
            localStorage.setItem("loginInfo", JSON.stringify(loginInfo));
        },
        logout(state, action) {
            state.isLogin = !state.isLogin;
            localStorage.removeItem("loginInfo");
        }
  },
})

export const { login, logout } 
    = authSlice.actions   //API 함수 또는 컴포넌트에서 dispatch(액션함수)

export default authSlice.reducer  //store  import