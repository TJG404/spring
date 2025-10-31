import { login, logout } from '../../feature/auth/authSlice.js';
import { validateFormCheck,  validateSignupFormCheck } from '../../utils/validate.js';
import { axiosPost } from '../../utils/dataFetch.js';
import { getCartCount } from '../../feature/cart/cartAPI.js';
import { updateCartCount, resetCartCount } from '../../feature/cart/cartSlice.js';
import { refreshCsrfToken } from '../../utils/manageCsrfToken.js';

/**
    Id 중복 체크
*/
export const getIdCheck = (id) => async(dispatch) => {
            const data = { "id": id };
            const url = "/member/idcheck";
            const result = await axiosPost(url, data);
            return result;
}

/**
    Signup
*/
export const getSignup = (formData, param) => async(dispatch) => {
     let result = null;
     if(validateSignupFormCheck(param)) {
                const url = "/member/signup";
                result = await axiosPost(url, formData);
      }
      return result;
}

/**
    Login
*/
export const getLogin = (formData, param) => async(dispatch) => {

    if(validateFormCheck(param)) {
        const url = "/member/login";
        const result = await axiosPost(url, formData);
        if(result.login) {
            dispatch(login({"userId":formData.id}));
            dispatch(getCartCount(formData.id));
            return true;
        }
    }
    return false;
}

/**
    Logout
 */
export const getLogout = () => async(dispatch) => {
    const url = "/member/logout";
    const result = await axiosPost(url, {});
    if(result) {
        refreshCsrfToken();  //csrf 토큰 재발급
        dispatch(logout());
        dispatch(resetCartCount());
    }
}
