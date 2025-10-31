import { Link, useNavigate } from 'react-router-dom';
import { FiShoppingBag } from "react-icons/fi";
import { GiShoppingCart } from "react-icons/gi";
import { useSelector, useDispatch } from 'react-redux';
import { getLogout } from '../../feature/auth/authAPI.js';

export function Header() {
    const navigate = useNavigate();
    const dispatch = useDispatch();
    const cartCount = useSelector((state) => state.cart.cartCount);
    const isLogin = useSelector((state) => state.auth.isLogin);
    let userId = null;
    if(isLogin) userId  = JSON.parse(localStorage.getItem("loginInfo")).userId;

    const handleLogout = () => {
        const succ = dispatch(getLogout());
//         const loginInfo = localStorage.getItem("loginInfo");
        if(succ) {
            alert("로그아웃 되었습니다");
            navigate("/");
        }
    }

    return (
        <div className="header-outer">
            <div className="header">
                <Link to="/" className='header-left'>
                    <FiShoppingBag />
                    <span>Shoppy-redux(toolkit)::fullstack</span>
                </Link>
                <nav className='header-right'>
                    {isLogin && <span>[{userId}]</span> }
                    <Link to="/all">Products</Link>
                    <Link to="/cart" className="header-icons-cart-link">
                        <GiShoppingCart className='header-icons'/>
                        <span className='header-icons-cart'>{cartCount}</span>
                    </Link>
                    { !isLogin && 
                        <Link to="/login">
                            <button type="button">Login</button>
                        </Link>                    
                    }
                    { isLogin &&
                        <button type="button"
                                onClick={handleLogout}>Logout</button>
                    }
                    <Link to="/signup">
                        <button type="button">Signup</button>
                    </Link>    
                    { isLogin &&
                        <Link to="/support">
                            <button type="button">Support</button>
                        </Link>                   
                    }               
                </nav>
            </div>
        </div>
    );
}