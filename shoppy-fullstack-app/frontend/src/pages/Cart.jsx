import { useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { RiDeleteBin6Line } from 'react-icons/ri';
import '../styles/cart.css';

import { useSelector, useDispatch } from 'react-redux';
import { showCart, updateCart, removeCart } from '../feature/cart/cartAPI.js';

export function Cart() {
    const navigate = useNavigate();
    const dispatch = useDispatch();
    const cartList = useSelector((state) => state.cart.cartList);
    const totalPrice = useSelector((state) => state.cart.totalPrice);   
      
    useEffect(()=> {  dispatch(showCart());  }, []);

    return (
        <div className='cart-container'>
            <h2 className='cart-header'>장바구니</h2>
            { cartList && cartList.map(item => 
                <div key={item.pid}>
                    <div className='cart-item'>
                        <img src={`/images/${item.image}`} alt="product img" />
                        <div className='cart-item-details'>
                            <p className='cart-item-title'>{item.name}</p>
                            <p className='cart-item-title'>{item.size}</p>
                            <p className='cart-item-price'>
                                {parseInt(item.price).toLocaleString()}원</p>
                        </div>
                        <div className='cart-quantity'>
                            <button type='button'
                                    onClick={()=>{item.qty > 1 && dispatch(updateCart(item.cid, "-"))}}>-</button>
                            <input type='text' value={item.qty} readOnly/>
                            <button type='button'
                                    onClick={()=>{dispatch(updateCart(item.cid, "+"))}}>+</button>
                        </div>
                        <button className='cart-remove'
                                onClick={()=>{dispatch(removeCart(item.cid))}}> 
                            <RiDeleteBin6Line />
                        </button> 
                    </div>
                </div>    
            )}

            {/* 주문 버튼 출력 */}
            { cartList && cartList.length > 0 ?
                <>
                    <div className='cart-summary'>
                        <h3>주문 예상 금액</h3>
                        <div className='cart-summary-sub'>
                            <p className='cart-total'>
                                <label>총 상품 가격 : </label>
                                <span>{totalPrice.toLocaleString()}원</span>
                            </p>
                            <p className='cart-total'>
                                <label>총 할인 가격 : </label>
                                <span>0원</span>
                            </p>
                            <p className='cart-total'>
                                <label>총 배송비 : </label>
                                <span>0원</span>
                            </p>
                        </div>
                        <p className='cart-total2'>
                            <label>총 금액 : </label>
                            <span>{totalPrice.toLocaleString()}원</span>
                        </p>
                    </div>
                    <div className='cart-actions'>
                        <button type='button'
                                onClick={()=>{
                                    navigate("/checkout");
                                }}>주문하기</button>
                    </div>
                </>
              :  <div>
                    <p> 장바구니에 담은 상품이 없습니다. &nbsp;&nbsp;&nbsp;&nbsp;
                        <Link to="/all">상품보러가기</Link>
                    </p>
                    <img src="/images/cart.jpg" 
                         style={{width:"50%", marginTop:"20px"}} />
                </div>
            } 
        </div>
    );
}

