import React from 'react';
import { addCartItem, updateCartCount, 
         showCartItem, updateTotalPrice,
         updateCartItem, removeCartItem } from './cartSlice.js';
import { axiosData, axiosPost } from '../../utils/dataFetch.js';


export const getCartCount = (id) => async(dispatch) => {
    const url = "/cart/count";
    const data = {"id": id};
    const jsonData = await axiosPost(url, data);
    dispatch(updateCartCount({"count": jsonData.sumQty}));
}

export const removeCart = (cid) => async(dispatch) => {
    const url = "/cart/deleteItem";
    const data = {"cid": cid};
    const rows = await axiosPost(url, data);
    const { userId } = JSON.parse(localStorage.getItem("loginInfo"));
    dispatch(getCartCount(userId));
    dispatch(showCart());
}

export const showCart = () => async (dispatch) => {
    const url = "/cart/list";
    const { userId } = JSON.parse(localStorage.getItem("loginInfo"));
    const jsonData = await axiosPost(url, {"id": userId});
    dispatch(showCartItem({"items": jsonData}));
    jsonData.length && dispatch(updateTotalPrice({"totalPrice" : jsonData[0].totalPrice}));
}

export const updateCart = (cid, type) => async(dispatch) => {
    const url = "/cart/updateQty";
    const data = {"cid": cid, "type": type};
    const rows = await axiosPost(url, data);
    const { userId } = JSON.parse(localStorage.getItem("loginInfo"));
    dispatch(getCartCount(userId));
    dispatch(showCart());
//    return rows;
}

export const checkQty = async(pid, size, id) => {
    const url = "/cart/checkQty";
    const data = {"pid": pid, "size": size, "id": id};
    const jsonData = await axiosPost(url, data);
    return jsonData;
}

export const addCart = (pid, size) => async (dispatch) => {
    const { userId } = JSON.parse(localStorage.getItem("loginInfo"));
    const checkResult = await checkQty(pid, size, userId);
    if(!checkResult.checkQty) {
        const url = "/cart/add";
        const item = {"pid":pid, "size":size, "qty":1, "id": userId};
        const rows = await axiosPost(url, item);
        alert("상품이 추가되었습니다");
      } else {
//        const rows = await updateCart(checkResult.cid, "+");
          const rows = dispatch(updateCart(checkResult.cid, "+"));
        alert("상품이 추가되었습니다");
      }
      dispatch(getCartCount(userId));
}

