import React from 'react';
import { createProduct, filterProduct } from './productSlice.js';
import { axiosData, groupByRows, axiosGet,  axiosPost } from '../../utils/dataFetch.js';

/**
    상품 Return
*/
export const getReturn = async() => {
    const url = "/product/return";
    const returnData  = await axiosGet(url);
    const list = JSON.parse(returnData.list);
    return {...returnData, list: list};
}

/**
    상품 QnA
*/
export const getQna = async(pid) => {
    const url = "/product/qna";
    const qna  = await axiosPost(url, {"pid": pid});
    return qna;
}


/**
    상품 상세 정보
*/
export const getDetailinfo = async(pid) => {
    const url = "/product/detailinfo";
    const info  = await axiosPost(url, {"pid": pid});
    const list = JSON.parse(info.list);
    return { ...info, list: list };
}

export const getProduct = (pid) => async(dispatch) => {
    // dispatch(filterProduct(pid));
    const url = "/product/pid";
    const product  = await axiosPost(url, {"pid": pid});
    dispatch(filterProduct({"product": product}));
}

export const getProductList = (number) => async(dispatch) => {
//    const jsonData = await axiosData("/data/products.json");
    const url = "/product/all";
    const jsonData = await axiosGet(url);
    const rows = groupByRows(jsonData, number);
    dispatch(createProduct({"productList": rows, "products":jsonData}));
}

