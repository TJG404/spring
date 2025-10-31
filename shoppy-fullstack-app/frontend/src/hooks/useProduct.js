import React, { useContext } from 'react';
import { ProductContext } from '../context/ProductContext.js';
import { axiosData, groupByRows } from '../utils/dataFetch.js';


export function useProduct() {
    const { productList, setProductList,
            product, setProduct,
            imgList, setImgList
     } = useContext(ProductContext);


    const createProduct = (number) => {
        const load = async () => {
            const jsonData = await axiosData("/data/products.json");
            const rows = groupByRows(jsonData, number);
            setProductList(rows);
        }
        load();
    }

    const filterProduct = (pid) => {        
        // productList가 2차원 배열이므로 flat() 함수를 이용하여 1차원 변경 후 filter
        const [filterProduct] = productList.flat().filter((item) => item.pid === pid);
        setProduct(filterProduct); 
        setImgList(filterProduct.imgList);                        
    }

    return { createProduct, filterProduct };
}

