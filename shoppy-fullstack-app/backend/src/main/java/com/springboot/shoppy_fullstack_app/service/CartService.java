package com.springboot.shoppy_fullstack_app.service;

import com.springboot.shoppy_fullstack_app.dto.CartItem;
import com.springboot.shoppy_fullstack_app.dto.CartListResponse;

import java.util.List;

public interface CartService {
    int deleteItem(CartItem cartItem);
    List<CartListResponse> findList(CartItem cartItem);
    CartItem getCount(CartItem cartItem);
    int updateQty(CartItem cartItem);
    CartItem checkQty(CartItem cartItem);
    int add(CartItem cartItem);
}
