package com.springboot.shoppy_fullstack_app.dto;

import lombok.Data;

@Data
public class CartListResponse {
    private String id;
    private String mname;
    private String phone;
    private String email;
    private int pid;
    private String name;
    private String info;
    private String image;
    private int price;
    private String size;
    private int qty;
    private int cid;
    private int totalPrice;
}
