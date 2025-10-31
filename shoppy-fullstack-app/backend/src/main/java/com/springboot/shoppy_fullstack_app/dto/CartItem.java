package com.springboot.shoppy_fullstack_app.dto;

import lombok.Data;

@Data
public class CartItem {
    private int cid;
    private String size;
    private int qty;
    private int pid;
    private String id;
    private String cdate;
    private int checkQty;
    private String type;
    private int sumQty;
}
