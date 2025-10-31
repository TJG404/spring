package com.springboot.shoppy_fullstack_app.dto;

import lombok.Data;

@Data
public class ProductReturn {
    private int rid;
    private String title;
    private String description;
    private String list;
}
