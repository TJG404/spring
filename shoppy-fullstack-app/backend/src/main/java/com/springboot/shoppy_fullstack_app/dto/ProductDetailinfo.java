package com.springboot.shoppy_fullstack_app.dto;

import lombok.Data;

@Data
public class ProductDetailinfo {
    private int did;
    private int pid;
    private String list;
    private String titleEn;
    private String titleKo;
}
