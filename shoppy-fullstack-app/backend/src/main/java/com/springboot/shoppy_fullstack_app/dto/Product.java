package com.springboot.shoppy_fullstack_app.dto;

import lombok.Data;

import java.util.List;

@Data
public class Product {
    private int pid;
    private String name;
    private long price;
    private String info;
    private double rate;
    private String image;
    private String imgList;
}

