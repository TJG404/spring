package com.springboot.shoppy_fullstack_app.dto;

import lombok.Data;

@Data
public class ProductQna {
    private int qid;
    private String title;
    private String content;
    private boolean isComplete;
    private boolean isLock;
    private String id;
    private int pid;
    private String cdate;
}
