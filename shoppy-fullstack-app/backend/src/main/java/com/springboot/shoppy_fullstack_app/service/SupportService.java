package com.springboot.shoppy_fullstack_app.service;

import com.springboot.shoppy_fullstack_app.dto.Support;

import java.util.List;

public interface SupportService {
    List<Support> findAll(Support support);
}
