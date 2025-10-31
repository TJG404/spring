package com.springboot.shoppy_fullstack_app.repository;

import com.springboot.shoppy_fullstack_app.dto.Member;

public interface MemberRepository {
    String login(String id);
    int save(Member member);
    Long findById(String id);
}
