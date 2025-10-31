package com.springboot.shoppy_fullstack_app.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/csrf")
public class CsrfController {

    // 최초 진입 or SPA 초기화용
    @GetMapping("/create")
    public ResponseEntity<CsrfToken> getCsrfToken(HttpServletRequest request) {
        CsrfToken token = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        return ResponseEntity.ok(token);
    }

    // 로그아웃 시 강제 갱신용
    @GetMapping("/refresh")
    public ResponseEntity<CsrfToken> refreshCsrfToken(HttpServletRequest request) {
        request.changeSessionId(); // 세션 갱신 (선택)
        CsrfToken token = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        return ResponseEntity.ok(token);
    }
}
