package com.springboot.shoppy_fullstack_app.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.*;
import org.springframework.util.StringUtils;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.function.Supplier;

/**
 * Spring Security 6.XX
 */

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                //.securityMatcher("/api/**")
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/csrf/**","/member/**", "/product/**", "/cart/**", "/support/**","/payment/**").permitAll()
//                        .requestMatchers("/api/user/**").hasRole("USER")
//                        .requestMatchers("/api/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated()
                )
                .cors((cors) -> cors
                        .configurationSource(corsConfigurationSource())
                )
                .csrf((csrf) -> csrf
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                        .csrfTokenRequestHandler(new SpaCsrfTokenRequestHandler())
                )
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
                .formLogin(form -> form.disable())   // 리다이렉트 발생 폼로그인 비활성화
                .httpBasic(basic -> basic.disable())
                .requestCache(rc -> rc.disable()) //로그인 후 리다이렉트 방지
                .securityContext(sc -> sc.requireExplicitSave(true)) //인증정보 세션 자동저장 방지
                //✨ SPA(React,Vue) 같은 클라이언트에서 RESTful 로그인(JSON 응답)과 세션/CSRF를 명확히 제어하기 위한 필수입력!!!
                ;

        return http.build();
    }


    /**
     * CORS 스프링 보안 객체
     */
    @Bean
    UrlBasedCorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("http://localhost:3000"));
        configuration.setAllowedMethods(Arrays.asList("GET","POST"));
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    /**
    * 비밀번호 암호화 설정 (PasswordEncoder)
    * Spring Security는 반드시 비밀번호를 암호화하여 저장하고 비교해야 함!!
    */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }


}//SecurityConfig class


/**
 * SPA(React, VUE) 연동을 위한 CSRF TOKEN  핸들러 클래스
 */
final class SpaCsrfTokenRequestHandler implements CsrfTokenRequestHandler {
    private final CsrfTokenRequestHandler plain = new CsrfTokenRequestAttributeHandler();
    private final CsrfTokenRequestHandler xor = new XorCsrfTokenRequestAttributeHandler();

    @Override
    public void handle(HttpServletRequest request,
                       HttpServletResponse response,
                       Supplier<CsrfToken> csrfToken) {

        this.xor.handle(request, response, csrfToken); //BEACH 공격 보호 제공
        csrfToken.get(); //토큰을 로드하여 토큰값을 쿠키에 렌더링
    }

    @Override
    public String resolveCsrfTokenValue(HttpServletRequest request, CsrfToken csrfToken) {
        String headerValue = request.getHeader(csrfToken.getHeaderName());

        return (StringUtils.hasText(headerValue)
                ? this.plain : this.xor).resolveCsrfTokenValue(request, csrfToken);
        //headerValue가 plain, xor 인지 체크하여 클라이언트에게 전송할 csrfToken 값 or 검증할 데이터 값을
        //생성하여 반환함
    }
}