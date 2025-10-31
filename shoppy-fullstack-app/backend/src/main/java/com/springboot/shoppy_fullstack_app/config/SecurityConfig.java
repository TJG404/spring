package com.springboot.shoppy_fullstack_app.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
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
                //                .securityMatcher("/api/**")
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
//                        .ignoringRequestMatchers("/member/logout")
                )
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
                .formLogin(form -> form.disable())   // 리다이렉트 발생 폼로그인 비활성화
                .httpBasic(basic -> basic.disable())
                .requestCache(rc -> rc.disable())// (선택)
                .securityContext(sc -> sc.requireExplicitSave(true))
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
 * SPA(React, VUE ..) 연동을 위한 CSRF TOKEN  핸들러 클래스
 */
final class SpaCsrfTokenRequestHandler implements CsrfTokenRequestHandler {
    private final CsrfTokenRequestHandler plain = new CsrfTokenRequestAttributeHandler();
    private final CsrfTokenRequestHandler xor = new XorCsrfTokenRequestAttributeHandler();

    @Override
    public void handle(HttpServletRequest request,
                       HttpServletResponse response,
                       Supplier<CsrfToken> csrfToken) {
        /*
         * Always use XorCsrfTokenRequestAttributeHandler to provide BREACH protection of
         * the CsrfToken when it is rendered in the response body.
         * /*
         * 항상 XorCsrfTokenRequestAttributeHandler를 사용하여 BREACH 보호 제공
         * 응답 본문에서 렌더링될 때의 CsrfToken.
         */

        this.xor.handle(request, response, csrfToken);
        /*
         * Render the token value to a cookie by causing the deferred token to be loaded.
         * 연기된 토큰을 로드하여 토큰 값을 쿠키에 렌더링합니다.
         */
        csrfToken.get();
    }

    @Override
    public String resolveCsrfTokenValue(HttpServletRequest request, CsrfToken csrfToken) {
        String headerValue = request.getHeader(csrfToken.getHeaderName());
        /*
         * If the request contains a request header, use CsrfTokenRequestAttributeHandler
         * to resolve the CsrfToken. This applies when a single-page application includes
         * the header value automatically, which was obtained via a cookie containing the
         * raw CsrfToken.
         *
         * In all other cases (e.g. if the request contains a request parameter), use
         * XorCsrfTokenRequestAttributeHandler to resolve the CsrfToken. This applies
         * when a server-side rendered form includes the _csrf request parameter as a
         * hidden input.
         * 요청에 요청 헤더가 포함된 경우, CsrfTokenRequestAttributeHandler를 사용합니다
         * CSRfToken을 해결합니다. 이는 단일 페이지 애플리케이션이 다음을 포함할 때 적용됩니다
         * 헤더 값은 다음을 포함하는 쿠키를 통해 자동으로 얻어졌습니다
         * 원시 CSRfToken.
         *
         * 다른 모든 경우(예: 요청에 요청 매개변수가 포함된 경우)
         * XorCsrfTokenRequestAttributeHandler가 CSRfToken을 해결하도록 요청합니다. 이는 적용됩니다
         * 서버 측 렌더링된 양식에 _csrf 요청 매개변수가 포함된 경우
         * 숨겨진 입력.
         */
        return (StringUtils.hasText(headerValue) ? this.plain : this.xor).resolveCsrfTokenValue(request, csrfToken);
    }
}