package com.example.springbootbasic.security;

import com.example.springbootbasic.util.Privileges;
import com.example.springbootbasic.util.Roles;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
//@EnableWebSecurity // 시큐리티 활성화 (version 낮을 때는 해야 함, 5점대 이상은 생략 가능)
public class WebSecurityConfig {
    private static final String[] WHITELIST={
        "/",
        "/login",
        "/register",
         "/css/**",
         "/fonts/**",
         "/images/**",
         "/js/**"
    };

    @Bean // 객체 생성
    public static PasswordEncoder passwordEncoder(){
         return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
    // 요청 url이 HttpSecurity http로 넘어옴
    // 그걸 SecurityFilterChain 필터링해야 한다

        http
                .authorizeHttpRequests(authz->authz
                        .requestMatchers(WHITELIST).permitAll() // permitAll() : 인증 없이 허가
                        .requestMatchers("/profile/**").authenticated()
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        // hasRole : 해당 역할 있어야 가능, // 'ROLE_ADMIN'의 'ROLE_' 생략
                        .requestMatchers("/editor/**").hasAnyRole("ADMIN", "EDITOR")
                        // hasAnyRole(): 역할 중 둘 중 하나만 있어도 가능
                        .requestMatchers("/test").hasAuthority(Privileges.ACCESS_ADMIN_PANEL.getPrivilege())
                        // hasAuthority() : 해당 권한이 있는 사람만 가능
                        .anyRequest().authenticated() // 나머지 url들은 인증이 있어야 접속 가능 -> login창으로 이동시킴
                )
                .formLogin(frm->frm
                        .loginPage("/login")
                        .loginProcessingUrl("/loginProc") // 언제 동작할 건지 설정
                        .usernameParameter("email") // username의 이름 알려주기 (다를 경우에만 적으면 됨)
                        // String username = request.getParameter("username") -> 이게 원래 구성되어 있음.
                        .passwordParameter("password") // password의 이름 알려주기 (password는 이름이 동일하니 생략 가능)
                        .defaultSuccessUrl("/", true) // 성공시는 "/" 루트로 이동
                        .failureUrl("/login?error") // failureUrl : 실패시 해당 url로 이동
                        .permitAll()
                )
                .logout(logout->logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/")
                        .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET")) // 기본이 post
                )
                .httpBasic(withDefaults());
        return  http.build();

    }
}
