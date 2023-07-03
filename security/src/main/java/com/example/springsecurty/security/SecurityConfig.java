package com.example.springsecurty.security;

import com.example.springsecurty.repository.UserRepository;
import com.example.springsecurty.security.filter.FormLoginFilter;
import com.example.springsecurty.security.filter.JwtAuthFilter;
import com.example.springsecurty.security.jwt.HeaderTokenExtractor;
import com.example.springsecurty.security.jwt.JwtTokenUtils;
import com.example.springsecurty.security.provider.FormLoginAuthProvider;
import com.example.springsecurty.security.provider.JWTAuthProvider;
import java.util.ArrayList;
import java.util.List;
import javafx.util.Pair;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final UserRepository userRepository;
    private final UserDetailServiceImpl userDetailService;
    private final JwtTokenUtils jwtTokenUtils;
    private final HeaderTokenExtractor extractor;

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .formLogin().disable()
                .httpBasic().disable()
                .apply(new MyCustomDsl()) // 커스텀 필터 등록
                .and()
                .authorizeRequests().anyRequest().permitAll()
                .and()
                .build();
    }

    @Bean
    public BCryptPasswordEncoder encodePassword(){
        return new BCryptPasswordEncoder();
    }

//    @Bean
//    public WebSecurityCustomizer webSecurityCustomizer(){
//        return (web) -> web.ignoring().antMatchers("/h2-console/**");
//    }

    @Autowired
    void registerProvider(AuthenticationManagerBuilder auth){
        auth.authenticationProvider(new FormLoginAuthProvider(userDetailService, encodePassword()));
        auth.authenticationProvider(new JWTAuthProvider(userRepository, jwtTokenUtils));
    }

    FormLoginFilter formLoginFilter(AuthenticationManager authenticationManager){
        FormLoginFilter formLoginFilter = new FormLoginFilter(authenticationManager);
        formLoginFilter.setFilterProcessesUrl("/user/login");
        formLoginFilter.setAuthenticationSuccessHandler(new FormLoginSuccessHandler(jwtTokenUtils));
        formLoginFilter.afterPropertiesSet();
        return formLoginFilter;
    }

    JwtAuthFilter jwtAuthFilter(AuthenticationManager authenticationManager){
        List<Pair<HttpMethod, String>> skipPathList = new ArrayList<>();
        Pair<HttpMethod, String> pair = new Pair<>(HttpMethod.POST, "/user");
        skipPathList.add(pair);

        FilterSkipMatcher matcher = new FilterSkipMatcher(skipPathList, "/**");
        JwtAuthFilter filter = new JwtAuthFilter(matcher, extractor);
        filter.setAuthenticationManager(authenticationManager);
        return filter;
    }

    public class MyCustomDsl extends AbstractHttpConfigurer<MyCustomDsl, HttpSecurity> {
        @Override
        public void configure(HttpSecurity http) throws Exception {
            AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
            http
                    .addFilterBefore(formLoginFilter(authenticationManager), UsernamePasswordAuthenticationFilter.class)
                    .addFilterBefore(jwtAuthFilter(authenticationManager), UsernamePasswordAuthenticationFilter.class);
        }
    }

}
