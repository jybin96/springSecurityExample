package com.example.springsecurty.controller;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.springsecurty.dto.SignUpDto;
import com.example.springsecurty.model.User;
import com.example.springsecurty.repository.UserRepository;
import com.example.springsecurty.security.UserDetailsImpl;
import com.example.springsecurty.security.jwt.HeaderTokenExtractor;
import com.example.springsecurty.security.jwt.JwtDecoder;
import com.example.springsecurty.security.jwt.JwtTokenUtils;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class UserController {
    private final UserRepository userRepository;
    private final HeaderTokenExtractor extractor;
    private BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
    private final JwtDecoder jwtDecoder;
    private final JwtTokenUtils jwtTokenUtils;

    String ACCESS_TOKEN_HEADER = "Access_Token";
    String REFRESH_TOKEN_HEADER = "Refresh_Token";
    String TOKEN_TYPE = "BEARER";


    @PostMapping("/user")
    public void signUpController(@RequestBody SignUpDto.Reqeust reqeust){
        String encodedPassword = passwordEncoder.encode(reqeust.getPassword());
        User user = new User(reqeust.getUserId(), encodedPassword);
        userRepository.save(user);
    }

    @GetMapping("/refresh")
    public ResponseEntity<String> refresh(HttpServletRequest request, HttpServletResponse response){
        String tokenPayLoad = request.getHeader("Authorization");
        String refreshToken = extractor.extract(tokenPayLoad, request);
        String username = jwtDecoder.decodeUsername(refreshToken);

        String accessToken = jwtTokenUtils.reissuanceAccessToken(username);

        Map<String, String> accessTokenResponseMap = new HashMap<>();

        // === 현재시간과 Refresh Token 만료날짜를 통해 남은 만료기간 계산 === //
        // === Refresh Token 만료시간 계산해 1개월 미만일 시 refresh token도 발급 === //
        long now = System.currentTimeMillis();
        long refreshExpireTime = jwtDecoder.getExpireTime(refreshToken);
        long diffDays = (refreshExpireTime - now) / 1000 / (24 * 3600);
        long diffMin = (refreshExpireTime - now) / 1000 / 60;

        if (diffMin < 5) {
            String newRefreshToken = jwtTokenUtils.reissuanceRefreshToken(username);
            User user = userRepository.findByUserId(username);
            user.setRefreshToken(newRefreshToken);
            userRepository.save(user);

            response.addHeader(REFRESH_TOKEN_HEADER, TOKEN_TYPE + " " + newRefreshToken);
        }

        response.addHeader(ACCESS_TOKEN_HEADER,  TOKEN_TYPE + " " + accessToken);


        return ResponseEntity.ok("완료");
    }

    @PostMapping("/test")
    public void test(@AuthenticationPrincipal UserDetailsImpl userDetails){
        User user = userDetails.getUser();
        System.out.println(user);
    }
}
