package com.example.springsecurty.security;

import com.example.springsecurty.security.jwt.JwtTokenUtils;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

public class FormLoginSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {
    private final JwtTokenUtils jwtTokenUtils;

    String AUTH_HEADER = "Authorization";
    String TOKEN_TYPE = "BEARER";
    ObjectMapper objectMapper = new ObjectMapper();

    public FormLoginSuccessHandler(JwtTokenUtils jwtTokenUtils) {
        this.jwtTokenUtils = jwtTokenUtils;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws ServletException, IOException {
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        String token = jwtTokenUtils.generateJwtToken(userDetails);

        response.addHeader(AUTH_HEADER, TOKEN_TYPE + " " + token);
        response.setContentType("application/json");
    }
}
