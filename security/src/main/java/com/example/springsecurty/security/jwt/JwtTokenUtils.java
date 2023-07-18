package com.example.springsecurty.security.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.springsecurty.model.User;
import com.example.springsecurty.repository.UserRepository;
import com.example.springsecurty.security.UserDetailsImpl;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@RequiredArgsConstructor
@Component
public class JwtTokenUtils {

    private final UserRepository userRepository;

    @Value("${spring.auth.secret.key}")
    String JWT_SECRET;

    private int SEC = 1;
    private int MINUTE = SEC * 60;
    private int HOUR = MINUTE * 60;
    private int DAY = 24 * HOUR;

    private int ACCESS_TOKEN_VALID_MILLI_SEC = 12 * HOUR * 1000;
    private int REFRESH_TOKEN_VALID_MILLI_SEC = 60 * DAY * 1000;


    final String CLAIM_EXPIRED_DATE = "EXPIRED_DATE";
    final String CLAIM_USER_NAME = "USER_NAME";
    final String ACCESS_TOKEN = "ACCESS_TOKEN";
    final String REFRESH_TOKEN = "REFRESH_TOKEN";

    public Map<String, String> generateJwtToken(UserDetailsImpl userDetails){
        try {
            Map<String, String> map = new HashMap<>();

            String accessToken = JWT.create()
                    .withIssuer("test")
                    .withClaim(CLAIM_USER_NAME, userDetails.getUsername())
                    .withClaim(CLAIM_EXPIRED_DATE, new Date(System.currentTimeMillis() + ACCESS_TOKEN_VALID_MILLI_SEC))
                    .sign(Algorithm.HMAC256(JWT_SECRET));

            String refreshToken = JWT.create()
                    .withIssuer("test")
                    .withClaim(CLAIM_USER_NAME, userDetails.getUsername())
                    .withClaim(CLAIM_EXPIRED_DATE, new Date(System.currentTimeMillis() + REFRESH_TOKEN_VALID_MILLI_SEC))
                    .sign(Algorithm.HMAC256(JWT_SECRET));

            map.put(ACCESS_TOKEN, accessToken);
            map.put(REFRESH_TOKEN, refreshToken);

            User user = userRepository.findByUserId(userDetails.getUsername());
            user.setRefreshToken(refreshToken);
            userRepository.save(user);

            return map;
        }
        catch (Exception e){
            throw new IllegalArgumentException("ERROR CREATE JWT TOKEN");
        }
    }

    public String reissuanceAccessToken(String username){
        try {
            String accessToken = JWT.create()
                    .withIssuer("test")
                    .withClaim(CLAIM_USER_NAME, username)
                    .withClaim(CLAIM_EXPIRED_DATE, new Date(System.currentTimeMillis() + ACCESS_TOKEN_VALID_MILLI_SEC))
                    .sign(Algorithm.HMAC256(JWT_SECRET));

            return accessToken;
        }
        catch (Exception e){
            throw new IllegalArgumentException("ERROR CREATE REISSUANCE ACCESS TOKEN");
        }

    }

    public String reissuanceRefreshToken(String username){
        try {
            String refreshToken = JWT.create()
                    .withIssuer("test")
                    .withClaim(CLAIM_USER_NAME, username)
                    .withClaim(CLAIM_EXPIRED_DATE, new Date(System.currentTimeMillis() + ACCESS_TOKEN_VALID_MILLI_SEC))
                    .sign(Algorithm.HMAC256(JWT_SECRET));

            return refreshToken;
        }
        catch (Exception e){
            throw new IllegalArgumentException("ERROR CREATE REISSUANCE ACCESS TOKEN");
        }

    }

}
