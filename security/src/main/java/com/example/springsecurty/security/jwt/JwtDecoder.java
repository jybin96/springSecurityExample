package com.example.springsecurty.security.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import java.util.Date;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
    public class JwtDecoder {
    private final JwtTokenUtils jwtTokenUtils;

    public String decodeUsername(String token){
        DecodedJWT decodedJWT = isValidToken(token);

        Date expireDate = decodedJWT.getClaim(jwtTokenUtils.CLAIM_EXPIRED_DATE).asDate();
        Date now = new Date();

        if(expireDate.before(now)){
            throw new IllegalArgumentException("토큰 만료");
        }

        return decodedJWT.getClaim(jwtTokenUtils.CLAIM_USER_NAME).asString();
    }


    DecodedJWT isValidToken(String token){
        try {
            Algorithm algorithm = Algorithm.HMAC256(jwtTokenUtils.JWT_SECRET);
            JWTVerifier verifier = JWT.require(algorithm).build();
            return verifier.verify(token);
        }
        catch (Exception e){
            throw new IllegalArgumentException();
        }
    }
}
