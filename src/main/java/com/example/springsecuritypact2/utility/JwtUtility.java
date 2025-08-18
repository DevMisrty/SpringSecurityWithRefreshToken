package com.example.springsecuritypact2.utility;

import com.example.springsecuritypact2.model.Users;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Service
public class JwtUtility {

    public String secretKey = "ans;kbc/;buibck;b;jbckjbdgiagdcba'obcjandc;bacdn,ab'cdbajblib";

    public SecretKey getKey(){
        return Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
    }

    public String createAccessToken(Users users){
        return Jwts.builder()
                .subject(users.getUsername())
                .claim("role", users.getRole())
                .claim("age",users.getAge())
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis()+ 1000 * 60 * 10))
                .signWith(getKey())
                .compact();
    }

    public String createRefreshToken(Users users){
        return Jwts.builder()
                .subject(users.getUsername())
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis()+ 1000L * 60 *60 *24 * 180))
                .signWith(getKey())
                .compact();
    }

    public boolean isValidToken(String token){
        return Jwts.parser()
                .verifyWith(getKey())
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getExpiration()
                .after(new Date());
    }

    public String getUsername(String token) {
        return Jwts.parser()
                .verifyWith(getKey())
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }
}
