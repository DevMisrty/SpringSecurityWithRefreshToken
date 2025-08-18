package com.example.springsecuritypact2.configuration;

import com.example.springsecuritypact2.model.Users;
import com.example.springsecuritypact2.repository.UsersRepo;
import com.example.springsecuritypact2.utility.JwtUtility;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Service
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {

    private final JwtUtility jwtUtility;
    private final UsersRepo usersRepo;

    @Override
    protected void doFilterInternal(HttpServletRequest request
            , HttpServletResponse response
            , FilterChain filterChain) throws ServletException, IOException {
        String token;
        String username;
        String authToken = request.getHeader("Authorization");
        if(authToken==null || !authToken.startsWith("Bearer")){
            filterChain.doFilter(request,response);
            return;
        }

        token = authToken.substring(7);
        if(jwtUtility.isValidToken(token)){
            username = jwtUtility.getUsername(token);
            Users users = usersRepo.findByUsername(username).orElseThrow();
            SecurityContextHolder.getContext()
                    .setAuthentication(
                            new UsernamePasswordAuthenticationToken(
                                    users.getUsername(),
                                    null,
                                    List.of(new SimpleGrantedAuthority("ROLE_" + users.getRole()))
                            )
                    );
        }
        filterChain.doFilter(request,response);
    }
}
