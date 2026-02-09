package com.example.springsecuritypact2.configuration;

import com.example.springsecuritypact2.model.Users;
import com.example.springsecuritypact2.repository.UsersRepo;
import com.example.springsecuritypact2.utility.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Service;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Service
@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {


    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    /**
     * This filter runs on every request to extract and validate the JWT.
     * If valid, it sets up the security context so Spring Security knows
     * who the user is for this request.
     */
    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        // Extract the Authorization header
        final String authHeader = request.getHeader("Authorization");

        // If there's no header or it doesn't start with "Bearer ", skip JWT processing
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            // Extract the actual token (remove "Bearer " prefix)
            final String jwt = authHeader.substring(7);
            final String username = jwtService.extractUsername(jwt);

            // If we extracted a username and there's no authentication set yet
            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                // Load user details from database
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);

                // Validate the token against the user
                if (jwtService.isTokenValid(jwt, userDetails)) {
                    // Create authentication token and set it in the context
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                    );
                    //The WebAuthenticationDetailsSource is a helper class provided by Spring Security specifically for
                    // web applications. Its job is to extract relevant contextual information from an HTTP request
                    // and package it into a details object. When you call buildDetails(request),
                    // it's looking at the HttpServletRequest and pulling out information like the remote IP address and
                    // the session ID if one exists.
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }
        } catch (Exception e) {
            // If anything goes wrong (expired token, invalid signature, etc.),
            // we simply don't set authentication and let the request continue.
            // Spring Security will handle the unauthorized response.
            logger.error("JWT validation failed: " + e.getMessage());
        }

        // Continue with the filter chain
        filterChain.doFilter(request, response);
    }
}
