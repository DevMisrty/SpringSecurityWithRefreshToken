package com.example.springsecuritypact2.configuration;

import com.example.springsecuritypact2.service.OAuthService;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


@Slf4j
@Configuration
@AllArgsConstructor
public class SecurityConfiguartion {

    private final JwtFilter jwtFilter;
    private final OAuthService oAuthService;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
        return http.csrf(csrf->csrf.disable())
                .authorizeHttpRequests(auth->
                    auth.requestMatchers("/adminPage").hasRole("admin")
                        .requestMatchers("/page1").hasRole("user")
                        .requestMatchers("/home","/users","/admins","/loginpage","/signin").permitAll()
                            .anyRequest().authenticated()
                )
                .httpBasic(auth->{})
                .oauth2Login(auth->auth.failureHandler((request,response,exception)->{
                    log.error("OAuth2 login failed",exception);
                    response.sendRedirect("/loginpage");
                }).successHandler(oAuthService::onAuthenticationSuccess))
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class)
                .build();
    }

//    @Bean
//    public UserDetailsService userDetailsService(){
//        UserDetails user = User.withUsername("user").password(passwordEncoder().encode("root")).roles("user").build();
//        UserDetails admin = User.withUsername("admin").password(passwordEncoder().encode("root")).roles("admin").build();
//        return new InMemoryUserDetailsManager(user,admin);
//    }
}
