package com.example.springsecuritypact2.service;

import com.example.springsecuritypact2.dto.LoginResponseDto;
import com.example.springsecuritypact2.dto.SignInRequestDto;
import com.example.springsecuritypact2.dto.SignInResponseDto;
import com.example.springsecuritypact2.model.AuthType;
import com.example.springsecuritypact2.model.Users;
import com.example.springsecuritypact2.repository.UsersRepo;
import com.example.springsecuritypact2.utility.AuthUtil;
import com.example.springsecuritypact2.utility.JwtService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Optional;

@Component
@RequiredArgsConstructor
public class OAuthService implements AuthenticationSuccessHandler {

    private final AuthUtil authUtil;
    private final UsersRepo usersRepo;
    private final AuthService authService;
    private final JwtService jwtService;
    private final ObjectMapper objectMapper;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) authentication;
        OAuth2User oauthUser = token.getPrincipal();

        // Registration ID, states what the Auth provider is, is it Google or Facebook.
        String registrationId = token.getAuthorizedClientRegistrationId();
        LoginResponseDto loginResponseDto = handleOAuth2Login(oauthUser, registrationId);

        response.setStatus(HttpStatus.OK.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(objectMapper.writeValueAsString(loginResponseDto));

    }


    @Transactional
    public LoginResponseDto handleOAuth2Login(OAuth2User oauthUser, String registrationId){

        // 1. Fetch Provider type, and Provider Id,
        AuthType authType = authUtil.getAuthType(registrationId);

        // 2. Save the Provider Type, and Provider Id in the database.
        String providerId = authUtil.getProviderId(oauthUser, registrationId);
        String email = oauthUser.getAttribute("email");

        // 3. If the user has an account, then redirect to Login.
        Users users =
                usersRepo.findByProviderIdAndProviderType(providerId, authType)
                        .orElse(null);
        Users usersByEmail = usersRepo.findByUsername(email)
                .orElse(null);

        if(users == null && usersByEmail == null) {
            // SignUp flow:
            String username = authUtil.getEmailFromOAuthUser(oauthUser, registrationId, providerId);
            users = authService.getUser(new SignInRequestDto(email, null), authType, providerId);
        }else if(users == null){
            // check for the updates in the details of the user. from the oauth provider.
            if(email != null && !email.isBlank() && !email.equals(users.getUsername())){
                users.setUsername(email);
                usersRepo.save(users);
            }
        }else{
            // Case where the user has an account, and the user tries to login via OAuth.
            // in our case we can handle it, by throwing an Exception.
            throw new IllegalArgumentException("User already exists");
        }

        // 4. otherwise first SignUp, and then Login User.
        String accessToken = jwtService.generateAccessToken(users);
        String refreshToken = jwtService.generateRefreshToken(users);

        return new LoginResponseDto(accessToken, refreshToken);

    }
}
