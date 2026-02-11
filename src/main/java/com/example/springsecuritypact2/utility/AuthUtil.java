package com.example.springsecuritypact2.utility;

import com.example.springsecuritypact2.model.AuthType;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class AuthUtil {

    public AuthType getAuthType(String registrationId){
        return switch(registrationId.toLowerCase()){
            case "google" -> AuthType.GOOGLE;
            case "facebook" -> AuthType.FACEBOOK;
            case "github" -> AuthType.GITHUB;
            case "twitter" -> AuthType.TWITTER;
            default -> AuthType.LOCAL;
        };
    }

    public String getProviderId(OAuth2User oAuth2User, String registrationId){
        String providerId = switch(registrationId.toString()){
            case "google" -> oAuth2User.getAttribute("sub");
            case "github" -> oAuth2User.getAttribute("id").toString();
            default -> {
                log.error("Invalid Auth Type");
                throw new IllegalArgumentException("Invalid Auth Type");
            }
        };

        if(providerId == null || providerId.isBlank()){
            log.error("Provider Id is null or blank");
            throw new IllegalArgumentException("Provider Id is null or blank");
        }

        return providerId;
    }

    public String getEmailFromOAuthUser(OAuth2User oAuth2User, String registrationId, String providerId){
        String email = oAuth2User.getAttribute("email");
        if(email!= null && !email.isBlank()){
            return email;
        }

        return switch(registrationId.toLowerCase()){
            case "google" -> oAuth2User.getAttribute("sub");
            case "github" -> oAuth2User.getAttribute("login");
            default -> providerId;
        };

    }
}
