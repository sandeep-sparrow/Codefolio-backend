package com.codefolio.backend.config;

import com.codefolio.backend.user.UserRepository;
import com.codefolio.backend.user.UserSession;
import com.codefolio.backend.user.UserSessionRepository;
import com.codefolio.backend.user.Users;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;

import java.io.IOException;
import java.util.Date;
import java.util.UUID;

@Component
@AllArgsConstructor
public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final UserRepository userRepository;
    private final UserSessionRepository userSessionRepository;
    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();


    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        String email;
        String name;
        if (authentication instanceof OAuth2AuthenticationToken) {
            email = ((OAuth2AuthenticationToken) authentication).getPrincipal().getAttribute("email");
            name = ((OAuth2AuthenticationToken) authentication).getPrincipal().getAttribute("name");
        } else if (authentication instanceof UsernamePasswordAuthenticationToken) {
            email = authentication.getName();
            name = "";
        } else {
            throw new IllegalArgumentException("Unexpected type of authentication: " + authentication);
        }

        System.out.println("User authenticated with email: " + email);
        Users user;
        if (userRepository.findByEmail(email).isPresent()){
            user = userRepository.findByEmail(email).get();
        }else if (authentication instanceof OAuth2AuthenticationToken){
            String randomPassword = UUID.randomUUID().toString();
            user = new Users(name, email, passwordEncoder.encode(randomPassword));
            userRepository.save(user);
        }
        else {
            throw new IllegalArgumentException("User not found");
        }

        String sessionId = RequestContextHolder.currentRequestAttributes().getSessionId();

        UserSession userSession = new UserSession(sessionId, user, new Date());

        userSessionRepository.save(userSession);

        Cookie cookie = new Cookie("SESSION_ID", sessionId);
        cookie.setPath("/");
        cookie.setSecure(true);
        cookie.setHttpOnly(true);
        response.addCookie(cookie);

        System.out.println("User session saved: " + userSession.getId());

        if (authentication instanceof OAuth2AuthenticationToken){
            response.sendRedirect("http://localhost:5173/dashboard");
        }
    }
}
