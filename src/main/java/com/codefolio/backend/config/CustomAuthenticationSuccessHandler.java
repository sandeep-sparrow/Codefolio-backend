package com.codefolio.backend.config;

import com.codefolio.backend.user.UserRepository;
import com.codefolio.backend.user.UserSession;
import com.codefolio.backend.user.UserSessionRepository;
import com.codefolio.backend.user.Users;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;

import java.io.IOException;
import java.util.Date;

@Component
@AllArgsConstructor
public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final UserRepository userRepository;
    private final UserSessionRepository userSessionRepository;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        String email = ((OAuth2AuthenticationToken) authentication).getPrincipal().getAttribute("email");

        System.out.println("User authenticated with email: " + email);

        Users user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("Could not find user with email: " + email));


        String sessionId = RequestContextHolder.currentRequestAttributes().getSessionId();

        UserSession userSession = new UserSession(sessionId, user, new Date());

        userSessionRepository.save(userSession);

        System.out.println("User session saved: " + userSession.getId());

    }
}