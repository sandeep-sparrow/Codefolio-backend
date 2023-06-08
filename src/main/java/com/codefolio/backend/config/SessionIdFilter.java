package com.codefolio.backend.config;

import com.codefolio.backend.user.UserSession;
import com.codefolio.backend.user.UserSessionRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.WebUtils;

import java.io.IOException;
import java.util.ArrayList;

public class SessionIdFilter extends OncePerRequestFilter {

    private final UserSessionRepository userSessionRepository;

    public SessionIdFilter(UserSessionRepository userSessionRepository) {
        this.userSessionRepository = userSessionRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String cookie = (WebUtils.getCookie(request, "SESSION_ID")).getValue();
        if (cookie != null) {

            if (userSessionRepository.findBySessionId(cookie).isPresent()) {
                System.out.println("HI!");
                UserSession userSession = userSessionRepository.findBySessionId(cookie).get();
                Authentication authentication = new UsernamePasswordAuthenticationToken(userSession.getUsers(), null, new ArrayList<>());
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }

        filterChain.doFilter(request, response);
    }
}