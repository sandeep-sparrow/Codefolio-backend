package com.codefolio.backend.authentication;
import com.codefolio.backend.user.UserRepository;
import com.codefolio.backend.user.UserSession;
import com.codefolio.backend.user.UserSessionRepository;
import com.codefolio.backend.user.Users;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.RequestContextHolder;

import java.util.ArrayList;
import java.util.Date;
import java.util.Optional;

@RestController
@AllArgsConstructor
public class AuthenticateController {

    private UserSessionRepository userSessionRepository;
    private UserRepository userRepository;

    @PostMapping("/login")
    public ResponseEntity<?> authenticate(@RequestBody LoginRequest loginRequest, HttpServletResponse response) {

        Optional<Users> user;
        if (loginRequest.username() != null && loginRequest.password() != null) {
            user = userRepository.findByEmail(loginRequest.username());
            Authentication authentication;
            if (user.isPresent()) {
                if (user.get().getPassword().equals(loginRequest.password())) {
                    authentication = new UsernamePasswordAuthenticationToken(loginRequest.username(), loginRequest.password(), new ArrayList<>());
                    String sessionId = RequestContextHolder.currentRequestAttributes().getSessionId();

                    UserSession userSession = new UserSession(sessionId, user.get(), new Date());

                    userSessionRepository.save(userSession);
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                    Cookie cookie = new Cookie("SESSION_ID", sessionId);
                    cookie.setPath("/");
                    cookie.setSecure(true);
                    cookie.setHttpOnly(true);
                    response.addCookie(cookie);

                    System.out.println("User session saved: " + userSession.getId());
                } else {
                    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
                }
            }
        }

        return ResponseEntity.ok("Logged in successfully");
    }

}
