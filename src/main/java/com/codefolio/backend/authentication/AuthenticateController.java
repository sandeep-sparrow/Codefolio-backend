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
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.RequestContextHolder;
import java.util.Date;
import java.util.Optional;

@RestController
@AllArgsConstructor
public class AuthenticateController {

    private AuthenticationManager authenticationManager;
    private UserSessionRepository userSessionRepository;
    private UserRepository userRepository;
    private final PasswordEncoder passwordEncoder = new BCryptPasswordEncoder();


    @PostMapping("/login")
    public ResponseEntity<?> authenticate(@RequestBody LoginRequest loginRequest, HttpServletResponse response) {

        Optional<Users> user = userRepository.findByEmail(loginRequest.username());
        System.out.println(user);
        if(user.isPresent() && passwordEncoder.matches(loginRequest.password(), user.get().getPassword())) {
            System.out.println("HI email!");
                Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.username(), loginRequest.password()));
                SecurityContextHolder.getContext().setAuthentication(authentication);
                String sessionId = RequestContextHolder.currentRequestAttributes().getSessionId();
            System.out.println(sessionId);
                Cookie cookie = new Cookie("SESSION_ID", sessionId);
                cookie.setPath("/");
                cookie.setSecure(true);
                cookie.setHttpOnly(true);
                response.addCookie(cookie);

                UserSession userSession = new UserSession(sessionId, user.get(), new Date());
                userSessionRepository.save(userSession);
            System.out.println(userSession);
                System.out.println("User session saved: " + userSession.getId());

                return ResponseEntity.ok("Logged in successfully");
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
        }
    }

}
