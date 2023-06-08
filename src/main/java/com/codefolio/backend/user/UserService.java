package com.codefolio.backend.user;

import com.google.gson.Gson;
import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.util.WebUtils;

@Service
@AllArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final UserSessionRepository userSessionRepository;

    public ResponseEntity<?> userDetails(HttpServletRequest request){
        String sessionId = (WebUtils.getCookie(request, "SESSION_ID")).getValue();
        UserSession userSession = userSessionRepository.findBySessionId(sessionId).orElseThrow();
        Users user = userSession.getUsers();
        Gson gson = new Gson();
        return ResponseEntity.ok(gson.toJson(user));
    }
}
