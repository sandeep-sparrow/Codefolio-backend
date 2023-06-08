package com.codefolio.backend.authentication;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class AuthenticateController {
    private final AuthenticateService authenticateService;

    public AuthenticateController(AuthenticateService authenticateService) {
        this.authenticateService = authenticateService;
    }

}
