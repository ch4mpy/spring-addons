package com.c4soft.springaddons.tutorials;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.c4soft.springaddons.tutorials.ServletResourceServerWithAdditionalHeader.SecurityConfig.MyAuth;

@RestController
@PreAuthorize("isAuthenticated()")
public class GreetingController {

    @GetMapping("/greet")
    public String getGreeting(MyAuth auth) {
        return "Hi %s! You are granted with: %s.".formatted(
                auth.getIdClaims().getEmail(),
                auth.getAuthorities());
    }
}
