package com.sopromadze.blogapi.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
public class HomeController {

    @GetMapping("/")
    public ResponseEntity<?> home() {
        Map<String, Object> response = new HashMap<>();
        response.put("status", "running");
        response.put("service", "Spring Boot Blog REST API");
        response.put("version", "1.0.0");
        response.put("timestamp", System.currentTimeMillis());
        response.put("endpoints", new HashMap<String, String>() {{
            put("api_docs", "/swagger-ui.html");
            put("health", "/actuator/health");
            put("posts", "/api/posts");
            put("albums", "/api/albums");
            put("auth_signup", "POST /api/auth/signup");
            put("auth_signin", "POST /api/auth/signin");
        }});
        return ResponseEntity.ok(response);
    }
}