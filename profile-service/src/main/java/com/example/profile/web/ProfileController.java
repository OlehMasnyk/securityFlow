package com.example.profile.web;

import java.util.Map;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ProfileController {

    @GetMapping("/api/profile")
    public Map<String, Object> profile(@AuthenticationPrincipal Jwt jwt) {
        return Map.of(
                "service", "profile-service",
                "subject", jwt.getSubject(),
                "preferredUsername", jwt.getClaimAsString("sub"),
                "roles", jwt.getClaimAsStringList("roles"),
                "issuedBy", jwt.getIssuer().toString(),
                "scopes", jwt.getClaimAsStringList("scope"));
    }
}
