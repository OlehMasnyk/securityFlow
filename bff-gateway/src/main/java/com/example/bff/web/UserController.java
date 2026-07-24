package com.example.bff.web;

import java.util.Map;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;

/**
 * Exposes the authenticated user's identity to the SPA. The browser learns who is logged in without
 * ever seeing the underlying tokens - only claims that the BFF chooses to reveal.
 */
@RestController
public class UserController {

    @GetMapping("/api/me")
    public Mono<Map<String, Object>> me(@AuthenticationPrincipal OidcUser oidcUser) {
        return Mono.just(Map.of(
                "name", oidcUser.getName(),
                "subject", oidcUser.getSubject(),
                "claims", oidcUser.getClaims(),
                "authorities", oidcUser.getAuthorities().stream()
                        .map(authority -> authority.getAuthority())
                        .toList()));
    }
}
