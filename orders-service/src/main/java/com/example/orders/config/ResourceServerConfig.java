package com.example.orders.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Stateless JWT resource server. Every request must carry a valid Bearer access token; the
 * {@code orders.read} scope is required to read orders. The JWT signature and issuer are validated
 * against the authorization server's JWK set (configured via {@code issuer-uri}).
 */
@Configuration(proxyBeanMethods = false)
public class ResourceServerConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        // Health probe is open (used by Docker/compose healthchecks).
                        .requestMatchers("/actuator/health/**").permitAll()
                        // Reading orders requires the orders.read scope (mapped to SCOPE_orders.read).
                        .requestMatchers("/api/orders/**").hasAuthority("SCOPE_orders.read")
                        // Any other endpoint just needs a valid token.
                        .anyRequest().authenticated())
                // Accept a Bearer JWT and validate it (signature/expiry/issuer) via the IdP's JWK set.
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))
                // No server-side session: identity comes solely from the JWT on each request.
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        return http.build();
    }
}
