package com.example.authserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Handles end-user authentication (the login page). This is separate from the protocol endpoints so
 * the authorization server can prompt the user before issuing an authorization code.
 */
@Configuration(proxyBeanMethods = false)
public class DefaultSecurityConfig {

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        // Public: the login page itself, its styling, favicon, and the health probe.
                        .requestMatchers("/login", "/css/**", "/favicon.ico", "/actuator/health/**").permitAll()
                        // Everything else needs the user to be logged in.
                        .anyRequest().authenticated())
                // Render our custom login page at /login and process the username/password POST there.
                .formLogin(form -> form.loginPage("/login").permitAll());
        return http.build();
    }

    /**
     * Demo users. In a real system this would be backed by a persistent user store and stronger
     * credential policies (MFA, password rotation, lockout, etc.).
     */
    @Bean
    public UserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
        // A regular user with a single role. The password is encoded (stored as {bcrypt}...).
        UserDetails alice = User.withUsername("alice")
                .password(passwordEncoder.encode("password"))
                .roles("USER")
                .build();
        // An admin user with two roles, to show role-based differences downstream.
        UserDetails admin = User.withUsername("admin")
                .password(passwordEncoder.encode("password"))
                .roles("USER", "ADMIN")
                .build();
        // In-memory store: swap for a JDBC/LDAP-backed store in production.
        return new InMemoryUserDetailsManager(alice, admin);
    }

    /**
     * Delegating encoder so stored secrets carry a {id} prefix (e.g. {bcrypt}, {noop}). This lets the
     * authorization server match both user passwords and the client secret consistently.
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}
