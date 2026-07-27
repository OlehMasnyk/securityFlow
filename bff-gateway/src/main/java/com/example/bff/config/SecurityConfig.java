package com.example.bff.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.client.web.server.DefaultServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.oidc.web.server.logout.OidcClientInitiatedServerLogoutSuccessHandler;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;
import org.springframework.security.web.server.authentication.HttpStatusServerEntryPoint;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.security.web.server.csrf.ServerCsrfTokenRequestAttributeHandler;
import org.springframework.web.server.WebFilter;
import reactor.core.publisher.Mono;

/**
 * Security for the Backend-For-Frontend.
 * <p>
 * The BFF is a confidential OAuth2 client. It runs the Authorization Code flow with PKCE, stores the
 * resulting tokens in a server-side session (Redis), and hands the browser only an {@code HttpOnly}
 * session cookie. Downstream calls are authorized by relaying the access token (see the gateway
 * {@code TokenRelay} filter in application.yml).
 */
@Configuration(proxyBeanMethods = false)
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(
            ServerHttpSecurity http,
            ServerOAuth2AuthorizationRequestResolver authorizationRequestResolver,
            ServerLogoutSuccessHandler logoutSuccessHandler) {

        http
                .authorizeExchange(exchange -> exchange
                        // Public: the SPA shell and static assets, so the app loads for anonymous users.
                        .pathMatchers("/", "/index.html", "/favicon.ico", "/assets/**", "/*.js", "/*.css", "/*.svg").permitAll()
                        // Public: the OAuth endpoints (login must be able to start) and logout.
                        .pathMatchers("/oauth2/**", "/login/**", "/logout").permitAll()
                        // Protected: everything the SPA actually consumes requires a logged-in session.
                        .pathMatchers("/api/**").authenticated()
                        // Anything else is served without authentication.
                        .anyExchange().permitAll())
                // Turn this gateway into an OAuth2/OIDC client. The custom resolver adds PKCE (below).
                .oauth2Login(oauth2 -> oauth2
                        .authorizationRequestResolver(authorizationRequestResolver))
                // On logout, also sign the user out at the identity provider (RP-initiated logout).
                .logout(logout -> logout.logoutSuccessHandler(logoutSuccessHandler))
                // For an unauthenticated /api/** call, return 401 instead of a 302 redirect to the IdP.
                // A cross-origin redirect would break the SPA's fetch(); 401 lets it show a login button.
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint(new HttpStatusServerEntryPoint(HttpStatus.UNAUTHORIZED)))
                .csrf(csrf -> csrf
                        // Store the CSRF token in a cookie the SPA's JavaScript can read (HttpOnly=false).
                        .csrfTokenRepository(CookieServerCsrfTokenRepository.withHttpOnlyFalse())
                        // Validate the RAW token the SPA sends back. The default XOR/BREACH-masking
                        // handler expects a masked value, which a cookie-reading SPA cannot produce;
                        // masking only matters when the token is rendered into an HTML body (never here).
                        .csrfTokenRequestHandler(new ServerCsrfTokenRequestAttributeHandler()));

        return http.build();
    }

    /**
     * Enables PKCE on the outgoing authorization request. Spring Security does not add PKCE for
     * confidential clients by default; {@code withPkce()} attaches the {@code code_challenge} and keeps
     * the {@code code_verifier} server-side for the token exchange.
     */
    @Bean
    public ServerOAuth2AuthorizationRequestResolver authorizationRequestResolver(
            ReactiveClientRegistrationRepository clientRegistrationRepository) {
        // Default resolver builds the /oauth2/authorize redirect from the client registration.
        DefaultServerOAuth2AuthorizationRequestResolver resolver =
                new DefaultServerOAuth2AuthorizationRequestResolver(clientRegistrationRepository);
        // withPkce(): generate a random code_verifier, attach its S256 code_challenge to the
        // authorization request, keep the verifier server-side, and replay it at token exchange.
        resolver.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce());
        return resolver;
    }

    /**
     * RP-initiated logout: ends the local session and redirects to the provider's end-session endpoint
     * so the user is signed out at the identity provider too.
     */
    @Bean
    public ServerLogoutSuccessHandler logoutSuccessHandler(
            ReactiveClientRegistrationRepository clientRegistrationRepository) {
        // Sends the browser to the provider's end_session_endpoint (with an id_token_hint).
        OidcClientInitiatedServerLogoutSuccessHandler handler =
                new OidcClientInitiatedServerLogoutSuccessHandler(clientRegistrationRepository);
        // Where the provider returns the browser after logging out (must be a registered URI).
        handler.setPostLogoutRedirectUri("http://127.0.0.1:8080/");
        return handler;
    }

    /**
     * Ensures the CSRF token is actually materialized so its cookie is written to the response, even on
     * requests where nothing else reads the token. Required for the cookie-based SPA CSRF pattern.
     */
    @Bean
    public WebFilter csrfCookieWebFilter() {
        return (exchange, chain) -> {
            // The CsrfToken is loaded lazily; subscribing to it here forces the XSRF-TOKEN cookie to
            // be written on the response even when no other component reads the token.
            Mono<CsrfToken> csrfToken = exchange.getAttribute(CsrfToken.class.getName());
            return (csrfToken != null ? csrfToken.then() : Mono.empty()).then(chain.filter(exchange));
        };
    }
}
