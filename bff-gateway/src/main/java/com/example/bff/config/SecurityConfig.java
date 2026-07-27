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
                        // The SPA shell and static assets are public; the flow is user-initiated.
                        .pathMatchers("/", "/index.html", "/favicon.ico", "/assets/**", "/*.js", "/*.css", "/*.svg").permitAll()
                        .pathMatchers("/oauth2/**", "/login/**", "/logout").permitAll()
                        // Everything the SPA actually consumes requires an authenticated session.
                        .pathMatchers("/api/**").authenticated()
                        .anyExchange().permitAll())
                .oauth2Login(oauth2 -> oauth2
                        .authorizationRequestResolver(authorizationRequestResolver))
                .logout(logout -> logout.logoutSuccessHandler(logoutSuccessHandler))
                // Return 401 (instead of a cross-origin redirect) so the SPA can render a login button.
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint(new HttpStatusServerEntryPoint(HttpStatus.UNAUTHORIZED)))
                // Cookie-based CSRF token readable by JS so the SPA can echo it back.
                // The plain request handler expects the raw token value (the SPA reads it straight
                // from the XSRF-TOKEN cookie). The XOR/BREACH masking used by default only matters
                // when the token is reflected in an HTML response body, which never happens here.
                .csrf(csrf -> csrf
                        .csrfTokenRepository(CookieServerCsrfTokenRepository.withHttpOnlyFalse())
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
        DefaultServerOAuth2AuthorizationRequestResolver resolver =
                new DefaultServerOAuth2AuthorizationRequestResolver(clientRegistrationRepository);
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
        OidcClientInitiatedServerLogoutSuccessHandler handler =
                new OidcClientInitiatedServerLogoutSuccessHandler(clientRegistrationRepository);
        // {baseUrl} resolves to the origin the browser actually used, so logout returns the user to
        // the same host they signed in from (localhost or 127.0.0.1) instead of a hardcoded one.
        handler.setPostLogoutRedirectUri("{baseUrl}/");
        return handler;
    }

    /**
     * Ensures the CSRF token is actually materialized so its cookie is written to the response, even on
     * requests where nothing else reads the token. Required for the cookie-based SPA CSRF pattern.
     */
    @Bean
    public WebFilter csrfCookieWebFilter() {
        return (exchange, chain) -> {
            Mono<CsrfToken> csrfToken = exchange.getAttribute(CsrfToken.class.getName());
            return (csrfToken != null ? csrfToken.then() : Mono.empty()).then(chain.filter(exchange));
        };
    }
}
