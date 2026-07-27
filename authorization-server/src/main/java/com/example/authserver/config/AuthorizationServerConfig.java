package com.example.authserver.config;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.UUID;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

/**
 * Configures the OAuth 2.1 / OpenID Connect Provider endpoints (authorize, token, jwks, userinfo,
 * discovery). This is where the server side of the Authorization Code + PKCE flow lives.
 */
@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {

    /**
     * The public issuer identifier. Must be reachable under the same URL by both the browser (for the
     * authorize redirect) and the backend services (for token exchange and JWKS). Defaults to
     * 127.0.0.1 for local runs; Docker overrides it to the shared {@code idp} hostname.
     */
    @Value("${app.issuer-uri:http://127.0.0.1:9000}")
    private String issuerUri;

    /**
     * Security filter chain dedicated to the protocol endpoints. It only matches the well-known
     * authorization-server endpoints and enables OpenID Connect. Unauthenticated HTML requests are
     * redirected to the login page so the user can authenticate before the authorization code is issued.
     */
    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                OAuth2AuthorizationServerConfigurer.authorizationServer();

        http
                // Restrict this filter chain to the protocol endpoints only (/oauth2/authorize,
                // /oauth2/token, /oauth2/jwks, /.well-known/**, /userinfo, /connect/logout, ...).
                // Everything else falls through to DefaultSecurityConfig (the login UI).
                .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                // Apply the authorization server configurer and enable the OpenID Connect layer
                // (ID tokens, UserInfo endpoint, discovery document).
                .with(authorizationServerConfigurer, authorizationServer ->
                        authorizationServer.oidc(Customizer.withDefaults()))
                // Every protocol endpoint requires an authenticated user session.
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                .exceptionHandling(exceptions -> exceptions
                        // If an unauthenticated browser requests an endpoint (e.g. /oauth2/authorize),
                        // redirect it to the login page instead of returning 401. Matched only for
                        // HTML requests so API/token calls still get a proper error response.
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)));

        return http.build();
    }

    /**
     * Registers the confidential BFF client.
     * <p>
     * PKCE is mandated via {@code requireProofKey(true)}. RFC 9700 (OAuth 2.0 Security BCP) recommends
     * PKCE even for confidential clients to defend against authorization code injection, since the
     * browser participates in the front-channel redirect.
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient bffClient = RegisteredClient.withId(UUID.randomUUID().toString())
                // Public identifier the client uses in the authorize/token requests.
                .clientId("bff-client")
                // Client secret. The {noop} prefix means "stored in plain text" and requires the
                // delegating PasswordEncoder (see DefaultSecurityConfig) to be matched.
                .clientSecret("{noop}bff-secret")
                // The client authenticates to the token endpoint with HTTP Basic (client_id:secret).
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                // Allowed grants: the interactive login flow ...
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                // ... and silent renewal via refresh token.
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                // Allow-list of URIs the authorization code may be returned to. Anything not listed
                // here is rejected (anti open-redirect / anti-CSRF control).
                // 8080 = gateway origin (also used by the nginx SPA in Docker).
                // 5173 = Vite dev server origin for local frontend development.
                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/idp")
                .redirectUri("http://127.0.0.1:5173/login/oauth2/code/idp")
                // Allow-list of URIs the user may be sent back to after RP-initiated logout.
                .postLogoutRedirectUri("http://127.0.0.1:8080/")
                .postLogoutRedirectUri("http://127.0.0.1:5173/")
                // Scopes this client may request. openid+profile are OIDC; the others gate the
                // two resource servers (mapped to SCOPE_* authorities in the access token).
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope("orders.read")
                .scope("profile.read")
                .clientSettings(ClientSettings.builder()
                        // Reject any authorization request without a PKCE code_challenge.
                        .requireProofKey(true)
                        // Skip the "do you allow this app?" consent screen (trusted first-party client).
                        .requireAuthorizationConsent(false)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        // Short-lived access token limits the damage of a leaked token.
                        .accessTokenTimeToLive(Duration.ofMinutes(15))
                        // Refresh token lifetime (how long silent renewal keeps working).
                        .refreshTokenTimeToLive(Duration.ofHours(8))
                        // Rotate the refresh token on each use and invalidate the previous one.
                        .reuseRefreshTokens(false)
                        .build())
                .build();

        // In-memory store: fine for a demo, lost on restart, not shared across instances.
        // Production would use a persistent RegisteredClientRepository (e.g. JDBC).
        return new InMemoryRegisteredClientRepository(bffClient);
    }

    /**
     * Adds the user's granted authorities as a {@code roles} claim so resource servers can perform
     * role-based checks in addition to scope-based checks.
     */
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return context -> {
            if (context.getPrincipal() != null && context.getPrincipal().getAuthorities() != null) {
                // Collect the authenticated user's authorities (e.g. ROLE_USER, ROLE_ADMIN) ...
                var roles = context.getPrincipal().getAuthorities().stream()
                        .map(authority -> authority.getAuthority())
                        .toList();
                // ... and write them into a custom "roles" claim on the issued token.
                context.getClaims().claim("roles", roles);
            }
        };
    }

    /**
     * The signing key material. The RSA private key signs issued JWTs; the public key is published
     * at /oauth2/jwks so clients and resource servers can verify signatures.
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        // Generate a fresh RSA keypair at startup (demo only - see the hardening note in the class).
        RSAKey rsaKey = generateRsaKey();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    /**
     * Decoder the authorization server uses internally to read the ID tokens it issues (validated
     * against the same JWK set).
     */
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        // The issuer identifier baked into every token (iss claim) and the discovery document.
        // Must match what resource servers and the BFF use to reach this provider (see the
        // issuer-consistency note on the issuerUri field).
        return AuthorizationServerSettings.builder()
                .issuer(issuerUri)
                .build();
    }

    private static RSAKey generateRsaKey() {
        KeyPair keyPair = generateRsaKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
    }

    private static KeyPair generateRsaKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException("Unable to generate RSA key pair", ex);
        }
    }
}
