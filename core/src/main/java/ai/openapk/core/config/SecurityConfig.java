package ai.openapk.core.config;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import jakarta.servlet.DispatcherType;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;
import java.util.Set;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@EnableConfigurationProperties(OpenApkProperties.class)
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            @Qualifier("corsConfigurationSource") CorsConfigurationSource cors
    ) throws Exception {
        return http
                .cors(c -> c.configurationSource(cors))
                .csrf(csrf -> csrf.disable())
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .dispatcherTypeMatchers(DispatcherType.ERROR, DispatcherType.ASYNC).permitAll()
                        .requestMatchers("/actuator/health/**", "/actuator/info").permitAll()
                        // /community/** is the anonymous-read public feed
                        // (list + single-report read). Abuse-report POST is
                        // also anonymous so signed-out readers can flag. All
                        // mutating community ops (publish/unpublish) live
                        // under /api/projects/{id}/report/community/** which
                        // is still authenticated.
                        .requestMatchers("/api/community/**").permitAll()
                        // The public-project CODE view (decompiled functions)
                        // requires an account: anonymous visitors get the
                        // report + highlights teaser, signing in unlocks the
                        // code. MUST be declared before the /api/public/**
                        // permitAll below — first match wins.
                        .requestMatchers("/api/public/projects/*/binary-analysis").authenticated()
                        // /api/public/** is the anonymous read surface for
                        // projects the owner flagged public_read_at (metadata,
                        // highlights, report, media). Gated per-request by
                        // ProjectPublicGuard, which 404s private/missing
                        // projects identically (no existence leak). Only READ
                        // endpoints live under it — every write/LLM path stays
                        // under the authenticated /api/projects/**.
                        .requestMatchers("/api/public/**").permitAll()
                        // /api/tos.md is the markdown body the acceptance
                        // modal renders. Must be readable BEFORE the user
                        // has signed in (the gate blocks all other /api/**)
                        // and BEFORE acceptance.
                        .requestMatchers("/api/tos.md").permitAll()
                        .requestMatchers("/api/**").authenticated()
                        .anyRequest().denyAll()
                )
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()))
                .build();
    }

    /**
     * Overrides Spring Boot's auto-configured issuer-uri decoder to also
     * check the token's authorized party — see {@link AuthorizedPartyValidator}
     * for why that matters. {@code NimbusJwtDecoder.withIssuerLocation}
     * performs the same OIDC-discovery lookup Boot's auto-config would have
     * done; defining this bean just lets us layer the extra validator on top
     * (the documented Spring Security pattern for custom claim validation).
     */
    @Bean
    JwtDecoder jwtDecoder(
            @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}") String issuerUri,
            OpenApkProperties props
    ) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withIssuerLocation(issuerUri).build();
        OAuth2TokenValidator<Jwt> withIssuer = JwtValidators.createDefaultWithIssuer(issuerUri);
        OAuth2TokenValidator<Jwt> withAzp = new AuthorizedPartyValidator(Set.copyOf(props.oauth2().allowedClientIds()));
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(withIssuer, withAzp));
        return decoder;
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource(OpenApkProperties props) {
        var cfg = new CorsConfiguration();
        cfg.setAllowedOrigins(props.cors().allowedOrigins());
        cfg.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
        cfg.setAllowedHeaders(List.of("*"));
        cfg.setExposedHeaders(List.of("Location"));
        cfg.setAllowCredentials(true);
        var src = new UrlBasedCorsConfigurationSource();
        src.registerCorsConfiguration("/**", cfg);
        return src;
    }
}
