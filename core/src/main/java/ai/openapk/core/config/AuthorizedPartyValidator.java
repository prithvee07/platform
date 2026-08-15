package ai.openapk.core.config;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Set;

/**
 * Rejects an otherwise-valid access token unless it was issued to one of
 * {@code allowedClientIds}. Spring's default issuer-uri {@code JwtDecoder}
 * validates signature, expiry, and issuer only — it never checks WHICH
 * OAuth client a token was minted for. Any token signed by the realm's key
 * is otherwise accepted, including ones issued to a completely different
 * client in the same Keycloak realm (the built-in {@code account} /
 * {@code admin-cli} / {@code security-admin-console} clients, or any future
 * third-party client an operator registers).
 *
 * <p>Checked against {@code azp} first — Keycloak populates it on every
 * access token with the requesting client's ID regardless of protocol-mapper
 * config, so this doesn't depend on the realm having a custom audience
 * mapper set up. {@code aud} is checked as a fallback for non-Keycloak or
 * differently-configured issuers that populate audience instead.
 */
final class AuthorizedPartyValidator implements OAuth2TokenValidator<Jwt> {

    private static final OAuth2Error ERROR = new OAuth2Error(
            "invalid_token",
            "The token was not issued to a trusted client",
            null
    );

    private final Set<String> allowedClientIds;

    AuthorizedPartyValidator(Set<String> allowedClientIds) {
        this.allowedClientIds = allowedClientIds;
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt token) {
        String azp = token.getClaimAsString("azp");
        if (azp != null && allowedClientIds.contains(azp)) {
            return OAuth2TokenValidatorResult.success();
        }
        var aud = token.getAudience();
        if (aud != null && aud.stream().anyMatch(allowedClientIds::contains)) {
            return OAuth2TokenValidatorResult.success();
        }
        return OAuth2TokenValidatorResult.failure(ERROR);
    }
}
