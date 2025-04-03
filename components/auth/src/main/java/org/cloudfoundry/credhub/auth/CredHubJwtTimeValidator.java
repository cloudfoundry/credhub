package org.cloudfoundry.credhub.auth;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.Assert;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Custom implementation of
 * {@link org.springframework.security.oauth2.jwt.JwtTimestampValidator}
 * to override OAuth2Error creation for expired access token
 */
public class CredHubJwtTimeValidator implements OAuth2TokenValidator<Jwt> {
    public static final String ACCESS_TOKEN_EXPIRED = "access_token_expired";
    private final Log logger = LogFactory.getLog(getClass());
    private static final Duration DEFAULT_MAX_CLOCK_SKEW = Duration.of(
            60, ChronoUnit.SECONDS);
    private final Duration clockSkew;
    private Clock clock = Clock.systemUTC();

    public CredHubJwtTimeValidator() {
        this.clockSkew = DEFAULT_MAX_CLOCK_SKEW;
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        Assert.notNull(jwt, "jwt cannot be null");
        Instant expiry = jwt.getExpiresAt();
        if (expiry != null) {
            if (Instant.now(this.clock).minus(this.clockSkew).isAfter(expiry)) {
                OAuth2Error oAuth2Error = createOAuth2Error(
                        ACCESS_TOKEN_EXPIRED, "Access token expired");
                throw new OAuth2AuthenticationException(oAuth2Error);
            }
        }
        Instant notBefore = jwt.getNotBefore();
        if (notBefore != null) {
            if (Instant.now(this.clock).plus(this.clockSkew)
                    .isBefore(notBefore)) {
                OAuth2Error oAuth2Error = createOAuth2Error(
                        OAuth2ErrorCodes.INVALID_TOKEN,
                        String.format("Jwt used before %s",
                                jwt.getNotBefore()));
                return OAuth2TokenValidatorResult.failure(oAuth2Error);
            }
        }
        return OAuth2TokenValidatorResult.success();
    }

    private OAuth2Error createOAuth2Error(String code, String reason) {
        this.logger.debug(reason);
        return new OAuth2Error(code, reason, null);
    }
}
