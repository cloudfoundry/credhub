package org.cloudfoundry.credhub.config;

import java.net.URISyntaxException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Objects;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationManagers;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.authentication.preauth.x509.X509AuthenticationFilter;

import org.cloudfoundry.credhub.auth.ActuatorPortFilter;
import org.cloudfoundry.credhub.auth.CredHubJwtTimeValidator;
import org.cloudfoundry.credhub.auth.OAuth2AuthenticationExceptionHandler;
import org.cloudfoundry.credhub.auth.OAuth2IssuerService;
import org.cloudfoundry.credhub.auth.PreAuthenticationFailureFilter;
import org.cloudfoundry.credhub.auth.X509AuthenticationProvider;

import static org.springframework.security.config.Customizer.withDefaults;

@ConditionalOnProperty("security.oauth2.enabled")
@Configuration
@EnableWebSecurity
public class AuthConfiguration {
    private static final String VALID_MTLS_ID = "\\bOU=(app:[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[a-f0-9]{4}-[a-f0-9]{12})\\b";
    private final OAuthProperties oAuthProperties;
    private final ActuatorPortFilter actuatorPortFilter;
    private final PreAuthenticationFailureFilter preAuthenticationFailureFilter;

    public AuthConfiguration(OAuthProperties oauthProperties, ActuatorPortFilter actuatorPortFilter, PreAuthenticationFailureFilter preAuthenticationFailureFilter) {
        this.oAuthProperties = oauthProperties;
        this.actuatorPortFilter = actuatorPortFilter;
        this.preAuthenticationFailureFilter = preAuthenticationFailureFilter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .x509(x509 -> x509
                        .subjectPrincipalRegex(VALID_MTLS_ID)
                        .userDetailsService(mtlsSUserDetailsService())
                        .withObjectPostProcessor(
                                new org.springframework.security.config.ObjectPostProcessor<X509AuthenticationFilter>() {
                            @Override
                            public <O extends X509AuthenticationFilter> O postProcess(O filter) {
                                filter.setContinueFilterChainOnUnsuccessfulAuthentication(false);
                                return filter;
                            }
                        })
                );

        http
                .addFilterBefore(actuatorPortFilter, X509AuthenticationFilter.class)
                .addFilterAfter(preAuthenticationFailureFilter, ActuatorPortFilter.class)
                .authenticationProvider(preAuthenticatedAuthenticationProvider());

        http
                .authorizeHttpRequests((authorize) -> authorize
                        .requestMatchers("/info").permitAll()
                        .requestMatchers("/docs/index.html").permitAll()
                        .requestMatchers("/health").permitAll()
                        .requestMatchers("/management").permitAll()
                        .requestMatchers("/**").access(
                                AuthorizationManagers.anyOf(
                                        AuthorityAuthorizationManager.hasRole(X509AuthenticationProvider.Companion.getMTLS_USER()),
                                        AuthorizationManagers.allOf(
                                                AuthorityAuthorizationManager.hasAuthority("SCOPE_credhub.read"),
                                                AuthorityAuthorizationManager.hasAuthority("SCOPE_credhub.write"))
                                        )
                                )
                )
                .oauth2ResourceServer(
                        (oauth2) ->
                                oauth2.authenticationEntryPoint(
                                        new OAuth2AuthenticationExceptionHandler())
                                        .jwt(withDefaults()))
                .httpBasic(AbstractHttpConfigurer::disable)
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }

    @Bean
    public NimbusJwtDecoder jwtDecoder(
            @Value("${security.oauth2.resource.jwt.key_value:#{null}}") String keyStr,
            @Autowired OAuth2IssuerService oAuth2IssuerService
    ) throws URISyntaxException, InvalidKeySpecException, NoSuchAlgorithmException {

        NimbusJwtDecoder jwtDecoder;

        // 'jwt.key_value' property, which was part of old oauth2 lib is not
        // part of new lib. The property was primarily used for unit test.
        // To keep things compatible with older credhub versions, use the
        // property if it exists. If not, use the jwkKeysPath.
        if (keyStr == null) {
            jwtDecoder = NimbusJwtDecoder
                    .withJwkSetUri(oAuthProperties.getJwkKeysPath())
                    .build();
        } else {
            jwtDecoder = NimbusJwtDecoder
                    .withPublicKey(strToRsaPublicKey(keyStr))
                    .build();
        }

        jwtDecoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                new CredHubJwtTimeValidator(),
                new JwtIssuerValidator(Objects.requireNonNull(
                        oAuth2IssuerService.getIssuer()))));

        return jwtDecoder;
    }

    private RSAPublicKey strToRsaPublicKey(String keyStr)
            throws InvalidKeySpecException, NoSuchAlgorithmException {
        String kyStrToDecode = keyStr
                .replaceAll("\n", "")
                .replaceFirst("-----BEGIN PUBLIC KEY-----", "")
                .replaceFirst("-----END PUBLIC KEY-----", "");
        byte[] data = Base64.getDecoder().decode((kyStrToDecode));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(data);
        KeyFactory factory = KeyFactory.getInstance("RSA");
        return (RSAPublicKey) factory.generatePublic(spec);
    }

    private UserDetailsService mtlsSUserDetailsService() {
        return new UserDetailsService() {
            @Override
            public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
                return new User(username, "", AuthorityUtils.NO_AUTHORITIES);
            }
        };
    }

    private PreAuthenticatedAuthenticationProvider preAuthenticatedAuthenticationProvider() {
        return new X509AuthenticationProvider();
    }
}
