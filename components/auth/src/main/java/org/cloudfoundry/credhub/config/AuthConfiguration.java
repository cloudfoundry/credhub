package org.cloudfoundry.credhub.config;

import java.security.interfaces.RSAPublicKey;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationManagers;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.authentication.preauth.x509.X509AuthenticationFilter;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.cloudfoundry.credhub.auth.ActuatorPortFilter;
import org.cloudfoundry.credhub.auth.PreAuthenticationFailureFilter;
import org.cloudfoundry.credhub.auth.X509AuthenticationProvider;

import static org.springframework.security.config.Customizer.withDefaults;

@ConditionalOnProperty("security.oauth2.enabled")
@Configuration
@EnableWebSecurity
public class AuthConfiguration {
    private static final String VALID_MTLS_ID = "\\bOU=(app:[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[a-f0-9]{4}-[a-f0-9]{12})\\b";
    private static final Logger LOGGER = LogManager.getLogger(AuthConfiguration.class.getName());

    @Value("${security.oauth2.resource.jwt.key_value}")
    RSAPublicKey publicKey;

    @Autowired
    OAuthProperties oAuthProperties;

    @Autowired
    ActuatorPortFilter actuatorPortFilter;

    @Autowired
    PreAuthenticationFailureFilter preAuthenticationFailureFilter;

    @Autowired
    OAuth2ExtraValidationFilter oAuth2ExtraValidationFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
         LOGGER.info("in securityFilterChain config");

        http
                .x509()
                .subjectPrincipalRegex(VALID_MTLS_ID)
                .userDetailsService(mtlsSUserDetailsService())
                .withObjectPostProcessor(
                        new ObjectPostProcessor<X509AuthenticationFilter>() {
                            @Override
                            public <O extends X509AuthenticationFilter> O postProcess(O filter) {
                                filter.setContinueFilterChainOnUnsuccessfulAuthentication(false);
                                return filter;
                            }
                        }
                );

        http
                .addFilterBefore(actuatorPortFilter, X509AuthenticationFilter.class)
                .addFilterAfter(preAuthenticationFailureFilter, ActuatorPortFilter.class)
                .addFilterAfter(oAuth2ExtraValidationFilter, PreAuthenticationFailureFilter.class)
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
                .oauth2ResourceServer((oauth2) -> oauth2.jwt(withDefaults()))
                .httpBasic().disable()
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        return http.build();
    }

    @Bean
    JwtDecoder jwtDecoder() throws Exception {
        LOGGER.info("in jwtDecoder");
        return NimbusJwtDecoder.withPublicKey(publicKey).build();

// TODO: The code we want to use for UAA providing the public key
//        String jwkKeysPath = "/token_keys";
//        try {
//            jwkKeysPath = oAuthProperties.getJwkKeysPath();
//        } catch (URISyntaxException ex) {
//            LOGGER.warn("Using default jwkKeysPath: {}", jwkKeysPath);
//        }
//
//        return NimbusJwtDecoder.withJwkSetUri(jwkKeysPath).build();
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
