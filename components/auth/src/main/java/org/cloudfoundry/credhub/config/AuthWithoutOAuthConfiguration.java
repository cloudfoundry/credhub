package org.cloudfoundry.credhub.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.authentication.preauth.x509.X509AuthenticationFilter;
import org.springframework.web.filter.UrlHandlerFilter;

import org.cloudfoundry.credhub.auth.PreAuthenticationFailureFilter;
import org.cloudfoundry.credhub.auth.X509AuthenticationProvider;

@ConditionalOnProperty(value = "security.oauth2.enabled", havingValue = "false", matchIfMissing = true)
@Configuration
@EnableWebSecurity
public class AuthWithoutOAuthConfiguration {
    private static final String VALID_MTLS_ID = "\\bOU=(app:[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[a-f0-9]{4}-[a-f0-9]{12})\\b";

    @Autowired
    PreAuthenticationFailureFilter preAuthenticationFailureFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http.x509(configurer -> {
            configurer
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
        });

        http
                .addFilterBefore(preAuthenticationFailureFilter, X509AuthenticationFilter.class)
                .addFilterBefore(
                        UrlHandlerFilter.trailingSlashHandler("/**").wrapRequest().build(),
                        PreAuthenticationFailureFilter.class)
                .authenticationProvider(preAuthenticatedAuthenticationProvider());

        http
                .authorizeHttpRequests((authorize) -> authorize
                        .requestMatchers("/info").permitAll()
                        .requestMatchers("/docs/index.html").permitAll()
                        .requestMatchers("/health").permitAll()
                        .requestMatchers("/management").permitAll()
                        .requestMatchers("/**").access(AuthorityAuthorizationManager
                                .hasRole(X509AuthenticationProvider.Companion.getMTLS_USER()))
                )
                .httpBasic(configurer -> {
                    configurer.disable();
                })
                .csrf(configurer -> {
                    configurer.disable();
                })
                .sessionManagement(configurer -> {
                    configurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
                });

        return http.build();
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
