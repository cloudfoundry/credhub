package org.cloudfoundry.credhub.config

import org.cloudfoundry.credhub.auth.PreAuthenticationFailureFilter
import org.cloudfoundry.credhub.auth.X509AuthenticationProvider
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.ObjectPostProcessor
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.core.authority.AuthorityUtils
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider
import org.springframework.security.web.authentication.preauth.x509.X509AuthenticationFilter

@ConditionalOnProperty(value = ["security.oauth2.enabled"], havingValue = "false", matchIfMissing = true)
@Configuration
@EnableResourceServer
@EnableWebSecurity
class AuthWithoutOAuthConfiguration
    @Autowired
    internal constructor(
        private val resourceServerProperties: ResourceServerProperties,
        private val preAuthenticationFailureFilter: PreAuthenticationFailureFilter,
    ) : ResourceServerConfigurerAdapter() {
        val preAuthenticatedAuthenticationProvider: PreAuthenticatedAuthenticationProvider
            @Bean
            get() = X509AuthenticationProvider()

        @Throws(Exception::class)
        override fun configure(resources: ResourceServerSecurityConfigurer) {
            resources.resourceId(resourceServerProperties.resourceId)
            resources.stateless(false)
        }

        @Throws(Exception::class)
        override fun configure(http: HttpSecurity) {
        /*
      Even though the configuration is non order specific, it's ordered here so one can understand
      the flow of operations. Before the Authenticate Override can be called in the http filter
      the subject principal must be correctly extracted, hence why the UserDetails for that sets
      the "NO_AUTHORITIES", leaving it to the x509v3 checker to set the final authority.

      The aggregate of all this is consumed in the final .access() method.
         */

            http
                .x509()
                .subjectPrincipalRegex(VALID_MTLS_ID)
                .userDetailsService(mtlsSUserDetailsService())
                .withObjectPostProcessor(
                    object : ObjectPostProcessor<X509AuthenticationFilter> {
                        override fun <O : X509AuthenticationFilter> postProcess(filter: O): O {
                            filter.setContinueFilterChainOnUnsuccessfulAuthentication(false)
                            return filter
                        }
                    },
                )

            http
                .addFilterBefore(preAuthenticationFailureFilter, X509AuthenticationFilter::class.java)
                .authenticationProvider(preAuthenticatedAuthenticationProvider)

            http
                .authorizeRequests()
                .antMatchers("/info")
                .permitAll()
                .antMatchers("/docs/index.html")
                .permitAll()
                .antMatchers("/health")
                .permitAll()
                .antMatchers("/management")
                .permitAll()
                .antMatchers("**")
                .access(
                    String.format(
                        "hasRole('%s')",
                        X509AuthenticationProvider.MTLS_USER,
                    ),
                )

            http.httpBasic().disable()
        }

        private fun mtlsSUserDetailsService(): UserDetailsService = UserDetailsService { User(it, "", AuthorityUtils.NO_AUTHORITIES) }

        companion object {
            // Only valid for v4 UUID by design.
            private val VALID_MTLS_ID = "\\bOU=(app:[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[a-f0-9]{4}-[a-f0-9]{12})\\b"
        }
    }
