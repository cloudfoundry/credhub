package org.cloudfoundry.credhub.config

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Profile
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.config.annotation.ObjectPostProcessor
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.oauth2.provider.error.DefaultWebResponseExceptionTranslator
import org.springframework.security.oauth2.provider.error.WebResponseExceptionTranslator
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter
import org.springframework.security.oauth2.provider.token.DefaultTokenServices
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter
import org.springframework.security.oauth2.provider.token.store.jwk.JwkTokenStore

@Configuration
@Profile("prod", "dev")
@ConditionalOnProperty("security.oauth2.enabled")
class OAuth2Configuration {

    @Bean
    fun resourceServerProperties(): ResourceServerProperties {
        return ResourceServerProperties()
    }

    @Bean
    @Throws(Exception::class)
    fun jwtAccessTokenConverter(): JwtAccessTokenConverter {
        val defaultAccessTokenConverter = DefaultAccessTokenConverter()
        defaultAccessTokenConverter.setIncludeGrantType(true)
        val jwtAccessTokenConverter = JwtAccessTokenConverter()
        jwtAccessTokenConverter.accessTokenConverter = defaultAccessTokenConverter
        jwtAccessTokenConverter.afterPropertiesSet()
        return jwtAccessTokenConverter
    }

    @Bean
    @Throws(Exception::class)
    fun jwkTokenStore(oAuthProperties: OAuthProperties): JwkTokenStore {
        return JwkTokenStore(oAuthProperties.jwkKeysPath, jwtAccessTokenConverter())
    }

    @Bean
    fun resourceServerTokenServices(tokenStore: JwkTokenStore): ResourceServerTokenServices {
        val defaultTokenServices = DefaultTokenServices()
        defaultTokenServices.setTokenStore(tokenStore)
        return defaultTokenServices
    }

    @Bean
    fun authenticationManagerBuilder(): AuthenticationManagerBuilder {
        val objectPostProcessor = object : ObjectPostProcessor<Any> {
            override fun <O : Any> postProcess(`object`: O): O {
                return `object`
            }
        }
        val authenticationManagerBuilder = AuthenticationManagerBuilder(objectPostProcessor)
        authenticationManagerBuilder.parentAuthenticationManager(authenticationManager())
        return authenticationManagerBuilder
    }

    @Bean
    fun authenticationManager(): AuthenticationManager {
        return AuthenticationManager { it }
    }

    @Bean
    fun webResponseExceptionTranslator(): WebResponseExceptionTranslator<*> {
        return DefaultWebResponseExceptionTranslator()
    }
}
