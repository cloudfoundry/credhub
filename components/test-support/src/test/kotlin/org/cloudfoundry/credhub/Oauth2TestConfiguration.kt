package org.cloudfoundry.credhub

import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Profile
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.config.annotation.ObjectPostProcessor
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter
import org.springframework.security.oauth2.provider.token.DefaultTokenServices
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices
import org.springframework.security.oauth2.provider.token.TokenStore
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore

@Configuration
@Profile("unit-test")
class Oauth2TestConfiguration {
    @Bean
    fun resourceServerProperties(): ResourceServerProperties = ResourceServerProperties()

    @Bean
    @Throws(Exception::class)
    fun jwtAccessTokenConverter(): JwtAccessTokenConverter =
        JwtAccessTokenConverter()
            .apply {
                accessTokenConverter =
                    DefaultAccessTokenConverter()
                        .apply { setIncludeGrantType(true) }
                setVerifierKey(resourceServerProperties().jwt.keyValue)
                afterPropertiesSet()
            }

    @Bean
    fun tokenStore(jwtAccessTokenConverter: JwtAccessTokenConverter): TokenStore = JwtTokenStore(jwtAccessTokenConverter)

    @Bean
    fun resourceServerTokenServices(tokenStore: TokenStore): ResourceServerTokenServices =
        DefaultTokenServices().apply { setTokenStore(tokenStore) }

    @Bean
    fun authenticationManagerBuilder(): AuthenticationManagerBuilder {
        val objectPostProcessor =
            object : ObjectPostProcessor<Any> {
                override fun <O : Any> postProcess(dataObject: O): O = dataObject
            }
        return AuthenticationManagerBuilder(objectPostProcessor)
            .parentAuthenticationManager(authenticationManager())
    }

    @Bean
    fun authenticationManager(): AuthenticationManager = AuthenticationManager { authentication -> authentication }
}
