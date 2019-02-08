package org.cloudfoundry.credhub.config

import org.springframework.context.MessageSource
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.support.MessageSourceAccessor

@Configuration
class DefaultExceptionHandlerConfig {
    @Bean
    fun messageSourceAccessor(messageSource: MessageSource): MessageSourceAccessor {
        return MessageSourceAccessor(messageSource)
    }
}
