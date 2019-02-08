package org.cloudfoundry.credhub.config

import org.cloudfoundry.credhub.util.CurrentTimeProvider
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration

@Configuration
class CurrentTimeProviderConfig {

    companion object {
        const val CURRENT_TIME_PROVIDER = "currentTimeProvider"
    }

    @Bean(name = [CurrentTimeProviderConfig.CURRENT_TIME_PROVIDER])
    fun currentTimeProvider(): CurrentTimeProvider {
        return CurrentTimeProvider()
    }
}
