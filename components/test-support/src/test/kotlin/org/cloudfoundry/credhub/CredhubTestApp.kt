package org.cloudfoundry.credhub

import org.cloudfoundry.credhub.config.CurrentTimeProviderConfig
import org.springframework.boot.autoconfigure.SpringBootApplication
import org.springframework.data.jpa.repository.config.EnableJpaAuditing

@SpringBootApplication
@EnableJpaAuditing(dateTimeProviderRef = CurrentTimeProviderConfig.CURRENT_TIME_PROVIDER)
class CredhubTestApp
