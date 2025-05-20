package org.cloudfoundry.credhub.config

import org.cloudfoundry.credhub.ManagementInterceptor
import org.cloudfoundry.credhub.interceptors.AuditInterceptor
import org.cloudfoundry.credhub.interceptors.UserContextInterceptor
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Configuration
import org.springframework.web.servlet.config.annotation.InterceptorRegistry
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer

@Configuration
class WebMvcConfiguration
    @Autowired
    constructor(
        private val auditInterceptor: AuditInterceptor,
        private val userContextInterceptor: UserContextInterceptor,
        private val managementInterceptor: ManagementInterceptor,
    ) : WebMvcConfigurer {
        override fun addInterceptors(registry: InterceptorRegistry) {
            registry.addInterceptor(auditInterceptor).excludePathPatterns(
                "/info",
                "/health",
                "/**/key-usage",
                "/version",
                "/docs/index.html",
            )
            registry.addInterceptor(managementInterceptor)
            registry.addInterceptor(userContextInterceptor).excludePathPatterns(
                "/info",
                "/health",
                "/**/key-usage",
                "/management",
                "/docs/index.html",
            )
        }
    }
