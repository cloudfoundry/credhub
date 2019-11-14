package org.cloudfoundry.credhub.config

import org.cloudfoundry.credhub.PermissionOperation
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.context.annotation.Configuration

@Configuration
@ConfigurationProperties("security.authorization")
class AuthorizationConfig {
    var permissions: List<Permission>? = null

    class Permission {
        var actors: List<String>? = null
        var operations: List<PermissionOperation>? = null
        var path: String? = null
    }
}
