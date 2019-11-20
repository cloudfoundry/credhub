package org.cloudfoundry.credhub.auth

import org.springframework.stereotype.Component
import org.springframework.web.context.annotation.RequestScope

@Component
@RequestScope
class UserContextHolder {
    var userContext: UserContext? = null
}
