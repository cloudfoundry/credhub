package org.cloudfoundry.credhub.interceptors

import org.cloudfoundry.credhub.auth.UserContextFactory
import org.cloudfoundry.credhub.auth.UserContextHolder
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.core.Authentication
import org.springframework.stereotype.Component
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@Component
class UserContextInterceptor @Autowired
internal constructor(
    private val userContextFactory: UserContextFactory,
    private val userContextHolder: UserContextHolder
) : HandlerInterceptorAdapter() {

    override fun preHandle(request: HttpServletRequest, response: HttpServletResponse, handler: Any): Boolean {
        val principal = if (request.userPrincipal != null) {
            request.userPrincipal as Authentication
        } else {
            return false
        }
        userContextHolder.userContext = userContextFactory.createUserContext(principal)
        return true
    }
}
