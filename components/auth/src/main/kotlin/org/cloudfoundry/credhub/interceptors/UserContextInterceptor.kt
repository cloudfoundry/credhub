package org.cloudfoundry.credhub.interceptors

import org.cloudfoundry.credhub.auth.UserContextFactory
import org.cloudfoundry.credhub.auth.UserContextHolder
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.core.Authentication
import org.springframework.stereotype.Component
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.web.servlet.HandlerInterceptor

@Component
class UserContextInterceptor
    @Autowired
    internal constructor(
        private val userContextFactory: UserContextFactory,
        private val userContextHolder: UserContextHolder,
    ) : HandlerInterceptor {
        override fun preHandle(
            request: HttpServletRequest,
            response: HttpServletResponse,
            handler: Any,
        ): Boolean {
            val principal =
                if (request.userPrincipal != null) {
                    request.userPrincipal as Authentication
                } else {
                    return false
                }
            userContextHolder.userContext = userContextFactory.createUserContext(principal)
            return true
        }
    }
