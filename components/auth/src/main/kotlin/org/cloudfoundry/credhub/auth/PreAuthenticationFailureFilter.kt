package org.cloudfoundry.credhub.auth

import org.springframework.security.core.AuthenticationException
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter
import java.io.IOException
import jakarta.servlet.FilterChain
import jakarta.servlet.ServletException
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse

@Component
class PreAuthenticationFailureFilter internal constructor(
    private val authenticationFailureHandler: X509AuthenticationFailureHandler,
) : OncePerRequestFilter() {
    @Throws(ServletException::class, IOException::class)
    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain,
    ) {
        try {
            filterChain.doFilter(request, response)
        } catch (exception: AuthenticationException) {
            authenticationFailureHandler.onAuthenticationFailure(request, response, exception)
        }
    }
}
