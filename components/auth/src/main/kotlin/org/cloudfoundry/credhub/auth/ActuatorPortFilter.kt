package org.cloudfoundry.credhub.auth

import jakarta.servlet.FilterChain
import jakarta.servlet.ServletException
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.beans.factory.annotation.Value
import org.springframework.http.HttpStatus
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter
import java.io.IOException

@Component
class ActuatorPortFilter : OncePerRequestFilter() {
    @Value("\${management.server.port}")
    private val port: Int? = null

    @Throws(ServletException::class, IOException::class)
    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain,
    ) {
        if (request.localPort == port && request.requestURI != "/health") {
            response.status = HttpStatus.NOT_FOUND.value()
        } else {
            filterChain.doFilter(request, response)
        }
    }
}
