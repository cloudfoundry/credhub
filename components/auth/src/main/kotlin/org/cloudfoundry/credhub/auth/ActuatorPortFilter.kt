package org.cloudfoundry.credhub.auth

import org.springframework.beans.factory.annotation.Value
import org.springframework.http.HttpStatus
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter
import java.io.IOException
import javax.servlet.FilterChain
import javax.servlet.ServletException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@Component
class ActuatorPortFilter : OncePerRequestFilter() {

    @Value("\${management.server.port}")
    private val port: Int? = null

    @Throws(ServletException::class, IOException::class)
    override fun doFilterInternal(request: HttpServletRequest, response: HttpServletResponse, filterChain: FilterChain) {
        if (request.localPort == port && request.requestURI != "/health") {
            response.status = HttpStatus.NOT_FOUND.value()
        } else {
            filterChain.doFilter(request, response)
        }
    }
}
