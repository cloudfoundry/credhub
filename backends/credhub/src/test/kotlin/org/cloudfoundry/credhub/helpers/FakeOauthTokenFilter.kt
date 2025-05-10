package org.cloudfoundry.credhub.helpers

import jakarta.servlet.Filter
import jakarta.servlet.FilterChain
import jakarta.servlet.FilterConfig
import jakarta.servlet.ServletException
import jakarta.servlet.ServletRequest
import jakarta.servlet.ServletResponse
import jakarta.servlet.http.HttpServletRequest
import java.io.IOException
import java.util.regex.Pattern

class FakeOauthTokenFilter : Filter {
    @Throws(ServletException::class)
    override fun init(filterConfig: FilterConfig) {
    }

    @Throws(IOException::class, ServletException::class)
    override fun doFilter(
        request: ServletRequest,
        response: ServletResponse,
        chain: FilterChain,
    ) {
        val servletRequest = request as HttpServletRequest
        val header = servletRequest.getHeader("Authorization") ?: throw ServletException("Missing Authorization header")
        val p = Pattern.compile("Bearer .+")
        if (!p.matcher(header).matches()) {
            throw ServletException("Missing auth token in Authorization header")
        }
        chain.doFilter(request, response)
    }

    override fun destroy() {}
}
