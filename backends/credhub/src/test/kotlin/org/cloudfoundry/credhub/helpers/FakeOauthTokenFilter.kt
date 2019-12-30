package org.cloudfoundry.credhub.helpers

import java.io.IOException
import java.util.regex.Pattern
import javax.servlet.Filter
import javax.servlet.FilterChain
import javax.servlet.FilterConfig
import javax.servlet.ServletException
import javax.servlet.ServletRequest
import javax.servlet.ServletResponse
import javax.servlet.http.HttpServletRequest

class FakeOauthTokenFilter : Filter {
    @Throws(ServletException::class)
    override fun init(filterConfig: FilterConfig) {
    }

    @Throws(IOException::class, ServletException::class)
    override fun doFilter(request: ServletRequest, response: ServletResponse, chain: FilterChain) {
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
