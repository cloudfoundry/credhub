package org.cloudfoundry.credhub

import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.cloudfoundry.credhub.exceptions.InvalidRemoteAddressException
import org.cloudfoundry.credhub.exceptions.ReadOnlyException
import org.springframework.stereotype.Component
import org.springframework.web.bind.annotation.RequestMethod
import org.springframework.web.servlet.AsyncHandlerInterceptor
import org.springframework.web.util.UriUtils
import java.nio.charset.StandardCharsets

@Component
class ManagementInterceptor(
    private val managementRegistry: ManagementRegistry,
) : AsyncHandlerInterceptor {
    override fun preHandle(
        request: HttpServletRequest,
        response: HttpServletResponse,
        handler: Any,
    ): Boolean {
        // Decode the raw requestURI so that percent-encoded paths like /%6Danagement are
        // normalised to /management before comparison — mirroring exactly what Tomcat's
        // CoyoteAdapter does via UDecoder.convert() when populating servletPath, and
        // consistent with how Spring Security's PathPatternRequestMatcher and Spring MVC's
        // handler mapping both resolve the effective path from the decoded form.
        // Using requestURI (rather than servletPath) also works in MockMvc, where the
        // servlet container never populates servletPath and it stays as "".
        val contextPath = request.contextPath ?: ""
        val decodedPath =
            UriUtils.decode(
                request.requestURI.removePrefix(contextPath),
                StandardCharsets.UTF_8,
            )

        if (decodedPath == MANAGEMENT_API && request.remoteAddr != request.localAddr) {
            throw InvalidRemoteAddressException()
        }

        if (managementRegistry.readOnlyMode &&
            !request.method.equals(RequestMethod.GET.toString(), ignoreCase = true) &&
            decodedPath != MANAGEMENT_API &&
            decodedPath != INTERPOLATE_API
        ) {
            throw ReadOnlyException()
        }

        return true
    }

    companion object {
        const val MANAGEMENT_API = "/management"
        const val INTERPOLATE_API = "/interpolate"
    }
}
