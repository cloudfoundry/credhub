package org.cloudfoundry.credhub

import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import org.cloudfoundry.credhub.exceptions.InvalidRemoteAddressException
import org.cloudfoundry.credhub.exceptions.ReadOnlyException
import org.springframework.stereotype.Component
import org.springframework.web.bind.annotation.RequestMethod
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter

@Component
class ManagementInterceptor(private val managementRegistry: ManagementRegistry) : HandlerInterceptorAdapter() {

    override fun preHandle(request: HttpServletRequest, response: HttpServletResponse, handler: Any): Boolean {
        if (request.requestURI == MANAGEMENT_API && request.remoteAddr != request.localAddr) {
            throw InvalidRemoteAddressException()
        }

        if (managementRegistry.readOnlyMode &&
            !request.method.equals(RequestMethod.GET.toString(), ignoreCase = true) &&
            request.requestURI != MANAGEMENT_API &&
            request.requestURI != INTERPOLATE_API) {
            throw ReadOnlyException()
        }

        return true
    }

    companion object {

        const val MANAGEMENT_API = "/management"
        const val INTERPOLATE_API = "/interpolate"
    }
}
