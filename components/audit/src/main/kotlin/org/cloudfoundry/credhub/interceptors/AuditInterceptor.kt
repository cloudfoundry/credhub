package org.cloudfoundry.credhub.interceptors

import org.apache.logging.log4j.LogManager
import org.cloudfoundry.credhub.audit.CEFAuditRecord
import org.cloudfoundry.credhub.auth.UserContextFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.lang.Nullable
import org.springframework.security.core.Authentication
import org.springframework.stereotype.Component
import org.springframework.web.servlet.handler.HandlerInterceptorAdapter
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@Component
class AuditInterceptor @Autowired
internal constructor(
    private val userContextFactory: UserContextFactory,
    private val auditRecord: CEFAuditRecord,
) : HandlerInterceptorAdapter() {

    override fun preHandle(request: HttpServletRequest, response: HttpServletResponse, handler: Any): Boolean {
        auditRecord.initCredentials()
        auditRecord.setHttpRequest(request)
        return true
    }

    override fun afterCompletion(request: HttpServletRequest, response: HttpServletResponse, handler: Any, @Nullable exception: Exception?) {
        val userAuth = request.userPrincipal ?: return
        val userContext = userContextFactory.createUserContext(userAuth as Authentication)

        auditRecord.username = userAuth.name
        auditRecord.httpStatusCode = response.status
        auditRecord.setUserGuid(userContext.actor!!)
        auditRecord.authMechanism = userContext.authMethod!!

        LOGGER.info(auditRecord.toString())
    }

    companion object {

        private val LOGGER = LogManager.getLogger("CEFAudit")
    }
}
