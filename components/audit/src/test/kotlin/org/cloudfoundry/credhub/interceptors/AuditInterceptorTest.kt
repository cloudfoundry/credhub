package org.cloudfoundry.credhub.interceptors

import java.util.UUID
import javax.servlet.http.HttpServletRequest.CLIENT_CERT_AUTH
import org.cloudfoundry.credhub.audit.AuditableCredentialVersion
import org.cloudfoundry.credhub.audit.AuditablePermissionData
import org.cloudfoundry.credhub.audit.CEFAuditRecord
import org.cloudfoundry.credhub.audit.OperationDeviceAction
import org.cloudfoundry.credhub.audit.RequestDetails
import org.cloudfoundry.credhub.auth.UserContext
import org.cloudfoundry.credhub.auth.UserContextFactory
import org.cloudfoundry.credhub.utils.VersionProvider
import org.hamcrest.MatcherAssert.assertThat
import org.hamcrest.Matchers.`is`
import org.hamcrest.Matchers.equalTo
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import org.mockito.ArgumentMatchers.any
import org.mockito.Mockito.`when`
import org.mockito.Mockito.mock
import org.mockito.Mockito.never
import org.mockito.Mockito.verify
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.core.Authentication

@RunWith(JUnit4::class)
class AuditInterceptorTest {
    private var subject: AuditInterceptor? = null
    private var userContextFactory: UserContextFactory? = null
    private var userContext: UserContext? = null
    private var response: MockHttpServletResponse? = null
    private var request: MockHttpServletRequest? = null
    private var auditRecord: CEFAuditRecord? = null
    private var versionProvider: VersionProvider? = null

    @Before
    fun setup() {
        versionProvider = mock(VersionProvider::class.java)
        `when`(versionProvider!!.currentVersion()).thenReturn("x.x.x")

        userContextFactory = mock(UserContextFactory::class.java)
        userContext = mock(UserContext::class.java)
        auditRecord = CEFAuditRecord(versionProvider!!)

        subject = AuditInterceptor(
                userContextFactory!!,
                auditRecord!!
        )
        request = MockHttpServletRequest()
        response = MockHttpServletResponse()
        val authentication = mock(Authentication::class.java)
        request!!.userPrincipal = authentication

        userContext = mock(UserContext::class.java)
        `when`(userContextFactory!!.createUserContext(any<Authentication>())).thenReturn(userContext)
        `when`(userContext!!.actor).thenReturn("user")
        `when`(userContext!!.authMethod).thenReturn(CLIENT_CERT_AUTH)
    }

    @Test
    fun afterCompletion_returnsIfNoUserIsPresent() {
        request!!.userPrincipal = null

        subject!!.afterCompletion(request!!, response!!, Any(), null)

        verify(userContextFactory, never())!!.createUserContext(null)
    }

    @Test
    fun afterCompletion_populatesTheCEFLogObject() {
        val authentication = mock(Authentication::class.java)
        `when`(authentication.name).thenReturn("foo")
        request!!.userPrincipal = authentication
        request!!.authType = CLIENT_CERT_AUTH
        response!!.status = 200

        val credentialVersion = mock(AuditableCredentialVersion::class.java)
        `when`(credentialVersion.uuid).thenReturn(UUID.randomUUID())
        auditRecord!!.setVersion(credentialVersion)

        val permissionData = mock(AuditablePermissionData::class.java)
        `when`(permissionData.uuid).thenReturn(UUID.randomUUID())
        `when`(permissionData.path).thenReturn("/some/path")
        auditRecord!!.setResource(permissionData)

        val requestDetails = mock(RequestDetails::class.java)
        `when`(requestDetails.operation()).thenReturn(OperationDeviceAction.ADD_PERMISSIONS)
        auditRecord!!.requestDetails = requestDetails

        auditRecord!!.setHttpRequest(request!!)

        subject!!.afterCompletion(request!!, response!!, Any(), null)
        assertThat(auditRecord!!.username, `is`(equalTo("foo")))
        assertThat(auditRecord!!.httpStatusCode, `is`(equalTo(200)))
        assertThat(auditRecord!!.result, `is`(equalTo("success")))
        assertThat(auditRecord!!.authMechanism, `is`(equalTo(CLIENT_CERT_AUTH)))
    }

    @Test
    fun preHandle_populatesTheCEFLogObject() {
        request!!.authType = CLIENT_CERT_AUTH
        request!!.requestURI = "/foo/bar"
        request!!.queryString = "baz=qux&hi=bye"
        request!!.method = "GET"
        subject!!.preHandle(request!!, response!!, Any())
        assertThat(auditRecord!!.requestPath, `is`(equalTo("/foo/bar?baz=qux&hi=bye")))
        assertThat(auditRecord!!.requestMethod, `is`(equalTo("GET")))
    }
}
