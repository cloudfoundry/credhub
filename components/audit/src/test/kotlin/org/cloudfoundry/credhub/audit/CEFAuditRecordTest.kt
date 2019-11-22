package org.cloudfoundry.credhub.audit

import java.nio.charset.StandardCharsets.UTF_8
import org.hamcrest.MatcherAssert.assertThat
import org.hamcrest.Matchers.`is`
import org.hamcrest.Matchers.equalTo
import org.junit.Before
import org.junit.Test
import org.springframework.mock.web.MockHttpServletRequest

class CEFAuditRecordTest {

    private var auditRecord: CEFAuditRecord? = null
    private var httpRequest: MockHttpServletRequest? = null

    @Before
    fun setUp() {
        this.auditRecord = CEFAuditRecord()
        this.httpRequest = MockHttpServletRequest()
        httpRequest!!.requestURI = "/foo/bar"
        httpRequest!!.queryString = "baz=qux&hi=bye"
        httpRequest!!.remoteAddr = "127.0.0.1"
        httpRequest!!.serverName = "credhub.example"
    }

    @Test
    fun getHttpRequest() {
        httpRequest!!.method = "GET"

        auditRecord!!.setHttpRequest(httpRequest!!)
        assertThat(auditRecord!!.requestPath, `is`(equalTo("/foo/bar?baz=qux&hi=bye")))
        assertThat(auditRecord!!.requestMethod, `is`(equalTo("GET")))
        assertThat(auditRecord!!.signatureId, `is`(equalTo("GET /foo/bar")))
        assertThat(auditRecord!!.sourceAddress, equalTo("127.0.0.1"))
        assertThat(auditRecord!!.destinationAddress, equalTo("credhub.example"))
    }

    @Test
    fun getHttpRequest_setsSourceAddressIfProxied() {
        httpRequest!!.addHeader("X-FORWARDED-FOR", "192.168.0.1")
        httpRequest!!.remoteAddr = "127.0.0.1"
        auditRecord!!.setHttpRequest(httpRequest!!)
        assertThat(auditRecord!!.sourceAddress, equalTo("192.168.0.1"))
    }

    @Test
    fun setHttpRequest() {
        val data = "{\"name\":\"example-value\",\"value\":\"secret\"}"
        httpRequest!!.setContent(data.toByteArray(UTF_8))
        httpRequest!!.method = "PUT"

        auditRecord!!.setHttpRequest(httpRequest!!)
        assertThat(auditRecord!!.requestPath, `is`(equalTo("/foo/bar?baz=qux&hi=bye")))
        assertThat(auditRecord!!.requestMethod, `is`(equalTo("PUT")))
        assertThat(auditRecord!!.signatureId, `is`(equalTo("PUT /foo/bar")))
        assertThat(auditRecord!!.sourceAddress, equalTo("127.0.0.1"))
        assertThat(auditRecord!!.destinationAddress, equalTo("credhub.example"))
    }
}
