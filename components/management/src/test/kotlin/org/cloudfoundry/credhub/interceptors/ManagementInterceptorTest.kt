package org.cloudfoundry.credhub.interceptors

import org.cloudfoundry.credhub.CredhubTestApp
import org.cloudfoundry.credhub.ManagementInterceptor
import org.cloudfoundry.credhub.ManagementRegistry
import org.cloudfoundry.credhub.exceptions.InvalidRemoteAddressException
import org.cloudfoundry.credhub.exceptions.ReadOnlyException
import org.cloudfoundry.credhub.utils.DatabaseProfileResolver
import org.hamcrest.core.Is.`is`
import org.junit.After
import org.junit.Assert.assertThat
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.test.context.ActiveProfiles
import org.springframework.test.context.junit4.SpringRunner

@RunWith(SpringRunner::class)
@ActiveProfiles(value = "unit-test", resolver = DatabaseProfileResolver::class)
@SpringBootTest(classes = [CredhubTestApp::class])
class ManagementInterceptorTest {
    private var subject: ManagementInterceptor? = null
    private var request: MockHttpServletRequest? = null
    private var response: MockHttpServletResponse? = null

    @Autowired
    private val managementRegistry: ManagementRegistry? = null

    @Before
    fun setup() {
        subject = ManagementInterceptor(managementRegistry!!)
        request = MockHttpServletRequest()
        response = MockHttpServletResponse()

        managementRegistry.readOnlyMode = false
    }

    @After
    fun tearDown() {
        managementRegistry!!.readOnlyMode = false
    }

    @Test(expected = InvalidRemoteAddressException::class)
    fun preHandle_throwsAnExceptionWhenRemoteAddressDoesNotMatchLocalAddress() {
        request!!.remoteAddr = "10.0.0.1"
        request!!.localAddr = "127.0.0.1"
        request!!.requestURI = "/management"
        subject!!.preHandle(request!!, response!!, Any())
        assertThat(response!!.status, `is`(401))
    }

    @Test
    fun preHandle_doesNotThrowAnExceptionWhenRemoteAddressMatchesLocalAddress() {
        request!!.remoteAddr = "127.0.0.1"
        request!!.localAddr = "127.0.0.1"
        request!!.requestURI = "/management"
        subject!!.preHandle(request!!, response!!, Any())
    }

    @Test(expected = ReadOnlyException::class)
    fun preHandle_throwsAnExceptionWhenTheRequestMethodIsNotGetInReadOnlyMode() {
        managementRegistry!!.readOnlyMode = true
        request!!.requestURI = "/api/v1/data"
        request!!.method = "POST"
        subject!!.preHandle(request!!, response!!, Any())
        assertThat(response!!.status, `is`(503))
    }

    @Test
    fun preHandle_throwsNoExceptionWhenTheRequestMethodGetInReadOnlyMode() {
        managementRegistry!!.readOnlyMode = true
        request!!.requestURI = "/api/v1/data"
        request!!.method = "GET"
        subject!!.preHandle(request!!, response!!, Any())
    }

    @Test
    fun preHandle_postsToManagementStillWork() {
        managementRegistry!!.readOnlyMode = true
        request!!.requestURI = "/management"
        request!!.method = "POST"
        subject!!.preHandle(request!!, response!!, Any())
    }

    @Test
    fun preHandle_continuesToServePostsToInterpolate() {
        managementRegistry!!.readOnlyMode = true
        request!!.requestURI = "/interpolate"
        request!!.method = "POST"
        subject!!.preHandle(request!!, response!!, Any())
    }
}
