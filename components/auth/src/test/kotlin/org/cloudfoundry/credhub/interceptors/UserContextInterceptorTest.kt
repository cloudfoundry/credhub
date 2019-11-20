package org.cloudfoundry.credhub.interceptors

import java.security.Principal
import javax.servlet.http.HttpServletRequest
import junit.framework.TestCase.assertFalse
import org.cloudfoundry.credhub.auth.UserContext
import org.cloudfoundry.credhub.auth.UserContextFactory
import org.cloudfoundry.credhub.auth.UserContextHolder
import org.hamcrest.MatcherAssert.assertThat
import org.hamcrest.Matchers.equalTo
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import org.mockito.ArgumentMatchers.any
import org.mockito.Mockito.`when`
import org.mockito.Mockito.mock
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.core.Authentication

@RunWith(JUnit4::class)
class UserContextInterceptorTest {
    private var subject: UserContextInterceptor? = null
    private var userContext: UserContext? = null
    private var userContextFactory: UserContextFactory? = null
    private var userContextHolder: UserContextHolder? = null
    private var request: HttpServletRequest? = null
    private var response: MockHttpServletResponse? = null

    @Before
    fun setup() {
        userContextFactory = mock(UserContextFactory::class.java)
        userContext = mock(UserContext::class.java)
        userContextHolder = UserContextHolder()

        subject = UserContextInterceptor(userContextFactory!!, userContextHolder!!)

        `when`(userContextFactory!!.createUserContext(any<Authentication>())).thenReturn(userContext)
        request = mock(HttpServletRequest::class.java)
        response = MockHttpServletResponse()
    }

    @Test
    @Throws(Exception::class)
    fun preHandle_setsUserContextFromPrincipal() {
        `when`<Principal>(request!!.userPrincipal).thenReturn(mock(Authentication::class.java))
        subject!!.preHandle(request!!, response!!, Any())

        assertThat<UserContext>(userContextHolder!!.userContext, equalTo<UserContext>(userContext))
    }

    @Test
    @Throws(Exception::class)
    fun preHandle_ReturnsFalseWhenNoPrincipal() {
        `when`<Principal>(request!!.userPrincipal).thenReturn(null)
        val result = subject!!.preHandle(request!!, response!!, Any())
        assertFalse(result)
    }
}
