package org.cloudfoundry.credhub.interceptors

import jakarta.servlet.http.HttpServletRequest
import org.cloudfoundry.credhub.auth.UserContext
import org.cloudfoundry.credhub.auth.UserContextFactory
import org.cloudfoundry.credhub.auth.UserContextHolder
import org.hamcrest.MatcherAssert.assertThat
import org.hamcrest.Matchers.equalTo
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.mockito.ArgumentMatchers.any
import org.mockito.Mockito.mock
import org.mockito.Mockito.`when`
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.core.Authentication
import java.security.Principal

class UserContextInterceptorTest {
    private var subject: UserContextInterceptor? = null
    private var userContext: UserContext? = null
    private var userContextFactory: UserContextFactory? = null
    private var userContextHolder: UserContextHolder? = null
    private var request: HttpServletRequest? = null
    private var response: MockHttpServletResponse? = null

    @BeforeEach
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
