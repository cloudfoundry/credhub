package org.cloudfoundry.credhub.auth

import com.jayway.jsonpath.JsonPath
import org.cloudfoundry.credhub.util.CurrentTimeProvider
import org.hamcrest.CoreMatchers.equalTo
import org.hamcrest.MatcherAssert.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.authentication.InsufficientAuthenticationException
import org.springframework.security.oauth2.provider.token.store.jwk.JwkException
import java.security.cert.CertPathValidatorException
import javax.servlet.http.HttpServletRequest

internal class OAuth2AuthenticationExceptionHandlerTest {
    private lateinit var oAuth2AuthenticationExceptionHandler: OAuth2AuthenticationExceptionHandler
    private lateinit var request: HttpServletRequest
    private lateinit var response: MockHttpServletResponse

    @BeforeEach
    fun setUp() {
        oAuth2AuthenticationExceptionHandler = OAuth2AuthenticationExceptionHandler(CurrentTimeProvider())
        request = MockHttpServletRequest()
        response = MockHttpServletResponse()
    }

    @AfterEach
    fun tearDown() {
    }

    @Test
    fun handleException_whenGivenCertPathValidationException_addsErrorMessage() {
        val certPathValidatorException = CertPathValidatorException("this is our error")
        val jwkException = JwkException("some jwk error", certPathValidatorException)
        val exception = InsufficientAuthenticationException(certPathValidatorException.message, jwkException)

        oAuth2AuthenticationExceptionHandler.handleException(request, response, exception)

        assertThat(
            JsonPath.compile("error").read(response.contentAsString),
            equalTo("server_error")
        )
        assertThat(
            JsonPath.compile("error_description").read(response.contentAsString),
            equalTo("Server unable to communicate with backend UAA due to untrusted CA: this is our error")
        )
        assertThat(response.status, equalTo(500))
    }
}