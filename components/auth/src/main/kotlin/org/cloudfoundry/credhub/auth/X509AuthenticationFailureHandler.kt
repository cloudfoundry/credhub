package org.cloudfoundry.credhub.auth

import com.fasterxml.jackson.databind.ObjectMapper
import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.auth.X509AuthenticationProvider.Companion.CLIENT_AUTH_EXTENDED_KEY_USAGE
import org.cloudfoundry.credhub.views.ResponseError
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpStatus
import org.springframework.security.core.AuthenticationException
import org.springframework.security.web.authentication.AuthenticationFailureHandler
import org.springframework.stereotype.Component
import org.springframework.util.MimeTypeUtils.APPLICATION_JSON
import java.io.IOException
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse

@Component
class X509AuthenticationFailureHandler
    @Autowired
    internal constructor(
        private val objectMapper: ObjectMapper,
    ) : AuthenticationFailureHandler {
        @Throws(IOException::class)
        override fun onAuthenticationFailure(
            request: HttpServletRequest,
            response: HttpServletResponse,
            exception: AuthenticationException,
        ) {
            if (exception.message.toString().contains(INVALID_DN_MESSAGE)) {
                writeUnauthorizedResponse(response, INVALID_MTLS_ID_RESPONSE)
            }

            if (exception.message.toString().contains("Certificate does not contain: $CLIENT_AUTH_EXTENDED_KEY_USAGE")) {
                writeUnauthorizedResponse(response, INVALID_CLIENT_AUTH_RESPONSE)
            }
        }

        @Throws(IOException::class)
        private fun writeUnauthorizedResponse(
            response: HttpServletResponse,
            message: String,
        ) {
            val responseError = ResponseError(message)

            response.status = HttpStatus.UNAUTHORIZED.value()
            response.contentType = APPLICATION_JSON.type
            response.writer.write(objectMapper.writeValueAsString(responseError))
        }

        companion object {
            private const val INVALID_DN_MESSAGE = "No matching pattern was found in subjectDN"
            private const val INVALID_MTLS_ID_RESPONSE = ErrorMessages.Auth.INVALID_MTLS_IDENTITY
            private const val INVALID_CLIENT_AUTH_RESPONSE = ErrorMessages.Auth.MTLS_NOT_CLIENT_AUTH
        }
    }
