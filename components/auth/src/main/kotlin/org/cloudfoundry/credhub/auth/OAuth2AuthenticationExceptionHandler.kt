package org.cloudfoundry.credhub.auth

import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.exceptions.AccessTokenExpiredException
import org.cloudfoundry.credhub.util.CurrentTimeProvider
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.security.core.AuthenticationException
import org.springframework.security.jwt.JwtHelper
import org.springframework.security.jwt.crypto.sign.InvalidSignatureException
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception
import org.springframework.security.oauth2.common.util.JsonParser
import org.springframework.security.oauth2.common.util.JsonParserFactory
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint
import org.springframework.security.oauth2.provider.token.AccessTokenConverter
import org.springframework.stereotype.Service
import java.io.IOException
import java.security.SignatureException
import java.security.cert.CertPathValidatorException
import javax.servlet.ServletException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@Service
@ConditionalOnProperty("security.oauth2.enabled")
class OAuth2AuthenticationExceptionHandler @Autowired
internal constructor(
    private val currentTimeProvider: CurrentTimeProvider,
) : OAuth2AuthenticationEntryPoint() {
    private val objectMapper: JsonParser = JsonParserFactory.create()

    @Throws(IOException::class, ServletException::class)
    override fun commence(
        request: HttpServletRequest,
        response: HttpServletResponse,
        authException: AuthenticationException,
    ) {
        handleException(request, response, authException)
    }

    @Throws(IOException::class, ServletException::class)
    fun handleException(
        request: HttpServletRequest,
        response: HttpServletResponse,
        runtimeException: RuntimeException,
    ) {
        val token = request.getAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_VALUE) as String?

        val tokenInformation = extractTokenInformation(token)

        val cause = extractCause(runtimeException)

        val exception: Exception
        exception = when {
            tokenIsExpired(tokenInformation) -> AccessTokenExpiredException("Access token expired", cause!!)
            cause is InvalidSignatureException -> OAuthSignatureException(
                removeTokenFromMessage(ErrorMessages.INVALID_TOKEN_SIGNATURE, token),
            )
            cause is SignatureException -> OAuthSignatureException(
                removeTokenFromMessage(ErrorMessages.MALFORMED_TOKEN, token),
            )
            cause is CertPathValidatorException ->
                InvalidUAACertificateException(
                    "Server unable to communicate with backend UAA due to untrusted CA: " + runtimeException.message,
                    cause,
                )
            else -> InvalidTokenException(
                removeTokenFromMessage(runtimeException.message.toString(), token),
                cause,
            )
        }

        exception.stackTrace = runtimeException.stackTrace

        doHandle(request, response, exception)
    }

    private fun extractCause(e: RuntimeException): Throwable? {
        var cause: Throwable? = e.cause
        var nextCause: Throwable? = cause?.cause
        while (nextCause != null && nextCause != cause) {
            cause = nextCause
            nextCause = cause.cause
        }
        return cause
    }

    private fun tokenIsExpired(tokenInformation: Map<String, Any>?): Boolean {
        val exp = if (tokenInformation != null) tokenInformation[AccessTokenConverter.EXP] as Long else null
        return exp != null && exp <= currentTimeProvider.instant.epochSecond
    }

    private fun extractTokenInformation(token: String?): Map<String, Any>? {
        return try {
            val jwt = JwtHelper.decode(token)

            val map = objectMapper.parseMap(jwt.claims)
            if (map.containsKey(AccessTokenConverter.EXP) && map[AccessTokenConverter.EXP] is Int) {
                val intValue = map[AccessTokenConverter.EXP] as Int
                map[AccessTokenConverter.EXP] = java.lang.Long.valueOf(intValue.toLong())
            }

            map
        } catch (mie: RuntimeException) {
            null
        }
    }

    private fun removeTokenFromMessage(message: String, token: String?): String {
        return message.replace(": $token", "")
    }
}

class InvalidUAACertificateException(msg: String?, t: Throwable?) : OAuth2Exception(msg, t) {
    override fun getOAuth2ErrorCode(): String? {
        return "server_error"
    }

    override fun getHttpErrorCode(): Int {
        return 500
    }
}
