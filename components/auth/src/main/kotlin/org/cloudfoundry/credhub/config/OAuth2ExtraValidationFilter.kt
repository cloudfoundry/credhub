package org.cloudfoundry.credhub.config

import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.auth.OAuth2AuthenticationExceptionHandler
import org.cloudfoundry.credhub.auth.OAuth2IssuerService
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.security.authentication.AuthenticationEventPublisher
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.authentication.InsufficientAuthenticationException
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.jwt.crypto.sign.InvalidSignatureException
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception
import org.springframework.security.oauth2.provider.authentication.BearerTokenExtractor
import org.springframework.security.oauth2.provider.authentication.TokenExtractor
import org.springframework.security.oauth2.provider.token.TokenStore
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken
import org.springframework.stereotype.Service
import org.springframework.web.filter.OncePerRequestFilter
import java.io.IOException
import java.security.SignatureException
import javax.servlet.FilterChain
import javax.servlet.ServletException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@Service
@ConditionalOnProperty("security.oauth2.enabled")
class OAuth2ExtraValidationFilter @Autowired
internal constructor(
    private val oAuth2IssuerService: OAuth2IssuerService,
    private val tokenStore: TokenStore,
    private val oAuth2AuthenticationExceptionHandler: OAuth2AuthenticationExceptionHandler,
    private val eventPublisher: AuthenticationEventPublisher
) : OncePerRequestFilter() {
    private val tokenExtractor: TokenExtractor

    init {
        this.tokenExtractor = BearerTokenExtractor()
    }

    @Throws(ServletException::class, IOException::class)
    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain
    ) {
        val authentication = tokenExtractor.extract(request)

        try {
            if (authentication != null) {
                val token = authentication.principal as String
                val accessToken = tokenStore.readAccessToken(token)
                val additionalInformation = accessToken.additionalInformation
                val issuer = (additionalInformation as java.util.Map<String, Any>).getOrDefault("iss", "") as String

                if (issuer != oAuth2IssuerService.getIssuer()) {
                    tokenStore.removeAccessToken(accessToken)

                    val errorMessage = ErrorMessages.Oauth.INVALID_ISSUER
                    throw OAuth2Exception(errorMessage)
                }
            }

            filterChain.doFilter(request, response)
        } catch (exception: OAuth2Exception) {
            SecurityContextHolder.clearContext()
            val authException = InsufficientAuthenticationException(
                exception.message, exception
            )
            eventPublisher.publishAuthenticationFailure(
                BadCredentialsException(exception.message, exception),
                PreAuthenticatedAuthenticationToken("access-token", "N/A")
            )
            oAuth2AuthenticationExceptionHandler.handleException(request, response, authException)
        } catch (exception: RuntimeException) {
            if (exception.cause is SignatureException || exception
                .cause is InvalidSignatureException
            ) {
                oAuth2AuthenticationExceptionHandler.handleException(request, response, exception)
            } else {
                throw exception
            }
        }
    }
}
