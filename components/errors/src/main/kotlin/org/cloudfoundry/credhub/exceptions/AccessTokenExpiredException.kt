package org.cloudfoundry.credhub.exceptions

import org.springframework.security.oauth2.common.exceptions.ClientAuthenticationException

class AccessTokenExpiredException(msg: String, t: Throwable) : ClientAuthenticationException(msg, t) {

    override fun getOAuth2ErrorCode(): String {
        return "access_token_expired"
    }

    override fun getHttpErrorCode(): Int {
        return 401
    }
}
