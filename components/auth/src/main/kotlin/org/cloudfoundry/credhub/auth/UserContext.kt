package org.cloudfoundry.credhub.auth

import java.time.Instant
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.style.BCStyle

class UserContext {
    class UnsupportedGrantTypeException(message: String) : Exception(message)
    class UnsupportedAuthMethodException(message: String) : Exception(message)

    var userId = VALUE_MISSING_OR_IRRELEVANT_TO_AUTH_TYPE
    var userName = VALUE_MISSING_OR_IRRELEVANT_TO_AUTH_TYPE
    var issuer = VALUE_MISSING_OR_IRRELEVANT_TO_AUTH_TYPE
    var validFrom = Instant.EPOCH.epochSecond
        private set
    var validUntil = Instant.EPOCH.epochSecond
        private set
    var clientId: String? = null
        private set
    var scope = VALUE_MISSING_OR_IRRELEVANT_TO_AUTH_TYPE
    var grantType = VALUE_MISSING_OR_IRRELEVANT_TO_AUTH_TYPE
    var authMethod: String? = null
        private set

    val actor: String
        get() {
            if (AUTH_METHOD_UAA == this.authMethod) {
                return when (this.grantType) {
                    UAA_PASSWORD_GRANT_TYPE -> {
                        UAA_USER_ACTOR_PREFIX + ":" + this.userId
                    }
                    UAA_CLIENT_CREDENTIALS_GRANT_TYPE -> {
                        UAA_CLIENT_ACTOR_PREFIX + ":" + this.clientId
                    }
                    else -> {
                        throw UnsupportedGrantTypeException(this.grantType.toString())
                    }
                }
            }

            return if (AUTH_METHOD_MUTUAL_TLS == this.authMethod) {
                MTLS_ACTOR_PREFIX + "-" + parseAppIdentifier(this.clientId)
            } else {
                throw UnsupportedAuthMethodException(this.authMethod.toString())
            }
        }

    // Needed for UserContextArgumentResolver
    constructor() : super() {}

    constructor(
        userId: String?,
        userName: String?,
        issuer: String?,
        validFrom: Long,
        validUntil: Long,
        clientId: String,
        scope: String,
        grantType: String,
        authMethod: String
    ) : super() {
        this.userId = userId
        this.userName = userName
        this.issuer = issuer
        this.validFrom = validFrom
        this.validUntil = validUntil
        this.clientId = clientId
        this.scope = scope
        this.grantType = grantType
        this.authMethod = authMethod
    }

    constructor(
        validFrom: Long,
        validUntil: Long,
        clientId: String,
        authMethod: String
    ) : super() {
        this.validFrom = validFrom
        this.validUntil = validUntil
        this.clientId = clientId
        this.authMethod = authMethod
    }

    private fun parseAppIdentifier(subjectDn: String?): String {
        val dnName = X500Name(subjectDn)
        val rdNs = dnName.getRDNs(BCStyle.OU)
        return rdNs[0].first.value.toString()
    }

    override fun toString(): String {
        return "UserContext{" +
            "userId='" + userId + '\''.toString() +
            ", userName='" + userName + '\''.toString() +
            ", issuer='" + issuer + '\''.toString() +
            ", validFrom=" + validFrom +
            ", validUntil=" + validUntil +
            ", clientId='" + clientId + '\''.toString() +
            ", scope='" + scope + '\''.toString() +
            ", grantType='" + grantType + '\''.toString() +
            ", authMethod='" + authMethod + '\''.toString() +
            '}'.toString()
    }

    companion object {

        val VALUE_MISSING_OR_IRRELEVANT_TO_AUTH_TYPE: String? = null
        const val AUTH_METHOD_UAA = "uaa"
        const val AUTH_METHOD_MUTUAL_TLS = "mutual_tls"
        private const val UAA_USER_ACTOR_PREFIX = "uaa-user"
        private const val UAA_CLIENT_ACTOR_PREFIX = "uaa-client"
        private const val MTLS_ACTOR_PREFIX = "mtls"
        private const val UAA_PASSWORD_GRANT_TYPE = "password"
        private const val UAA_CLIENT_CREDENTIALS_GRANT_TYPE = "client_credentials"
    }
}
