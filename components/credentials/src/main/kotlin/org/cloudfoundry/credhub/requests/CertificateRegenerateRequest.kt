package org.cloudfoundry.credhub.requests

import tools.jackson.databind.JsonNode

class CertificateRegenerateRequest(
    var setAsTransitional: Boolean = false,
    var allowTransitionalParentToSign: Boolean = false,
    var keyLength: Int? = null,
    var duration: Int? = null,
    var metadata: JsonNode? = null,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as CertificateRegenerateRequest

        if (setAsTransitional != other.setAsTransitional) return false
        if (allowTransitionalParentToSign != other.allowTransitionalParentToSign) return false
        if (keyLength != other.keyLength) return false
        if (duration != other.duration) return false

        return true
    }

    override fun hashCode(): Int {
        var result = setAsTransitional.hashCode()
        result = 31 * result + allowTransitionalParentToSign.hashCode()
        return result
    }
}
