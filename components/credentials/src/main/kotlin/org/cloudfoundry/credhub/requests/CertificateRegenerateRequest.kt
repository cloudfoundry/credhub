package org.cloudfoundry.credhub.requests

import com.fasterxml.jackson.annotation.JsonAutoDetect
import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.databind.JsonNode

@JsonAutoDetect
class CertificateRegenerateRequest {

    @JsonProperty("set_as_transitional")
    @set:JsonProperty("set_as_transitional")
    var isTransitional: Boolean = false

    @JsonProperty("allow_transitional_parent_to_sign")
    @set:JsonProperty("allow_transitional_parent_to_sign")
    var allowTransitionalParentToSign: Boolean = false

    @JsonProperty("metadata")
    @set:JsonProperty("metadata")
    var metadata: JsonNode? = null

    constructor() : super() {
        /* this needs to be there for jackson to be happy */
    }

    constructor(transitional: Boolean, allowTransitionalParentToSign: Boolean, metadata: JsonNode?) : super() {
        this.isTransitional = transitional
        this.allowTransitionalParentToSign = allowTransitionalParentToSign
        this.metadata = metadata
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as CertificateRegenerateRequest

        if (isTransitional != other.isTransitional) return false
        if (allowTransitionalParentToSign != other.allowTransitionalParentToSign) return false

        return true
    }

    override fun hashCode(): Int {
        var result = isTransitional.hashCode()
        result = 31 * result + allowTransitionalParentToSign.hashCode()
        return result
    }
}
