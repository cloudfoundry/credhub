package org.cloudfoundry.credhub.requests

import com.fasterxml.jackson.annotation.JsonAutoDetect
import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.databind.JsonNode
import org.apache.commons.lang3.builder.EqualsBuilder
import org.apache.commons.lang3.builder.HashCodeBuilder

@JsonAutoDetect
class CertificateRegenerateRequest {

    @JsonProperty("set_as_transitional")
    @set:JsonProperty("set_as_transitional")
    var isTransitional: Boolean = false

    @JsonProperty("metadata")
    @set:JsonProperty("metadata")
    var metadata: JsonNode? = null

    constructor() : super() {
        /* this needs to be there for jackson to be happy */
    }

    constructor(transitional: Boolean, metadata: JsonNode?) : super() {
        this.isTransitional = transitional
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) {
            return true
        }

        if (other == null || javaClass != other.javaClass) {
            return false
        }

        val that = other as CertificateRegenerateRequest?

        return EqualsBuilder()
            .append(isTransitional, that!!.isTransitional)
            .isEquals
    }

    override fun hashCode(): Int {
        return HashCodeBuilder(17, 37)
            .append(isTransitional)
            .toHashCode()
    }
}
