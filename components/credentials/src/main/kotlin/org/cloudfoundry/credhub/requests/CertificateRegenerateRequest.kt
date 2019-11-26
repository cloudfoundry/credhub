package org.cloudfoundry.credhub.requests

import com.fasterxml.jackson.annotation.JsonAutoDetect
import com.fasterxml.jackson.annotation.JsonProperty
import org.apache.commons.lang3.builder.EqualsBuilder
import org.apache.commons.lang3.builder.HashCodeBuilder

@JsonAutoDetect
class CertificateRegenerateRequest {

    @JsonProperty("set_as_transitional")
    @set:JsonProperty("set_as_transitional")
    var isTransitional: Boolean = false

    constructor() : super() {
        /* this needs to be there for jackson to be happy */
    }

    constructor(transitional: Boolean) : super() {
        this.isTransitional = transitional
    }

    override fun equals(o: Any?): Boolean {
        if (this === o) {
            return true
        }

        if (o == null || javaClass != o.javaClass) {
            return false
        }

        val that = o as CertificateRegenerateRequest?

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
