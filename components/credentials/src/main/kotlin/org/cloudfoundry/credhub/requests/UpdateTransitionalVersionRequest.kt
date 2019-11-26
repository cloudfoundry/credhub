package org.cloudfoundry.credhub.requests

import com.fasterxml.jackson.annotation.JsonProperty
import org.apache.commons.lang3.builder.EqualsBuilder
import org.apache.commons.lang3.builder.HashCodeBuilder

class UpdateTransitionalVersionRequest {
    @JsonProperty("version")
    var versionUuid: String? = null

    constructor() : super() {}

    constructor(versionUuid: String) : super() {
        this.versionUuid = versionUuid
    }

    override fun equals(o: Any?): Boolean {
        if (this === o) {
            return true
        }

        if (o == null || javaClass != o.javaClass) {
            return false
        }

        val that = o as UpdateTransitionalVersionRequest?

        return EqualsBuilder()
            .append(versionUuid, that!!.versionUuid)
            .isEquals
    }

    override fun hashCode(): Int {
        return HashCodeBuilder(17, 37)
            .append(versionUuid)
            .toHashCode()
    }
}
