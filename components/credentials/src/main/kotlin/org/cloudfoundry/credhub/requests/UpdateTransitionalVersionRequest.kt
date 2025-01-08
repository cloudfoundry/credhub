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

    override fun equals(other: Any?): Boolean {
        if (this === other) {
            return true
        }

        if (other == null || javaClass != other.javaClass) {
            return false
        }

        val that = other as UpdateTransitionalVersionRequest?

        return EqualsBuilder()
            .append(versionUuid, that!!.versionUuid)
            .isEquals
    }

    override fun hashCode(): Int =
        HashCodeBuilder(17, 37)
            .append(versionUuid)
            .toHashCode()
}
