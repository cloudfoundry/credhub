package org.cloudfoundry.credhub.requests

import org.apache.commons.lang3.builder.EqualsBuilder
import org.apache.commons.lang3.builder.HashCodeBuilder

class UsernameValue {
    var username: String? = null

    override fun equals(other: Any?): Boolean {
        if (this === other) {
            return true
        }

        if (other == null || javaClass != other.javaClass) {
            return false
        }

        val that = other as UsernameValue?

        return EqualsBuilder()
            .append(username, that!!.username)
            .isEquals
    }

    override fun hashCode(): Int =
        HashCodeBuilder(17, 37)
            .append(username)
            .toHashCode()
}
