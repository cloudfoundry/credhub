package org.cloudfoundry.credhub.requests

import org.apache.commons.lang3.builder.EqualsBuilder
import org.apache.commons.lang3.builder.HashCodeBuilder

class UsernameValue {
    var username: String? = null

    override fun equals(o: Any?): Boolean {
        if (this === o) {
            return true
        }

        if (o == null || javaClass != o.javaClass) {
            return false
        }

        val that = o as UsernameValue?

        return EqualsBuilder()
            .append(username, that!!.username)
            .isEquals
    }

    override fun hashCode(): Int {
        return HashCodeBuilder(17, 37)
            .append(username)
            .toHashCode()
    }
}
