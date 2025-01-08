package org.cloudfoundry.credhub.requests

import java.util.Objects

class RsaGenerationParameters : RsaSshGenerationParameters() {
    override fun equals(other: Any?): Boolean {
        if (this === other) {
            return true
        }

        if (other == null || javaClass != other.javaClass) {
            return false
        }

        val that = other as RsaGenerationParameters?
        return keyLength == that!!.keyLength
    }

    override fun hashCode(): Int = Objects.hash(keyLength)
}
