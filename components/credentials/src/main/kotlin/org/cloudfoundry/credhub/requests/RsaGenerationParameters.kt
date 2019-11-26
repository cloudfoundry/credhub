package org.cloudfoundry.credhub.requests

import java.util.Objects

class RsaGenerationParameters : RsaSshGenerationParameters() {
    override fun equals(o: Any?): Boolean {
        if (this === o) {
            return true
        }

        if (o == null || javaClass != o.javaClass) {
            return false
        }

        val that = o as RsaGenerationParameters?
        return keyLength == that!!.keyLength
    }

    override fun hashCode(): Int {
        return Objects.hash(keyLength)
    }
}
