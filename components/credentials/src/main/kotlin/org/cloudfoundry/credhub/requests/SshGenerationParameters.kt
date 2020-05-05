package org.cloudfoundry.credhub.requests

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.annotation.JsonInclude.Include.NON_DEFAULT
import java.util.Objects

@JsonInclude(NON_DEFAULT)
class SshGenerationParameters : RsaSshGenerationParameters() {

    var sshComment: String? = ""

    override fun equals(other: Any?): Boolean {
        if (this === other) {
            return true
        }

        if (other == null || javaClass != other.javaClass) {
            return false
        }

        val that = other as SshGenerationParameters?
        return sshComment == that!!.sshComment && keyLength == that.keyLength
    }

    override fun hashCode(): Int {
        return Objects.hash(sshComment, keyLength)
    }
}
