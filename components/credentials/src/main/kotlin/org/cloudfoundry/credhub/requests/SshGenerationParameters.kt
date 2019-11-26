package org.cloudfoundry.credhub.requests

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.annotation.JsonInclude.Include.NON_DEFAULT
import java.util.Objects

@JsonInclude(NON_DEFAULT)
class SshGenerationParameters : RsaSshGenerationParameters() {

    var sshComment: String? = ""

    override fun equals(o: Any?): Boolean {
        if (this === o) {
            return true
        }

        if (o == null || javaClass != o.javaClass) {
            return false
        }

        val that = o as SshGenerationParameters?
        return sshComment == that!!.sshComment && keyLength == that.keyLength
    }

    override fun hashCode(): Int {
        return Objects.hash(sshComment, keyLength)
    }
}
