package org.cloudfoundry.credhub.requests

import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.exceptions.ParameterizedValidationException

open class RsaSshGenerationParameters : GenerationParameters() {
    var keyLength = 2048
    val validKeyLengths: List<Int> = listOf(2048, 3072, 4096)

    override fun validate() {
        if (!validKeyLengths.contains(keyLength)) {
            throw ParameterizedValidationException(ErrorMessages.INVALID_KEY_LENGTH)
        }
    }
}
