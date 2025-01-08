package org.cloudfoundry.credhub.exceptions

import org.cloudfoundry.credhub.ErrorMessages

open class InvalidDurationCertificateException
    @JvmOverloads
    constructor(
        messageCode: String = ErrorMessages.INVALID_DURATION,
        parameters: Array<Any> = arrayOf(),
    ) : ParameterizedValidationException(messageCode)
