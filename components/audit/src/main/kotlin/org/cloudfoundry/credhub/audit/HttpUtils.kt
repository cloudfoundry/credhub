package org.cloudfoundry.credhub.audit

import org.springframework.http.HttpStatus

class HttpUtils private constructor() {
    companion object {
        fun getResultCode(statusCode: Int): String =
            if (statusCode < HttpStatus.OK.value()) {
                "info"
            } else if (statusCode < HttpStatus.MULTIPLE_CHOICES.value()) {
                "success"
            } else if (statusCode < HttpStatus.BAD_REQUEST.value()) {
                "redirect"
            } else if (statusCode < HttpStatus.INTERNAL_SERVER_ERROR.value()) {
                "clientError"
            } else {
                "serverError"
            }
    }
}
