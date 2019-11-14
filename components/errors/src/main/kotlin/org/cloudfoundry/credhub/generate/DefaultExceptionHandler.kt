package org.cloudfoundry.credhub.generate

import org.springframework.http.HttpStatus
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.web.bind.annotation.RestControllerAdvice

import org.apache.logging.log4j.LogManager
import org.cloudfoundry.credhub.ErrorMessages
import org.cloudfoundry.credhub.views.ResponseError

@RestControllerAdvice
class DefaultExceptionHandler {

    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    @ExceptionHandler(Exception::class)
    fun handleGeneralException(e: Exception): ResponseError {
        val message = ErrorMessages.INTERNAL_SERVER_ERROR
        LOGGER.error(message, e.javaClass)
        LOGGER.error(message, e)
        return ResponseError(message)
    }

    companion object {

        private val LOGGER = LogManager.getLogger(DefaultExceptionHandler::class.java)
    }
}
