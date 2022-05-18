package org.cloudfoundry.credhub.generate

import org.cloudfoundry.credhub.exceptions.EntryNotFoundException
import org.cloudfoundry.credhub.views.ResponseError
import org.junit.Assert.*
import org.junit.Test

class ExceptionHandlersTest {

    @Test
    fun handleNotFoundExceptionWorks() {
        var handler = ExceptionHandlers()
        var e = EntryNotFoundException("TEST MESSAGE")

        var result : ResponseError = handler.handleNotFoundException(e)

        assertEquals("TEST MESSAGE", result.error)
    }
}