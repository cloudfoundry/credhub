package org.cloudfoundry.credhub.generate

import org.cloudfoundry.credhub.exceptions.EntryNotFoundException
import org.cloudfoundry.credhub.views.ResponseError
import org.junit.Assert.assertEquals
import org.junit.Test

class ExceptionHandlersTest {

    @Test
    fun handleNotFoundExceptionWorks() {
        val handler = ExceptionHandlers()
        val e = EntryNotFoundException("TEST MESSAGE")

        val result: ResponseError = handler.handleNotFoundException(e)

        assertEquals("TEST MESSAGE", result.error)
    }
}
