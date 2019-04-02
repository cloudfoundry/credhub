package org.cloudfoundry.credhub.helpers

import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder

fun MockHttpServletRequestBuilder.credHubAuthHeader(): MockHttpServletRequestBuilder {
    this.header("Authorization", "Bearer [some-token]")
    return this
}
