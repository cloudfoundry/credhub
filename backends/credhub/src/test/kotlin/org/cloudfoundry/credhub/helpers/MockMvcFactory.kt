package org.cloudfoundry.credhub.helpers

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.PropertyNamingStrategy.SNAKE_CASE
import org.cloudfoundry.credhub.util.TimeModuleFactory
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter
import org.springframework.restdocs.JUnitRestDocumentation
import org.springframework.restdocs.cli.CliDocumentation.curlRequest
import org.springframework.restdocs.http.HttpDocumentation.httpRequest
import org.springframework.restdocs.http.HttpDocumentation.httpResponse
import org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.documentationConfiguration
import org.springframework.restdocs.operation.preprocess.Preprocessors.prettyPrint
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.result.MockMvcResultHandlers.print
import org.springframework.test.web.servlet.setup.MockMvcBuilders
import org.springframework.test.web.servlet.setup.StandaloneMockMvcBuilder

class MockMvcFactory {
    companion object {
        private fun getPreconfiguredJacksonConverter(): MappingJackson2HttpMessageConverter {
            val converter = MappingJackson2HttpMessageConverter()
            val objectMapper = ObjectMapper()
                .registerModule(TimeModuleFactory.createTimeModule())
                .setPropertyNamingStrategy(SNAKE_CASE)

            converter.setObjectMapper(objectMapper)
            return converter
        }

        @JvmStatic
        fun newSpringRestDocMockMvc(controller: Any, restDocumentation: JUnitRestDocumentation, disableAuth: Boolean = false): MockMvc {
            val mockMvcBuilder = MockMvcBuilders
                .standaloneSetup(controller)
                .setMessageConverters(getPreconfiguredJacksonConverter())
                .alwaysDo<StandaloneMockMvcBuilder>(print())
                .apply<StandaloneMockMvcBuilder>(
                    documentationConfiguration(restDocumentation)
                        .uris()
                        .withScheme("https")
                        .withHost("example.com")
                        .withPort(443)
                        .and()
                        .snippets()
                        .withDefaults(
                            curlRequest(),
                            httpRequest(),
                            httpResponse()
                        )
                        .and()
                        .operationPreprocessors()
                        .withResponseDefaults(prettyPrint())
                )

            if (!disableAuth) {
                mockMvcBuilder.apply<StandaloneMockMvcBuilder>(springSecurity(FakeOauthTokenFilter()))
            }

            return mockMvcBuilder.build()
        }
    }
}
