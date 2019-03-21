package org.cloudfoundry.credhub.testhelpers

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.PropertyNamingStrategy.SNAKE_CASE
import org.cloudfoundry.credhub.handlers.FakeOauthTokenFilter
import org.cloudfoundry.credhub.util.TimeModuleFactory
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter
import org.springframework.restdocs.JUnitRestDocumentation
import org.springframework.restdocs.cli.CliDocumentation.curlRequest
import org.springframework.restdocs.http.HttpDocumentation.httpRequest
import org.springframework.restdocs.http.HttpDocumentation.httpResponse
import org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.documentationConfiguration
import org.springframework.restdocs.operation.preprocess.Preprocessors.prettyPrint
import org.springframework.restdocs.payload.PayloadDocumentation.requestBody
import org.springframework.restdocs.payload.PayloadDocumentation.responseBody
import org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.result.MockMvcResultHandlers.print
import org.springframework.test.web.servlet.setup.MockMvcBuilders
import org.springframework.test.web.servlet.setup.StandaloneMockMvcBuilder


class MockMvcFactory {
    companion object {
        private fun getPreconfiguredJacksonConverter() : MappingJackson2HttpMessageConverter {
            val converter = MappingJackson2HttpMessageConverter()
            val objectMapper = ObjectMapper()
                .registerModule(TimeModuleFactory.createTimeModule())
                .setPropertyNamingStrategy(SNAKE_CASE)

            converter.setObjectMapper(objectMapper)
            return converter
        }

        @JvmStatic
        fun newSpringRestDocMockMvc(controller: Any, restDocumentation: JUnitRestDocumentation): MockMvc {
            return MockMvcBuilders
                .standaloneSetup(controller)
                .setMessageConverters(getPreconfiguredJacksonConverter())
                .alwaysDo<StandaloneMockMvcBuilder>(print())
                .apply<StandaloneMockMvcBuilder>(springSecurity(FakeOauthTokenFilter()))
                .apply<StandaloneMockMvcBuilder>(
                    documentationConfiguration(restDocumentation)
                        .snippets()
                        .withDefaults(
                            curlRequest(),
                            httpRequest(),
                            httpResponse(),
                            requestBody(),
                            responseBody()
                        )
                        .and()
                        .operationPreprocessors()
                        .withResponseDefaults(prettyPrint())
                )
                .build()
        }
    }
}
