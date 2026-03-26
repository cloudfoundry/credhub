package org.cloudfoundry.credhub.helpers

import org.cloudfoundry.credhub.generate.ExceptionHandlers
import org.cloudfoundry.credhub.util.TimeModuleFactory
import org.springframework.http.converter.json.JacksonJsonHttpMessageConverter
import org.springframework.restdocs.ManualRestDocumentation
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
import tools.jackson.databind.PropertyNamingStrategies
import tools.jackson.databind.json.JsonMapper
import tools.jackson.module.kotlin.KotlinModule

class MockMvcFactory {
    companion object {
        private fun getPreconfiguredJacksonConverter(): JacksonJsonHttpMessageConverter {
            val objectMapper =
                JsonMapper
                    .builder()
                    .addModule(TimeModuleFactory.createTimeModule())
                    .addModule(KotlinModule.Builder().build())
                    .propertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE)
                    .build()
            return JacksonJsonHttpMessageConverter(objectMapper)
        }

        @JvmStatic
        fun newSpringRestDocMockMvc(
            controller: Any,
            restDocumentation: ManualRestDocumentation,
            disableAuth: Boolean = false,
        ): MockMvc {
            val mockMvcBuilder =
                MockMvcBuilders
                    .standaloneSetup(controller)
                    .setControllerAdvice(ExceptionHandlers())
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
                                httpResponse(),
                            ).and()
                            .operationPreprocessors()
                            .withResponseDefaults(prettyPrint()),
                    )

            if (!disableAuth) {
                mockMvcBuilder.apply<StandaloneMockMvcBuilder>(springSecurity(FakeOauthTokenFilter()))
            }

            return mockMvcBuilder.build()
        }
    }
}
