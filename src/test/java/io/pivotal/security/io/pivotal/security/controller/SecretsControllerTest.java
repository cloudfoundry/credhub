package io.pivotal.security.io.pivotal.security.controller;

import org.junit.Test;
import org.springframework.http.MediaType;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;


public class SecretsControllerTest extends HtmlUnitTestBase {

    @Test
    public void validPutSecret() throws Exception {

        String request = "{ \"values\": { \"key1\": \"value1\" }}";
        mockMvc.perform(put("/api/secret/testid").content(request))
                .andExpect(status().isCreated())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
                .andExpect(content().string(request));
    }

}


