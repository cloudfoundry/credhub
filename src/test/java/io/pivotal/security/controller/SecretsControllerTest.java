package io.pivotal.security.controller;

import io.pivotal.security.entity.Secret;
import io.pivotal.security.repository.SecretRepository;
import org.junit.Assert;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.mock.http.MockHttpOutputMessage;

import java.io.IOException;
import java.util.HashMap;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;


public class SecretsControllerTest extends HtmlUnitTestBase {

    @Autowired
    private HttpMessageConverter mappingJackson2HttpMessageConverter;

    @Autowired
    private SecretRepository secretRepository;

    @Test
    public void validPutSecret() throws Exception {
        HashMap<String, String> values = new HashMap<>();
        values.put("key1", "value1");
        Secret secret = new Secret(values);

        String secretJson = json(secret);

        mockMvc.perform(put("/api/secret/testid")
                .content(secretJson)
                .contentType(MediaType.APPLICATION_JSON_UTF8))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
                .andExpect(content().json(secretJson));

        Assert.assertEquals(secretRepository.get("testid"), secret);
    }

    @Test
    public void validGetSecret() throws Exception {
        HashMap<String, String> values = new HashMap<>();
        values.put("key1", "value1");
        Secret secret = new Secret(values);

        secretRepository.set("whatever", secret);

        String expectedJson = json(secret);

        mockMvc.perform(get("/api/secret/whatever"))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON_UTF8))
                .andExpect(content().json(expectedJson));
    }

    protected String json(Object o) throws IOException {
        MockHttpOutputMessage mockHttpOutputMessage = new MockHttpOutputMessage();
        this.mappingJackson2HttpMessageConverter.write(
                o, MediaType.APPLICATION_JSON, mockHttpOutputMessage);
        return mockHttpOutputMessage.getBodyAsString();
    }
}
