package com.magneto.gpt;

import org.junit.Test;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

/**
 * LLM 凭证与端点必须可以在不改仓库内 application.properties 的前提下替换：
 * token 属于机密，不能进版本控制；端点在 OpenAI 之外的兼容服务上必须可指向别处。
 */
public class GPTServerConfigTest {

    private static final String CLASSPATH_TOKEN = "classpath-token";
    private static final String ENV_TOKEN = "env-token";
    private static final String ENV_ENDPOINT = "https://api.deepseek.com/v1/chat/completions";

    private Properties classpathProps(String token) {
        Properties properties = new Properties();
        if (token != null) {
            properties.setProperty("gpt.access-token", token);
        }
        return properties;
    }

    private Map<String, String> env(String token, String endpoint) {
        Map<String, String> env = new HashMap<>();
        if (token != null) {
            env.put(GPTServer.TOKEN_ENV_VAR, token);
        }
        if (endpoint != null) {
            env.put(GPTServer.ENDPOINT_ENV_VAR, endpoint);
        }
        return env;
    }

    @Test
    public void tokenPrefersTheEnvironmentOverTheClasspathFile() {
        String token = GPTServer.resolveAccessToken(env(ENV_TOKEN, null), classpathProps(CLASSPATH_TOKEN));

        assertEquals(ENV_TOKEN, token);
    }

    @Test
    public void tokenFallsBackToTheClasspathFile() {
        String token = GPTServer.resolveAccessToken(Collections.<String, String>emptyMap(), classpathProps(CLASSPATH_TOKEN));

        assertEquals(CLASSPATH_TOKEN, token);
    }

    @Test
    public void tokenIsNullWhenNothingIsConfigured() {
        String token = GPTServer.resolveAccessToken(Collections.<String, String>emptyMap(), classpathProps(null));

        assertNull(token);
    }

    @Test
    public void aBlankEnvironmentTokenIsTreatedAsAbsent() {
        String token = GPTServer.resolveAccessToken(env("   ", null), classpathProps(CLASSPATH_TOKEN));

        assertEquals("a blank override must not shadow the configured token", CLASSPATH_TOKEN, token);
    }

    @Test
    public void anEnvironmentTokenIsTrimmed() {
        String token = GPTServer.resolveAccessToken(env("  " + ENV_TOKEN + "\n", null), classpathProps(null));

        assertEquals(ENV_TOKEN, token);
    }

    @Test
    public void endpointPrefersTheEnvironment() {
        String endpoint = GPTServer.resolveEndpoint(env(null, ENV_ENDPOINT));

        assertEquals(ENV_ENDPOINT, endpoint);
    }

    @Test
    public void endpointDefaultsToOpenAi() {
        String endpoint = GPTServer.resolveEndpoint(Collections.<String, String>emptyMap());

        assertEquals("https://api.openai.com/v1/chat/completions", endpoint);
    }

    @Test
    public void aBlankEnvironmentEndpointIsTreatedAsAbsent() {
        String endpoint = GPTServer.resolveEndpoint(env(null, "  "));

        assertEquals("https://api.openai.com/v1/chat/completions", endpoint);
    }
}
