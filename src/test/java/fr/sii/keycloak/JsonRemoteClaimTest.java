package fr.sii.keycloak;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.ws.rs.client.Invocation;
import javax.ws.rs.core.Response;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class JsonRemoteClaimTest {
    private final Map<String, String> parameters = new HashMap<>();
    private final Map<String, String> headers = new HashMap<>();
    private String url;

    @BeforeEach
    void setUp() {
        parameters.clear();
        parameters.put("username", "dev");
        headers.clear();
        url = "http://10.11.34.30:6666/pup_p_rest_service_dbg/auth";
    }

    @Test
    void makeInvocationBuilder() {
        assertNotNull(JsonRemoteClaim.makeInvocationBuilder(parameters, headers, url));
    }

    @Test
    void parseResponse() {
        System.out.println("parseResponse");
        final Invocation.Builder builder = JsonRemoteClaim.makeInvocationBuilder(parameters, headers, url);
        assertNotNull(builder);
        final Response response = builder.get();
        assertNotNull(JsonRemoteClaim.parseResponse(response));
    }
}