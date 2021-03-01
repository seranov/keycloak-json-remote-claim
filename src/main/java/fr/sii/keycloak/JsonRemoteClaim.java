package fr.sii.keycloak;

import com.fasterxml.jackson.databind.JsonNode;
import org.jboss.resteasy.plugins.providers.RegisterBuiltin;
import org.jboss.resteasy.plugins.providers.jackson.ResteasyJackson2Provider;
import org.jboss.resteasy.spi.ResteasyProviderFactory;
import org.keycloak.models.*;
import org.keycloak.protocol.oidc.mappers.*;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.representations.IDToken;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Invocation;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * @author <a href="mailto:ni.roussel@gmail.com">Nicolas Roussel</a>
 * @version $Revision: 1 $
 */
public class JsonRemoteClaim extends AbstractOIDCProtocolMapper implements OIDCAccessTokenMapper, OIDCIDTokenMapper, UserInfoTokenMapper {

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    private final static String REMOTE_URL = "remote.url";
    private final static String REMOTE_HEADERS = "remote.headers";
    private final static String REMOTE_PARAMETERS = "remote.parameters";
    private final static String REMOTE_PARAMETERS_USERNAME = "remote.parameters.username";
    private final static String REMOTE_PARAMETERS_CLIENTID = "remote.parameters.clientid";

    private static Client client = ClientBuilder.newClient();

    /**
     * Inner configuration to cache retrieved authorization for multiple tokens
     */
    private final static String REMOTE_AUTHORIZATION_ATTR = "remote-authorizations";

    /*
     * ID of the token mapper.
     * Must be public
     */
    public final static String PROVIDER_ID = "json-remote-claim";

    static {
        OIDCAttributeMapperHelper.addIncludeInTokensConfig(configProperties, JsonRemoteClaim.class);
        OIDCAttributeMapperHelper.addTokenClaimNameConfig(configProperties);

        ProviderConfigProperty property;

        // Username
        property = new ProviderConfigProperty();
        property.setName(REMOTE_PARAMETERS_USERNAME);
        property.setLabel("Send user name");
        property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        property.setHelpText("Send the username as query parameter (param: username).");
        property.setDefaultValue("true");
        configProperties.add(property);

        // Client_id
        property = new ProviderConfigProperty();
        property.setName(REMOTE_PARAMETERS_CLIENTID);
        property.setLabel("Send client ID");
        property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        property.setHelpText("Send the client_id as query parameter (param: client_id).");
        property.setDefaultValue("false");
        configProperties.add(property);

        // URL
        property = new ProviderConfigProperty();
        property.setName(REMOTE_URL);
        property.setLabel("URL");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("Full URL of the remote service endpoint.");
        configProperties.add(property);

        // Parameters
        property = new ProviderConfigProperty();
        property.setName(REMOTE_PARAMETERS);
        property.setLabel("Parameters");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("List of query parameters to send separated by '&'. Separate parameter name and value by an equals sign '=', the value can contain equals signs (ex: scope=all&full=true).");
        configProperties.add(property);

        // Headers
        property = new ProviderConfigProperty();
        property.setName(REMOTE_HEADERS);
        property.setLabel("Headers");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("List of headers to send separated by '&'. Separate header name and value by an equals sign '=', the value can contain equals signs (ex: Authorization=az89d).");
        configProperties.add(property);

        // jsonType.label
        property = new ProviderConfigProperty();
        property.setName(OIDCAttributeMapperHelper.JSON_TYPE);
        property.setLabel(OIDCAttributeMapperHelper.JSON_TYPE);
        property.setType("");
        property.setHelpText("Must be ");
        configProperties.add(property);
    }

    @Override
    public String getDisplayCategory() {
        return "Token mapper";
    }

    @Override
    public String getDisplayType() {
        return "JSON Remote claim";
    }

    @Override
    public String getHelpText() {
        return "Retrieve JSON data to include from a remote HTTP endpoint.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession, KeycloakSession keycloakSession, ClientSessionContext clientSessionCtx) {
        JsonNode claims = clientSessionCtx.getAttribute(REMOTE_AUTHORIZATION_ATTR, JsonNode.class);
        if (claims == null) {
            claims = getRemoteAuthorizations(mappingModel, userSession);
            clientSessionCtx.setAttribute(REMOTE_AUTHORIZATION_ATTR, claims);
        }

        {
            mappingModel.getConfig().put(OIDCAttributeMapperHelper.JSON_TYPE, "JSON");
            mappingModel.getConfig().put(OIDCAttributeMapperHelper.TOKEN_CLAIM_NAME,
                    JsonRemoteClaim.class.getSimpleName());
        }

        /*System.out.println("Before mapClaim: token=" + token.toString() +
                "; token.size=" + token.getOtherClaims().keySet().size() +
                "; mappingModel=" + mappingModel.toString() +
                "; claims=" + claims.toPrettyString());
        mappingModel.getConfig().forEach((key, value) -> System.out.println("mappingModel.getConfig: " + key + "=" + value));
        token.getOtherClaims().forEach((key, value) -> System.out.println("token.getOtherClaims before: " + key + "=" + value));*/
        OIDCAttributeMapperHelper.mapClaim(token, mappingModel, claims);
        /*System.out.println("After mapClaim: token.size=" + token.getOtherClaims().keySet().size());
        token.getOtherClaims().forEach((key, value) -> System.out.println("token.getOtherClaims after: " + key + "=" + value));*/
    }

    /**
     * Deprecated, added for older versions
     * <p>
     * Caution: This version does not allow to minimize request number
     *
     * @deprecated override {@link #setClaim(IDToken, ProtocolMapperModel, UserSessionModel, KeycloakSession, ClientSessionContext)} instead.
     */
    @Override
    protected void setClaim(IDToken token, ProtocolMapperModel mappingModel, UserSessionModel userSession) {
        JsonNode claims = getRemoteAuthorizations(mappingModel, userSession);
        OIDCAttributeMapperHelper.mapClaim(token, mappingModel, claims);
    }

    private Map<String, String> getQueryParameters(ProtocolMapperModel mappingModel, UserSessionModel userSession) {
        final String configuredParameter = mappingModel.getConfig().get(REMOTE_PARAMETERS);
        final boolean sendUsername = "true".equals(mappingModel.getConfig().get(REMOTE_PARAMETERS_USERNAME));
        final boolean sendClientID = "true".equals(mappingModel.getConfig().get(REMOTE_PARAMETERS_CLIENTID));

        // Get parameters
        final Map<String, String> formattedParameters = buildMapFromStringConfig(configuredParameter);

        // Get client ID
        if (sendClientID) {
            String clientID = userSession.getAuthenticatedClientSessions().values().stream()
                    .map(AuthenticatedClientSessionModel::getClient)
                    .map(ClientModel::getClientId)
                    .distinct()
                    .collect(Collectors.joining(","));
            formattedParameters.put("client_id", clientID);
        }

        // Get username
        if (sendUsername) {
            formattedParameters.put("username", userSession.getLoginUsername());
        }

        return formattedParameters;
    }

    private Map<String, String> getheaders(ProtocolMapperModel mappingModel, UserSessionModel userSession) {
        final String configuredHeaders = mappingModel.getConfig().get(REMOTE_HEADERS);

        // Get headers
        return buildMapFromStringConfig(configuredHeaders);
    }

    private Map<String, String> buildMapFromStringConfig(String config) {
        final Map<String, String> map = new HashMap<>();

        //FIXME: using MULTIVALUED_STRING_TYPE would be better but it doesn't seem to work
        if (config != null && !"".equals(config.trim())) {
            String[] configList = config.trim().split("&");
            String[] keyValue;
            for (String configEntry : configList) {
                keyValue = configEntry.split("=", 2);
                if (keyValue.length == 2) {
                    map.put(keyValue[0], keyValue[1]);
                }
            }
        }

        return map;
    }

    private static void registerResteasyJackson2Provider() {
        final ResteasyProviderFactory instance = ResteasyProviderFactory.getInstance();
        RegisterBuiltin.register(instance);
        instance.registerProvider(ResteasyJackson2Provider.class);
    }

    static Invocation.Builder makeInvocationBuilder(final Map<String, String> parameters,
                                                    final Map<String, String> headers,
                                                    final String url) {
        Invocation.Builder res;

        final StringBuilder sbWebServiceMakeLog = new StringBuilder("JsonRemoteClaim.getRemoteAuthorizations: url=");

        // Call remote service
        final Response response;
        try {
            WebTarget target = client.target(url);
            sbWebServiceMakeLog.append(url).append("; queryParams={");
            // Build parameters
            for (final Map.Entry<String, String> param : parameters.entrySet()) {
                target = target.queryParam(param.getKey(), param.getValue());
                sbWebServiceMakeLog.append(param.getKey()).append("=").append(param.getValue()).append(", ");
            }
            sbWebServiceMakeLog.append("}; headers={");
            Invocation.Builder builder = target.request(MediaType.APPLICATION_JSON);
            // Build headers
            for (final Map.Entry<String, String> header : headers.entrySet()) {
                builder = builder.header(header.getKey(), header.getValue());
                sbWebServiceMakeLog.append(header.getKey()).append("=").append(header.getValue()).append(", ");
            }
            sbWebServiceMakeLog.append("}");
            System.out.println(sbWebServiceMakeLog.toString());
            res = builder;
        } catch (RuntimeException e) {
            // exceptions are thrown to prevent token from being delivered without all information
            throw new JsonRemoteClaimException("Error when accessing remote claim", url, e);
        }
        return res;
    }

    static JsonNode parseResponse(final Response response) {
        registerResteasyJackson2Provider();
        //System.out.println("Response: " + response.readEntity(String.class));
        final JsonNode jsonNode = response.readEntity(JsonNode.class);
        System.out.println("Response: " + jsonNode.toPrettyString());
        return jsonNode;
    }

    private JsonNode getRemoteAuthorizations(final ProtocolMapperModel mappingModel, final UserSessionModel userSession) {
        // Call remote service
        final String url = mappingModel.getConfig().get(REMOTE_URL);
        // Get parameters
        final Map<String, String> parameters = getQueryParameters(mappingModel, userSession);
        // Get headers
        final Map<String, String> headers = getheaders(mappingModel, userSession);
        final Invocation.Builder builder = makeInvocationBuilder(parameters, headers, url);
        final Response response = builder.get();

        // Check response status
        if (response.getStatus() != 200) {
            response.close();
            throw new JsonRemoteClaimException("Wrong status received for remote claim - Expected: 200, Received: " +
                    response.getStatus(), url);
        }

        // Bind JSON response
        try {
            return parseResponse(response);
        } catch (RuntimeException e) {
            // exceptions are thrown to prevent token from being delivered without all information
            throw new JsonRemoteClaimException("Error when parsing response for remote claim", url, e);
        } finally {
            response.close();
        }
    }
}