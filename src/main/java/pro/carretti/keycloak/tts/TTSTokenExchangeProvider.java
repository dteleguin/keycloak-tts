package pro.carretti.keycloak.tts;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.jboss.logging.Logger;

import org.keycloak.OAuth2Constants;
import org.keycloak.Token;
import org.keycloak.TokenCategory;
import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.common.util.Time;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureSignerContext;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.oidc.TokenExchangeContext;
import org.keycloak.protocol.oidc.TokenExchangeProvider;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.JsonWebToken;
import org.keycloak.services.Urls;
import org.keycloak.utils.OAuth2Error;

public class TTSTokenExchangeProvider implements TokenExchangeProvider {

    private static final Logger LOG = Logger.getLogger(TTSTokenExchangeProvider.class);
    private static final String TXN_TOKEN_REQUESTED_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:txn_token";
    private static final String TXN_TOKEN_TYPE = "txntoken+jwt";
    private static final String N_A = "N_A";
    private static final String TXN = "txn";
    private static final String PURP = "purp";
    private static final String REQUEST_CONTEXT = "request_context";
    private static final String REQUEST_DETAILS = "request_details";

    // TODO: configure
    private static final String ALLOWED_AUDIENCE = "http://trust-domain.example";
    // TODO: configure
    private static final long TXN_TOKEN_LIFESPAN = 5;

    private final KeycloakSession session;
    private final RealmModel realm;
    private final ClientModel client;
    private final OIDCIdentityProvider idp;

    private String audience;
    private String scope;

    public TTSTokenExchangeProvider(KeycloakSession session, OIDCIdentityProviderConfig config) {
        this.session = session;
        this.realm = session.getContext().getRealm();
        this.client = session.getContext().getClient();
        this.idp = new OIDCIdentityProvider(session, config);
        // TODO: event
    }

    @Override
    public boolean supports(TokenExchangeContext context) {
        String requestedTokenType = context.getParams().getRequestedTokenType();
        return TXN_TOKEN_REQUESTED_TOKEN_TYPE.equals(requestedTokenType);
    }

    @Override
    public Response exchange(TokenExchangeContext context) {
        TokenExchangeContext.Params params = context.getParams();

        LOG.debug("TTS::exchange");

        // REQUIRED
        this.audience = params.getAudience();
        this.scope = params.getScope();
        String subjectToken = params.getSubjectToken();
        String subjectTokenType = params.getSubjectTokenType();

        // OPTIONAL
        String requestContext = context.getFormParams().getFirst(REQUEST_CONTEXT);
        String requestDetails = context.getFormParams().getFirst(REQUEST_DETAILS);

        if (!OAuth2Constants.ACCESS_TOKEN_TYPE.equals(subjectTokenType)) {
            LOG.warnv("Subject token type not recognized: {0}", subjectTokenType);
            throw new OAuth2Error().invalidRequest("Subject token type not recognized: " + subjectTokenType);
        }

        if (!ALLOWED_AUDIENCE.equals(audience)) {
            LOG.warnv("Audience not allowed: ", audience);
            throw new OAuth2Error().invalidRequest("Audience not allowed: " + audience);
        }

        JsonWebToken jwt = this.idp.validateToken(subjectToken);
        AccessToken txnToken = createTxnToken(jwt);
        String txnTokenString = encode(txnToken);

        LOG.debug("TTS::exchange successful");
        return createResponse(txnTokenString);
    }

    private AccessToken createTxnToken(JsonWebToken jwt) {
        AccessToken token = new AccessToken();

        // REQUIRED
        token.issuedNow();
        token.exp(Time.currentTime() + TXN_TOKEN_LIFESPAN);
        token.audience(this.audience);
        token.setOtherClaims(TXN, KeycloakModelUtils.generateId());
        token.setSubject(client.getClientId());
        // TODO: getPurp()
        token.setOtherClaims(PURP, getPurp());

        // OPTIONAL
        String issuer = Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName());
        token.issuer(issuer);
        // TODO: azd
        // TODO: rctx

        return token;
    }

    private String encode(Token token) {
        String signatureAlgorithm = session.tokens().signatureAlgorithm(TokenCategory.ACCESS);
        SignatureProvider signatureProvider = session.getProvider(SignatureProvider.class, signatureAlgorithm);
        SignatureSignerContext signer = signatureProvider.signer();

        String encodedToken = new JWSBuilder().type(TXN_TOKEN_TYPE).jsonContent(token).sign(signer);
        return encodedToken;
    }

    private Response createResponse(String accessToken) {
        AccessTokenResponse tokenResponse = new TxnTokenResponse();
        tokenResponse.setTokenType(N_A);
        tokenResponse.setToken(accessToken);
        tokenResponse.setIdToken(null);
        tokenResponse.setRefreshToken(null);
        tokenResponse.getOtherClaims().clear();
        tokenResponse.getOtherClaims().put(OAuth2Constants.ISSUED_TOKEN_TYPE, TXN_TOKEN_REQUESTED_TOKEN_TYPE);
//        event.success();
        return Response.ok(tokenResponse).type(MediaType.APPLICATION_JSON_TYPE).build();
    }

    private String getPurp() {
        return scope;
        // TODO: validate & map
//        return switch (scope) {
//            case "scope1" -> "purp1";
//            default -> "default";
//        };
    }

    @Override
    public void close() {
    }

    @JsonIgnoreProperties({ "expires_in", "refresh_expires_in", "not-before-policy" })
    class TxnTokenResponse extends AccessTokenResponse {

    }

}
