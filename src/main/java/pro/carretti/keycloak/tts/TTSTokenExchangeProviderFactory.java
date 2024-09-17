package pro.carretti.keycloak.tts;

import java.io.IOException;
import org.jboss.logging.Logger;
import org.keycloak.Config.Scope;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.utils.PostMigrationEvent;
import org.keycloak.protocol.oidc.TokenExchangeProvider;
import org.keycloak.protocol.oidc.TokenExchangeProviderFactory;
import org.keycloak.protocol.oidc.representations.OIDCConfigurationRepresentation;

public class TTSTokenExchangeProviderFactory implements TokenExchangeProviderFactory {

    private static final String PROVIDER_ID = "transaction-token-service";
    private static final String ISSUER = "http://localhost:8080/realms/external";
    private static final String CLIENT = "frontend";
    private static final String WELL_KNOWN = "/.well-known/openid-configuration";
    private static final Logger LOG = Logger.getLogger(TTSTokenExchangeProviderFactory.class);

    private OIDCIdentityProviderConfig config;
    private String issuer;
    private String client;

    @Override
    public TokenExchangeProvider create(KeycloakSession session) {
        return new TTSTokenExchangeProvider(session, config);
    }

    @Override
    public void init(Scope scope) {
        this.issuer = scope.get("issuer", ISSUER);
        this.client = scope.get("client", CLIENT);
        this.config = new OIDCIdentityProviderConfig();
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        factory.register(event -> {
            if (event instanceof PostMigrationEvent postMigrationEvent) {
                setupAS(postMigrationEvent.getFactory());
            }
        });
    }

    private void setupAS(KeycloakSessionFactory factory) {
        try {
            KeycloakSession session = factory.create();
            String metadata = issuer + WELL_KNOWN;
            OIDCConfigurationRepresentation rep = SimpleHttp.doGet(metadata, session).asJson(OIDCConfigurationRepresentation.class);

            config.setIssuer(rep.getIssuer());
            config.setLogoutUrl(rep.getLogoutEndpoint());
            config.setAuthorizationUrl(rep.getAuthorizationEndpoint());
            config.setTokenUrl(rep.getTokenEndpoint());
            config.setUserInfoUrl(rep.getUserinfoEndpoint());
            if (rep.getJwksUri() != null) {
                config.setValidateSignature(true);
                config.setUseJwksUrl(true);
                config.setJwksUrl(rep.getJwksUri());
            }
            config.setClientId(client);
            LOG.debugv("IdP Config = {0}", config);
        } catch (IOException ex) {
            LOG.error("Failed to retrieve OIDC metadata", ex);
        }
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public int order() {
        return 100;
    }

}
