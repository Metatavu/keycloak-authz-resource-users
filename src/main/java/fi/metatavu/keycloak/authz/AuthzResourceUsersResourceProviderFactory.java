package fi.metatavu.keycloak.authz;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

/**
 * SPI Factory class for providingREST paths for authz resource users
 *
 * @author Antti Leppä
 */
public class AuthzResourceUsersResourceProviderFactory implements RealmResourceProviderFactory {

  public static final String ID = "authz-resource-users";

  @Override
  public String getId() {
    return ID;
  }

  @Override
  public int order() {
    return 0;
  }

  @Override
  public RealmResourceProvider create(KeycloakSession keycloakSession) {
    return new AuthzResourceUsersResourceProvider(keycloakSession);
  }

  @Override
  public void init(Config.Scope scope) {
  }

  @Override
  public void postInit(KeycloakSessionFactory keycloakSessionFactory) {
  }

  @Override
  public void close() {
  }
}