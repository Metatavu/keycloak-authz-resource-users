package fi.metatavu.keycloak.authz;

import org.jboss.resteasy.annotations.cache.NoCache;
import org.jboss.resteasy.spi.HttpRequest;
import org.keycloak.authorization.AuthorizationProvider;
import org.keycloak.authorization.AuthorizationProviderFactory;
import org.keycloak.authorization.Decision;
import org.keycloak.authorization.common.DefaultEvaluationContext;
import org.keycloak.authorization.common.UserModelIdentity;
import org.keycloak.authorization.identity.Identity;
import org.keycloak.authorization.model.Resource;
import org.keycloak.authorization.model.ResourceServer;
import org.keycloak.authorization.model.Scope;
import org.keycloak.authorization.permission.ResourcePermission;
import org.keycloak.authorization.policy.evaluation.EvaluationContext;
import org.keycloak.authorization.policy.evaluation.Result;
import org.keycloak.authorization.store.ResourceServerStore;
import org.keycloak.authorization.store.ResourceStore;
import org.keycloak.authorization.store.StoreFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.representations.idm.authorization.AuthorizationRequest;
import org.keycloak.representations.idm.authorization.Permission;
import org.keycloak.services.resource.RealmResourceProvider;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Class for providing REST paths for authz resource users
 *
 * @author Antti Leppä
 */
public class AuthzResourceUsersResourceProvider implements RealmResourceProvider {

  private final KeycloakSession session;

  public AuthzResourceUsersResourceProvider(KeycloakSession session) {
    this.session = session;
  }

  @Override
  public Object getResource() {
    return this;
  }

  @GET
  @Path("/clients/{clientId}/resource/{resourceId}/users")
  @Produces(MediaType.APPLICATION_JSON)
  @NoCache
  public Response getCerts(@Context HttpRequest request, @PathParam("clientId") String clientId, @PathParam("resourceId") String resourceId) {
    RealmModel realm = session.getContext().getRealm();

    AuthorizationProviderFactory authorizationProviderFactory = (AuthorizationProviderFactory) session.getKeycloakSessionFactory().getProviderFactory(AuthorizationProvider.class);
    AuthorizationProvider authorizationProvider = authorizationProviderFactory.create(session, realm);
    StoreFactory storeFactory = authorizationProvider.getStoreFactory();
    ResourceStore resourceStore = storeFactory.getResourceStore();
    ResourceServerStore resourceServerStore = storeFactory.getResourceServerStore();
    ResourceServer resourceServer = resourceServerStore.findById(clientId);
    if (resourceServer == null) {
      return Response.status(Response.Status.NOT_FOUND)
        .entity("Resource server not found")
        .build();
    }

    Resource resource = resourceStore.findById(resourceId, resourceServer.getId());
    if (resource == null) {
      return Response.status(Response.Status.NOT_FOUND)
        .entity("Resource not found")
        .build();
    }

    List<UserModel> users = session.users().getUsersStream(realm, false)
      .filter(user -> evaluateResource(authorizationProvider, resourceServer, realm, user, resource))
      .collect(Collectors.toList());

    return Response.ok(users.stream().map(UserModel::getId).collect(Collectors.toList())).build();
  }

  /**
   * Evaluates whether user has permission to given resource
   *
   * @param authorizationProvider authorization provider
   * @param resourceServer resource server
   * @param realm realm
   * @param user user
   * @param resource resource
   * @return whether user has permission to given resource
   */
  private boolean evaluateResource(AuthorizationProvider authorizationProvider, ResourceServer resourceServer, RealmModel realm, UserModel user, Resource resource) {
    Identity identity = new UserModelIdentity(realm, user);
    AuthorizationRequest request = new AuthorizationRequest();
    DecisionResultCollector decisionResultCollector = new DecisionResultCollector(authorizationProvider, resourceServer, request);
    ResourcePermission permission = new ResourcePermission(resource, Collections.emptyList(), resourceServer);


    EvaluationContext evaluationContext = new DefaultEvaluationContext(identity, session);
    authorizationProvider.evaluators().from(Collections.singleton(permission), evaluationContext).evaluate(decisionResultCollector);

    Map<ResourcePermission, Result> results = decisionResultCollector.getResults();
    if (!results.containsKey(permission)) {
      return false;
    }

    return results.values().stream().noneMatch(evaluationResult -> evaluationResult.getEffect().equals(Decision.Effect.DENY));
  }

  @Override
  public void close() {
  }

  /**
   * DecisionResultCollector implementation
   */
  private static class DecisionResultCollector extends org.keycloak.authorization.policy.evaluation.DecisionPermissionCollector {

    /**
     * Constructor
     *
     * @param authorizationProvider authorization provider
     * @param resourceServer resource server
     * @param request authorization request
     */
    public DecisionResultCollector(AuthorizationProvider authorizationProvider, ResourceServer resourceServer, AuthorizationRequest request) {
      super(authorizationProvider, resourceServer, request);
    }

    @Override
    protected boolean isGranted(Result.PolicyResult policyResult) {
      if (super.isGranted(policyResult)) {
        policyResult.setEffect(Effect.PERMIT);
        return true;
      }
      return false;
    }

    @Override
    protected void grantPermission(AuthorizationProvider authorizationProvider, Set<Permission> permissions, ResourcePermission permission, Collection<Scope> grantedScopes, ResourceServer resourceServer, AuthorizationRequest request, Result result) {
      result.setStatus(Effect.PERMIT);
      result.getPermission().getScopes().retainAll(grantedScopes);
      super.grantPermission(authorizationProvider, permissions, permission, grantedScopes, resourceServer, request, result);
    }

    /**
     * Returns result map
     *
     * @return result map
     */
    public Map<ResourcePermission, Result> getResults() {
      return results;
    }
  }

}

