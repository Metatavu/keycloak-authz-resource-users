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
import org.keycloak.authorization.store.ScopeStore;
import org.keycloak.authorization.store.StoreFactory;
import org.keycloak.common.ClientConnection;
import org.keycloak.models.AdminRoles;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.ModelToRepresentation;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.idm.authorization.AuthorizationRequest;
import org.keycloak.representations.idm.authorization.Permission;
import org.keycloak.services.managers.AppAuthManager;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.resource.RealmResourceProvider;

import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

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
  public Response listResourceUsers(
    @Context HttpRequest request,
    @Context HttpHeaders headers,
    @Context ClientConnection clientConnection,
    @PathParam("clientId") String clientId,
    @PathParam("resourceId") String resourceId,
    @QueryParam("scopes") List<String> requestScopes,
    @QueryParam("search") String search,
    @QueryParam("first") Long first,
    @QueryParam("max") Long max
  ) {
    RealmModel realm = session.getContext().getRealm();

    AuthenticationManager.AuthResult auth = new AppAuthManager.BearerTokenAuthenticator(session)
      .setRealm(realm)
      .setConnection(clientConnection)
      .setHeaders(headers)
      .authenticate();

    if (auth == null || auth.getUser() == null || auth.getToken() == null) {
      return Response.status(Response.Status.UNAUTHORIZED)
        .entity("Unauthorized")
        .build();
    }

    Map<String, AccessToken.Access> resourceAccess = auth.getToken().getResourceAccess();
    AccessToken.Access realmManagementAccess = resourceAccess.get("realm-management");

    if (realmManagementAccess == null || !realmManagementAccess.isUserInRole(AdminRoles.QUERY_USERS)) {
      return Response.status(Response.Status.FORBIDDEN)
        .entity("Forbidden")
        .build();
    }

    AuthorizationProviderFactory authorizationProviderFactory = (AuthorizationProviderFactory) session.getKeycloakSessionFactory().getProviderFactory(AuthorizationProvider.class);
    AuthorizationProvider authorizationProvider = authorizationProviderFactory.create(session, realm);
    StoreFactory storeFactory = authorizationProvider.getStoreFactory();
    ResourceStore resourceStore = storeFactory.getResourceStore();
    ScopeStore scopeStore = storeFactory.getScopeStore();
    ResourceServerStore resourceServerStore = storeFactory.getResourceServerStore();
    ResourceServer resourceServer = resourceServerStore.findById(realm, clientId);
    if (resourceServer == null) {
      return Response.status(Response.Status.NOT_FOUND)
        .entity("Resource server not found")
        .build();
    }

    Resource resource = resourceStore.findById(realm, resourceServer, resourceId);
    if (resource == null) {
      return Response.status(Response.Status.NOT_FOUND)
        .entity("Resource not found")
        .build();
    }

    List<Scope> scopes = new ArrayList<>(requestScopes.size());
    for (String requestScope : requestScopes) {
      Scope scope = scopeStore.findByName(resourceServer, requestScope);
      if (scope == null) {
        return Response.status(Response.Status.BAD_REQUEST)
          .entity(String.format("Requested scope %s could not be found", requestScope))
          .build();
      }

      if (!resource.getScopes().contains(scope)) {
        return Response.status(Response.Status.BAD_REQUEST)
          .entity(String.format("Requested scope %s is not available on given resource", requestScope))
          .build();
      }

      scopes.add(scope);
    }

    Stream<UserModel> userStream = getUserStream(realm, search)
      .filter(user -> evaluateResource(authorizationProvider, resourceServer, realm, user, resource, scopes))
      .sorted(Comparator.comparing(UserModel::getId));

    if (first != null) {
      userStream = userStream.skip(first);
    }

    if (max != null) {
      userStream = userStream.limit(max);
    }

    return Response.ok(userStream.map(ModelToRepresentation::toBriefRepresentation))
        .build();
  }

  @POST
  @Path("/clients/{clientId}/resourceUserAccess")
  @Produces(MediaType.APPLICATION_JSON)
  @Consumes(MediaType.APPLICATION_JSON)
  @NoCache
  public Response queryResourceUsersAccess(
    @Context HttpRequest request,
    @Context HttpHeaders headers,
    @Context ClientConnection clientConnection,
    @PathParam("clientId") String clientId,
    AuthzResourceUsersAccessRequest authzResourceUsersRequest
  ) {
    RealmModel realm = session.getContext().getRealm();

    AuthenticationManager.AuthResult auth = new AppAuthManager.BearerTokenAuthenticator(session)
      .setRealm(realm)
      .setConnection(clientConnection)
      .setHeaders(headers)
      .authenticate();

    if (auth == null || auth.getUser() == null || auth.getToken() == null) {
      return Response.status(Response.Status.UNAUTHORIZED)
        .entity("Unauthorized")
        .build();
    }

    Map<String, AccessToken.Access> resourceAccess = auth.getToken().getResourceAccess();
    AccessToken.Access realmManagementAccess = resourceAccess.get("realm-management");

    if (realmManagementAccess == null || !realmManagementAccess.isUserInRole(AdminRoles.QUERY_USERS)) {
      return Response.status(Response.Status.FORBIDDEN)
        .entity("Forbidden")
        .build();
    }

    AuthorizationProviderFactory authorizationProviderFactory = (AuthorizationProviderFactory) session.getKeycloakSessionFactory().getProviderFactory(AuthorizationProvider.class);
    AuthorizationProvider authorizationProvider = authorizationProviderFactory.create(session, realm);
    StoreFactory storeFactory = authorizationProvider.getStoreFactory();
    ResourceStore resourceStore = storeFactory.getResourceStore();
    ScopeStore scopeStore = storeFactory.getScopeStore();
    ResourceServerStore resourceServerStore = storeFactory.getResourceServerStore();
    ResourceServer resourceServer = resourceServerStore.findById(realm, clientId);
    if (resourceServer == null) {
      return Response.status(Response.Status.NOT_FOUND)
        .entity("Resource server not found")
        .build();
    }

    List<String> userIds = authzResourceUsersRequest.getUserIds();
    List<String> resourceIds = authzResourceUsersRequest.getResourceIds();
    List<String> requestScopes = authzResourceUsersRequest.getScopes();

    List<AuthzResourceUserAccessResponse> response = new ArrayList<>();

    for (String userId : userIds) {
      UserModel user = session.users().getUserById(realm, userId);
      if (user == null) {
        continue;
      }

      for (String resourceId : resourceIds) {
        Resource resource = resourceStore.findById(realm, resourceServer, resourceId);
        if (resource == null) {
          continue;
        }
        
        List<String> allowedScopes = new ArrayList<>();
        for (String requestScope : requestScopes) {
          Scope scope = scopeStore.findByName(resourceServer, requestScope);
          if (scope == null) {
            continue;
          }
    
          if (!resource.getScopes().contains(scope)) {
            continue;
          }

          if (evaluateResource(authorizationProvider, resourceServer, realm, user, resource, List.of(scope))) {
            allowedScopes.add(requestScope);
          }
        }
        if (!allowedScopes.isEmpty()) {
          response.add(new AuthzResourceUserAccessResponse(userId, resourceId, allowedScopes));
        }
      }
    }

    return Response.ok(response).build();
  }

  /**
   * Returns stream to users
   *
   * @param realm realm
   * @param search search string (optional)
   * @return stream for matching users
   */
  private Stream<UserModel> getUserStream(RealmModel realm, String search) {
    if (search != null) {
      return session.users().searchForUserStream(realm, search);
    }

    return session.users().getUsersStream(realm, false);
  }

  /**
   * Evaluates whether user has permission to given resource
   *
   * @param authorizationProvider authorization provider
   * @param resourceServer resource server
   * @param realm realm
   * @param user user
   * @param resource resource
   * @param scopes scopes
   * @return whether user has permission to given resource
   */
  private boolean evaluateResource(AuthorizationProvider authorizationProvider, ResourceServer resourceServer, RealmModel realm, UserModel user, Resource resource, List<Scope> scopes) {
    Identity identity = new UserModelIdentity(realm, user);
    AuthorizationRequest request = new AuthorizationRequest();
    DecisionResultCollector decisionResultCollector = new DecisionResultCollector(authorizationProvider, resourceServer, request);
    List<String> requestedScopeNames = scopes.stream().map(scope -> scope.getName()).collect(Collectors.toList());

    Set<ResourcePermission> permissions;

    if (scopes == null || scopes.isEmpty()) {
      permissions = Collections.singleton(new ResourcePermission(resource, Collections.emptyList(), resourceServer));
    } else {
      permissions = scopes.stream()
        .map(scope -> new ResourcePermission(resource, Collections.singleton(scope), resourceServer))
        .collect(Collectors.toSet());
    }

    EvaluationContext evaluationContext = new DefaultEvaluationContext(identity, session);
    authorizationProvider.evaluators().from(permissions, evaluationContext).evaluate(decisionResultCollector);
    Map<ResourcePermission, Result> results = decisionResultCollector.getResults();
    return results.values().stream().anyMatch(evaluationResult -> {
      boolean permit = evaluationResult.getEffect().equals(Decision.Effect.PERMIT);
      boolean hasScopes = evaluationResult.getResults()
        .stream()
        .flatMap(res -> res.getPolicy().getScopes().stream())
        .map(scope -> scope.getName())
        .collect(Collectors.toList())
        .containsAll(requestedScopeNames);

      return permit && hasScopes;
    });
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

