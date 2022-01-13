package org.springframework.security.oauth2.server.authorization.mongodb;

import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;

/**
 * Created on: 9/13/21.
 *
 * @author Bjorn Harvold Responsibility:
 */
@RequiredArgsConstructor
@Component
public class MongoRegisteredClientRepository implements RegisteredClientRepository {
    private final MongoDbRegisteredClientRepository repository;

    @Override
    public void save(RegisteredClient registeredClient) {
        this.repository.save(from(registeredClient));
    }

    @Override
    public RegisteredClient findById(String id) {
        return this.repository.findById(id)
                .map(this::to)
                .orElse(null);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        return this.repository.findByClientId(clientId)
                .map(this::to)
                .orElse(null);
    }

    public RegisteredClient to(MongoDbOAuth2RegisteredClient client) {
        if (client == null) {
            return null;
        }

        final List<ClientAuthenticationMethod> methods = client.getClientAuthenticationMethods().stream()
                .map(this::resolveClientAuthenticationMethod)
                .toList();

        final List<AuthorizationGrantType> grantTypes = client.getAuthorizationGrantTypes().stream()
                .map(this::resolveAuthorizationGrantType)
                .toList();

        final ClientSettings clientSettings = ClientSettings.builder()
                .requireProofKey(client.getClientSettings().isRequireProofKey())
                .requireAuthorizationConsent(client.getClientSettings().isRequireAuthorizationConsent())
                .build();

        final org.springframework.security.oauth2.jose.jws.SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.from(client.getTokenSettings().getIdTokenSignatureAlgorithm().getName());

        final TokenSettings tokenSettings = TokenSettings.builder()
                .accessTokenTimeToLive(client.getTokenSettings().getAccessTokenTimeToLive())
                .reuseRefreshTokens(client.getTokenSettings().isReuseRefreshTokens())
                .refreshTokenTimeToLive(client.getTokenSettings().getRefreshTokenTimeToLive())
                .idTokenSignatureAlgorithm(signatureAlgorithm)
                .build();

        return RegisteredClient.withId(client.getId())
                .clientId(client.getClientId())
                .clientIdIssuedAt(client.getClientIdIssuedAt())
                .clientSecret(client.getClientSecret())
                .clientSecretExpiresAt(client.getClientSecretExpiresAt())
                .clientName(client.getClientName())
                .clientAuthenticationMethods(clientMethods ->
                        clientMethods.addAll(methods)
                )
                .authorizationGrantTypes(authorizationTypes ->
                        authorizationTypes.addAll(grantTypes)
                )
                .redirectUris(redirectUris -> redirectUris.addAll(client.getRedirectUris()))
                .scopes(scopes -> scopes.addAll(client.getScopes()))
                .clientSettings(clientSettings)
                .tokenSettings(tokenSettings)
                .build();
    }

    public MongoDbOAuth2RegisteredClient from(RegisteredClient registeredClient) {
        Instant clientIdIssuedAt = registeredClient.getClientIdIssuedAt() != null ?
                registeredClient.getClientIdIssuedAt() : Instant.now();

        Instant clientSecretExpiresAt = registeredClient.getClientSecretExpiresAt() != null ?
                registeredClient.getClientSecretExpiresAt() : null;

        final List<OAuth2ClientAuthenticationMethod> clientAuthenticationMethods = registeredClient.getClientAuthenticationMethods().stream()
                .map(this::resolveOauth2ClientAuthenticationMethod)
                .toList();

        final List<OAuth2AuthorizationGrantType> authorizationGrantTypes = registeredClient.getAuthorizationGrantTypes().stream()
                .map(this::resolveOauth2AuthorizationGrantType)
                .toList();

        final OAuth2ClientSettings clientSettings = new OAuth2ClientSettings(registeredClient.getClientSettings().isRequireProofKey(), registeredClient.getClientSettings().isRequireAuthorizationConsent());

        final MongoDbSignatureAlgorithm signatureAlgorithm = MongoDbSignatureAlgorithm.from(registeredClient.getTokenSettings().getIdTokenSignatureAlgorithm().getName());
        final OAuth2TokenSettings tokenSettings = new OAuth2TokenSettings(registeredClient.getTokenSettings().getAccessTokenTimeToLive(), registeredClient.getTokenSettings().isReuseRefreshTokens(), registeredClient.getTokenSettings().getRefreshTokenTimeToLive(), signatureAlgorithm);

        return new MongoDbOAuth2RegisteredClient(
                registeredClient.getId(),
                registeredClient.getClientId(),
                clientIdIssuedAt,
                registeredClient.getClientSecret(),
                clientSecretExpiresAt,
                registeredClient.getClientName(),
                clientAuthenticationMethods,
                authorizationGrantTypes,
                registeredClient.getRedirectUris(),
                registeredClient.getScopes(),
                clientSettings,
                tokenSettings
        );
    }


    private ClientAuthenticationMethod resolveClientAuthenticationMethod(OAuth2ClientAuthenticationMethod clientAuthenticationMethod) {
        if (ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue().equals(clientAuthenticationMethod.getValue())) {
            return ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
        } else if (ClientAuthenticationMethod.CLIENT_SECRET_POST.getValue().equals(clientAuthenticationMethod.getValue())) {
            return ClientAuthenticationMethod.CLIENT_SECRET_POST;
        } else if (ClientAuthenticationMethod.NONE.getValue().equals(clientAuthenticationMethod.getValue())) {
            return ClientAuthenticationMethod.NONE;
        }
        return new ClientAuthenticationMethod(clientAuthenticationMethod.getValue());        // Custom client authentication method
    }

    private OAuth2ClientAuthenticationMethod resolveOauth2ClientAuthenticationMethod(ClientAuthenticationMethod clientAuthenticationMethod) {
        if (OAuth2ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue().equals(clientAuthenticationMethod.getValue())) {
            return OAuth2ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
        } else if (OAuth2ClientAuthenticationMethod.CLIENT_SECRET_POST.getValue().equals(clientAuthenticationMethod.getValue())) {
            return OAuth2ClientAuthenticationMethod.CLIENT_SECRET_POST;
        } else if (OAuth2ClientAuthenticationMethod.NONE.getValue().equals(clientAuthenticationMethod.getValue())) {
            return OAuth2ClientAuthenticationMethod.NONE;
        }
        return OAuth2ClientAuthenticationMethod.NONE;        // Custom client authentication method
    }

    private AuthorizationGrantType resolveAuthorizationGrantType(OAuth2AuthorizationGrantType authorizationGrantType) {
        if (AuthorizationGrantType.AUTHORIZATION_CODE.getValue().equals(authorizationGrantType.getValue())) {
            return AuthorizationGrantType.AUTHORIZATION_CODE;
        } else if (AuthorizationGrantType.CLIENT_CREDENTIALS.getValue().equals(authorizationGrantType.getValue())) {
            return AuthorizationGrantType.CLIENT_CREDENTIALS;
        } else if (AuthorizationGrantType.REFRESH_TOKEN.getValue().equals(authorizationGrantType.getValue())) {
            return AuthorizationGrantType.REFRESH_TOKEN;
        }
        return new AuthorizationGrantType(authorizationGrantType.getValue());        // Custom authorization grant type
    }

    private OAuth2AuthorizationGrantType resolveOauth2AuthorizationGrantType(AuthorizationGrantType authorizationGrantType) {
        if (OAuth2AuthorizationGrantType.AUTHORIZATION_CODE.getValue().equals(authorizationGrantType.getValue())) {
            return OAuth2AuthorizationGrantType.AUTHORIZATION_CODE;
        } else if (OAuth2AuthorizationGrantType.CLIENT_CREDENTIALS.getValue().equals(authorizationGrantType.getValue())) {
            return OAuth2AuthorizationGrantType.CLIENT_CREDENTIALS;
        } else if (OAuth2AuthorizationGrantType.REFRESH_TOKEN.getValue().equals(authorizationGrantType.getValue())) {
            return OAuth2AuthorizationGrantType.REFRESH_TOKEN;
        }
        return OAuth2AuthorizationGrantType.PASSWORD;        // FYI this is different than the example so might be an issue
    }
}
