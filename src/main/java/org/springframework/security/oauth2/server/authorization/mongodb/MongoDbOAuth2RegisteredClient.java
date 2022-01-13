package org.springframework.security.oauth2.server.authorization.mongodb;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.TypeAlias;
import org.springframework.data.annotation.Version;
import org.springframework.data.mongodb.core.index.CompoundIndex;
import org.springframework.data.mongodb.core.index.CompoundIndexes;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;
import java.util.List;
import java.util.Set;

/**
 * Created on: 9/13/21.
 *
 * @author Bjorn Harvold Responsibility:
 */
@TypeAlias("OAuth2RegisteredClient")
@Document
@CompoundIndexes({
        @CompoundIndex(name = "find_by_client_id", def = "{'clientId': 1}")
})
@NoArgsConstructor
@AllArgsConstructor
@Data
public class MongoDbOAuth2RegisteredClient {

    @Id
    private String id;
    private String clientId;
    private Instant clientIdIssuedAt;
    private String clientSecret;
    private Instant clientSecretExpiresAt;
    private String clientName;
    private List<OAuth2ClientAuthenticationMethod> clientAuthenticationMethods;
    private List<OAuth2AuthorizationGrantType> authorizationGrantTypes;
    private Set<String> redirectUris;
    private Set<String> scopes;
    private OAuth2ClientSettings clientSettings;
    private OAuth2TokenSettings tokenSettings;

    @Version
    private Long version;

    /**
     * Instantiates a new O auth 2 registered client.
     *
     * @param id                          the id
     * @param clientId                    the client id
     * @param clientIdIssuedAt            the client id issued at
     * @param clientSecret                the client secret
     * @param clientSecretExpiresAt       the client secret expires at
     * @param clientName                  the client name
     * @param clientAuthenticationMethods the client authentication methods
     * @param authorizationGrantTypes     the authorization grant types
     * @param redirectUris                the redirect uris
     * @param scopes                      the scopes
     * @param clientSettings              the client settings
     * @param tokenSettings               the token settings
     */
    public MongoDbOAuth2RegisteredClient(String id,
                                         String clientId,
                                         Instant clientIdIssuedAt,
                                         String clientSecret,
                                         Instant clientSecretExpiresAt,
                                         String clientName,
                                         List<OAuth2ClientAuthenticationMethod> clientAuthenticationMethods,
                                         List<OAuth2AuthorizationGrantType> authorizationGrantTypes,
                                         Set<String> redirectUris,
                                         Set<String> scopes,
                                         OAuth2ClientSettings clientSettings,
                                         OAuth2TokenSettings tokenSettings) {
        this.id = id;
        this.clientId = clientId;
        this.clientIdIssuedAt = clientIdIssuedAt;
        this.clientSecret = clientSecret;
        this.clientSecretExpiresAt = clientSecretExpiresAt;
        this.clientName = clientName;
        this.clientAuthenticationMethods = clientAuthenticationMethods;
        this.authorizationGrantTypes = authorizationGrantTypes;
        this.redirectUris = redirectUris;
        this.scopes = scopes;
        this.clientSettings = clientSettings;
        this.tokenSettings = tokenSettings;
    }
}
