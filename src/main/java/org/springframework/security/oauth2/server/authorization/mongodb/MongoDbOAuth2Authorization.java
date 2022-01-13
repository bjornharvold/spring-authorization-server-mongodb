package org.springframework.security.oauth2.server.authorization.mongodb;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.TypeAlias;
import org.springframework.data.mongodb.core.index.CompoundIndex;
import org.springframework.data.mongodb.core.index.CompoundIndexes;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;

/**
 * Created on: 9/13/21.
 *
 * @author Bjorn Harvold Responsibility:
 */
@TypeAlias("MongoDbOAuth2Authorization")
@Document
@CompoundIndexes({
        @CompoundIndex(name = "find_by_state", unique = true, def = "{'state': 1}"),
        @CompoundIndex(name = "find_by_authorization_code", unique = true, def = "{'authorizationCode': 1}"),
        @CompoundIndex(name = "find_by_access_token", unique = true, def = "{'accessToken': 1}"),
        @CompoundIndex(name = "find_by_refresh_token", unique = true, def = "{'refreshToken': 1}"),
        @CompoundIndex(name = "find_by_all_keys", unique = true, def = "{'state': 1, 'authorizationCode': 1, 'accessToken': 1, 'refreshToken': 1}")
})
@NoArgsConstructor
@AllArgsConstructor
@Data
public class MongoDbOAuth2Authorization {
    @Id
    private String id;
    private String registeredClientId;
    private String principalName;
    private String authorizationGrantType;
    private String attributes;
    private String state;
    private String authorizationCode;
    private Instant authorizationCodeIssuedAt;
    private Instant authorizationCodeExpiresAt;
    private String authorizationCodeMetadata;
    private String accessToken;
    private Instant accessTokenIssuedAt;
    private Instant accessTokenExpiresAt;
    private String accessTokenMetadata;
    private String accessTokenScopes;
    private String refreshToken;
    private Instant refreshTokenIssuedAt;
    private Instant refreshTokenExpiresAt;
    private String refreshTokenMetadata;
    private String idToken;
    private Instant idTokenIssuedAt;
    private Instant idTokenExpiresAt;
    private String idTokenMetadata;
    private String idTokenClaims;
}
