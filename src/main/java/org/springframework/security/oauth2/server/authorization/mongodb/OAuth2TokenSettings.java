package org.springframework.security.oauth2.server.authorization.mongodb;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Duration;

/**
 * Created on: 9/13/21.
 *
 * @author Bjorn Harvold Responsibility:
 */
@NoArgsConstructor
@AllArgsConstructor
@Data
public class OAuth2TokenSettings {
    private Duration accessTokenTimeToLive;
    private boolean reuseRefreshTokens = true;
    private Duration refreshTokenTimeToLive;
    private MongoDbSignatureAlgorithm idTokenSignatureAlgorithm;
}
