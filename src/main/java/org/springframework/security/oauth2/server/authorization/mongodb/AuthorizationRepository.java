package org.springframework.security.oauth2.server.authorization.mongodb;

import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Optional;

/**
 * Created on: 9/14/21.
 *
 * @author Bjorn Harvold Responsibility:
 */
public interface AuthorizationRepository extends MongoRepository<MongoDbOAuth2Authorization, String> {
    Optional<MongoDbOAuth2Authorization> findByState(String state);

    Optional<MongoDbOAuth2Authorization> findByAuthorizationCode(String authorizationCode);

    Optional<MongoDbOAuth2Authorization> findByAccessToken(String accessToken);

    Optional<MongoDbOAuth2Authorization> findByRefreshToken(String refreshToken);

    Optional<MongoDbOAuth2Authorization> findByStateOrAuthorizationCodeOrAccessTokenOrRefreshToken(String token);
}
