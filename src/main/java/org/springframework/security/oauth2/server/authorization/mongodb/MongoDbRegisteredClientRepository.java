package org.springframework.security.oauth2.server.authorization.mongodb;

import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.List;
import java.util.Optional;

/**
 * Created on: 9/14/21.
 *
 * @author Bjorn Harvold Responsibility:
 */
public interface MongoDbRegisteredClientRepository extends MongoRepository<MongoDbOAuth2RegisteredClient, String> {
    /**
     * Find by client id optional.
     *
     * @param clientId the client id
     * @return the optional
     */
    Optional<MongoDbOAuth2RegisteredClient> findByClientId(String clientId);

}
