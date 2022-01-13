package org.springframework.security.oauth2.server.authorization.mongodb;

import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.Optional;

/**
 * Created on: 9/14/21.
 *
 * @author Bjorn Harvold Responsibility:
 */
public interface AuthorizationConsentRepository extends MongoRepository<MongoDbOAuth2AuthorizationConsent, String> {
    /**
     * Find by registered client id and principal name optional.
     *
     * @param registeredClientId the registered client id
     * @param principalName      the principal name
     * @return the optional
     */
    Optional<MongoDbOAuth2AuthorizationConsent> findByRegisteredClientIdAndPrincipalName(String registeredClientId, String principalName);

    /**
     * Delete by registered client id and principal name.
     *
     * @param registeredClientId the registered client id
     * @param principalName      the principal name
     */
    void deleteByRegisteredClientIdAndPrincipalName(String registeredClientId, String principalName);
}
