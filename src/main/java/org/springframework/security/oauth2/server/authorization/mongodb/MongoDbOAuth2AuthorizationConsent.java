package org.springframework.security.oauth2.server.authorization.mongodb;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.TypeAlias;
import org.springframework.data.mongodb.core.index.CompoundIndex;
import org.springframework.data.mongodb.core.index.CompoundIndexes;
import org.springframework.data.mongodb.core.mapping.Document;

/**
 * Created on: 9/13/21.
 *
 * @author Bjorn Harvold Responsibility:
 */
@TypeAlias("MongoDbOAuth2AuthorizationConsent")
@Document
@CompoundIndexes({
        @CompoundIndex(name = "primary_key", unique = true, def = "{'registeredClientId': 1, 'principalName': 1}")
})
@NoArgsConstructor
@AllArgsConstructor
@Data
public class MongoDbOAuth2AuthorizationConsent {
    @Id
    private String id;

    private String registeredClientId;

    private String principalName;

    private String authorities;
}
