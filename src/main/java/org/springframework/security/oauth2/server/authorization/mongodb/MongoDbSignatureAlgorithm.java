package org.springframework.security.oauth2.server.authorization.mongodb;

/**
 * Created on: 1/4/22.
 *
 * @author Bjorn Harvold
 * Responsibility:
 */
public enum MongoDbSignatureAlgorithm {
    RS256("RS256"),
    RS384("RS384"),
    RS512("RS512"),
    ES256("ES256"),
    ES384("ES384"),
    ES512("ES512"),
    PS256("PS256"),
    PS384("PS384"),
    PS512("PS512");

    private final String name;

    MongoDbSignatureAlgorithm(String name) {
        this.name = name;
    }

    public String getName() {
        return this.name;
    }

    public static MongoDbSignatureAlgorithm from(String name) {
        MongoDbSignatureAlgorithm[] var1 = values();

        for (MongoDbSignatureAlgorithm value : var1) {
            if (value.getName().equals(name)) {
                return value;
            }
        }

        return null;
    }
}
