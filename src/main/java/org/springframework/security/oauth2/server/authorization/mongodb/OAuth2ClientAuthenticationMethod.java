package org.springframework.security.oauth2.server.authorization.mongodb;

/**
 * Created on: 9/13/21.
 *
 * @author Bjorn Harvold Responsibility:
 */
public enum OAuth2ClientAuthenticationMethod {
    /**
     * Client secret basic o auth 2 client authentication method.
     */
    CLIENT_SECRET_BASIC("client_secret_basic"),
    /**
     * Client secret post o auth 2 client authentication method.
     */
    CLIENT_SECRET_POST("client_secret_post"),
    /**
     * Client secret jwt o auth 2 client authentication method.
     */
    CLIENT_SECRET_JWT("client_secret_jwt"),
    /**
     * Private key jwt o auth 2 client authentication method.
     */
    PRIVATE_KEY_JWT("private_key_jwt"),
    /**
     * None o auth 2 client authentication method.
     */
    NONE("none");

    private final String value;

    OAuth2ClientAuthenticationMethod(String value) {
        this.value = value;
    }

    /**
     * Gets value.
     *
     * @return the value
     */
    public String getValue() {
        return value;
    }
}
