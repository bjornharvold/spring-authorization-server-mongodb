package org.springframework.security.oauth2.server.authorization.mongodb;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Created on: 9/13/21.
 *
 * @author Bjorn Harvold Responsibility:
 */
@NoArgsConstructor
@AllArgsConstructor
@Data
public class OAuth2ClientSettings {
    private boolean requireProofKey = false;
    private boolean requireAuthorizationConsent = false;
}
