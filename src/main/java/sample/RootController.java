package sample;

import sample.saml.CertManager;
import sample.saml.SAMLAssertionBuilder;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.opensaml.xml.security.credential.Credential;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URLDecoder;

@RestController
public class RootController {
    private static final Logger log = LogManager.getLogger(RootController.class);

    private static final String PUBLICK_KEY_FILE_NAME = "certificate.crt";
    private static final String PRIVATE_KEY_FILE_NAME = "privateKey.pkcs8";
    private static final String SAML_POST_TEMPLATE = "SAMLPost.html";

    private static final String IDP_URL = "http://idppostexample.com";

    @RequestMapping("/samlpost")
    public void samlPost(@RequestParam("spURL") String spURL, @RequestParam("spEntity") String spEntity, @RequestParam String username,
                         @RequestParam(value = "goto", required = false) String state,
                         HttpServletResponse httpResponse) {

        // If you do not want to understand what is under the hood of this SAMLAssertionBuilder, this is how to use it.

        // Read the private key and public key of ceritificat with paths provided.
        // public key: certificate.crt, private key: privateKey.pkcs8
        final Credential credential = CertManager.getSigningCredential(RootController.class.getClassLoader().getResourceAsStream(PUBLICK_KEY_FILE_NAME), RootController.class.getClassLoader().getResourceAsStream(PRIVATE_KEY_FILE_NAME));

        // Create SAMLAssertionBuilder with IDP_URL (A endpoint for your system), created credential, spEntity (name of the other system), spURL (the endpoint of the other system).
        SAMLAssertionBuilder builder = new SAMLAssertionBuilder(IDP_URL, credential, spEntity, spURL);

        // Create the SAML respone by passing the authenticating username in your system
        final String encodedResponse = SAMLAssertionBuilder.encodeSAMLResponse(builder.buildResponse(username));

        // Return the web response with the above assertion
        try {
            // read respone template
            final String template = IOUtils.toString(RootController.class.getClassLoader().getResourceAsStream(SAML_POST_TEMPLATE), "UTF-8");
            final String targetURL = URLDecoder.decode(StringUtils.defaultString(state), "UTF-8");

            httpResponse.setStatus(HttpServletResponse.SC_OK);
            // fill in the template and return
            httpResponse.getWriter().println(String.format(template, spURL, encodedResponse, targetURL));
        } catch (IOException e) {
            log.error("Cannot read SAMLPost.html", e);
        }

            // In order to use this SAMLAssertionBuilder properly, you only need to provide the followin info
            // PUBLICK_KEY_FILE_NAME, e.g. certificate.crt
            // PRIVATE_KEY_FILE_NAME, e.g. privateKey.pkcs8
            // IDP_URL,               e.g. https://www.dpos.com/login
            // spURL,                 e.g. https://superservice.auth0.com/login/callback?connection=DPOS-QA
            // spEntity,              e.g. urn:auth0:superservice:NissanEU-QA
        }
}