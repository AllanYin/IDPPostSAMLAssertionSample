package Example;

import Example.saml.CertManager;
import Example.saml.SAMLAssertionBuilder;
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

    private static final String PUBLICK_KEY_FILE_NAME = "ifm.crt";
    private static final String PRIVATE_KEY_FILE_NAME = "ifm.pkcs8";
    private static final String SAML_POST_TEMPLATE = "SAMLPost.html";

    private static final Credential CREDENTIAL = CertManager.getSigningCredential(RootController.class.getClassLoader().getResourceAsStream(PUBLICK_KEY_FILE_NAME), RootController.class.getClassLoader().getResourceAsStream(PRIVATE_KEY_FILE_NAME));
    private static final String IDP_URL = "http://idppostexample.com";

    @RequestMapping("/samlpost")
    public void samlPost(@RequestParam("spURL") String spURL, @RequestParam("spEntity") String spEntity, @RequestParam String username,
                         @RequestParam(value = "goto", required = false) String state,
                         HttpServletResponse httpResponse) {

        SAMLAssertionBuilder builder = new SAMLAssertionBuilder(IDP_URL, CREDENTIAL, spEntity, spURL);
        final String encodedResponse = SAMLAssertionBuilder.encodeSAMLResponse(builder.buildResponse(username));

        try {
            final String template = IOUtils.toString(RootController.class.getClassLoader().getResourceAsStream(SAML_POST_TEMPLATE), "UTF-8");
            final String targetURL = URLDecoder.decode(StringUtils.defaultString(state), "UTF-8");

            httpResponse.setStatus(HttpServletResponse.SC_OK);
            httpResponse.getWriter().println(String.format(template, spURL, encodedResponse, targetURL));
        } catch (IOException e) {
            log.error("Cannot read SAMLPost.html", e);
        }
    }
}