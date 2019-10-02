package sample.saml;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.joda.time.DateTime;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.core.impl.*;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.schema.impl.XSStringBuilder;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.signature.impl.SignatureBuilder;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;

import java.io.ByteArrayOutputStream;
import java.util.Base64;
import java.util.UUID;


public class SAMLAssertionBuilder {
    private static final Logger log = LogManager.getLogger(SAMLAssertionBuilder.class);

    public static final int VALID_NOT_BEFORE_IN_SECONDS = 10 * 60;
    public static final int VALID_NOT_AFTER_IN_SECONDS = 2 * 60 * 60;
    private static final String SIGNATURE_SIGN_ALGO = SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1;

    private static final String USER_ID_ATTRIBUTE_NAME = "user_id";

    static {
        try {
            DefaultBootstrap.bootstrap();
        } catch (ConfigurationException e) {
            log.error("Cannot init SAML Engine", e);
        }

    }

    // current website's URL
    private String idpURL;
    private Credential credential;

    private String spEntity;
    private String spURL;

    public SAMLAssertionBuilder(String idpURL, Credential credential, String spEntity, String spURL) {
        this.idpURL = idpURL;
        this.credential = credential;

        this.spEntity = spEntity;
        this.spURL = spURL;
    }

    public Response buildResponse(final String username) {
        ResponseBuilder responseBuilder = new ResponseBuilder();
        Response response = responseBuilder.buildObject();
        response.setDestination(spURL);
        response.setID(UUID.randomUUID().toString());
        response.setIssueInstant(new DateTime());
        response.setVersion(SAMLVersion.VERSION_20);
        response.setIssuer(getIssuer());
        response.setStatus(buildStatus());
        Assertion assertion = buildAssertion(username);
        response.getAssertions().add(assertion);
        Signature signature = buildSignature();
        response.setSignature(signature);

        try {
            new ResponseMarshaller().marshall(response);
            Signer.signObject(signature);
        } catch (Exception e) {
            log.error("Cannot sign SAML assertion", e);
        }

        return response;
    }

    private Assertion buildAssertion(final String username) {
        DateTime issueInstance = new DateTime();

        AssertionBuilder assertionBuilder = new AssertionBuilder();
        Assertion assertion = assertionBuilder.buildObject();
        assertion.setID(UUID.randomUUID().toString());
        assertion.setIssueInstant(issueInstance);
        assertion.setIssuer(getIssuer());
        assertion.setConditions(buildConditions(issueInstance));
        assertion.setSubject(buildSubject(issueInstance));
        assertion.getAuthnStatements().add(buildAuthnStatement(issueInstance));
        assertion.getAttributeStatements().add(buildAttributeStatement(username));

        return assertion;
    }

    private Signature buildSignature() {
        SignatureBuilder builder = new SignatureBuilder();
        Signature signature = builder.buildObject();
        signature.setSigningCredential(credential);
        signature.setSignatureAlgorithm(SIGNATURE_SIGN_ALGO);
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        return signature;
    }

    private Issuer getIssuer() {
        // create Issuer object
        IssuerBuilder issuerBuilder = new IssuerBuilder();
        Issuer issuer = issuerBuilder.buildObject();
        issuer.setValue(idpURL);
        return issuer;
    }

    private Subject buildSubject(DateTime issueInstance) {
        // create name element
        NameIDBuilder nameIdBuilder = new NameIDBuilder();
        NameID nameId = nameIdBuilder.buildObject();
        nameId.setValue(spEntity);
        nameId.setFormat(NameID.PERSISTENT);

        SubjectConfirmationDataBuilder dataBuilder = new SubjectConfirmationDataBuilder();
        SubjectConfirmationData subjectConfirmationData = dataBuilder.buildObject();
        subjectConfirmationData.setNotBefore(issueInstance.minusSeconds(VALID_NOT_BEFORE_IN_SECONDS));
        subjectConfirmationData.setNotOnOrAfter(issueInstance.plusSeconds(VALID_NOT_AFTER_IN_SECONDS));
        subjectConfirmationData.setRecipient(spURL);

        SubjectConfirmationBuilder subjectConfirmationBuilder = new SubjectConfirmationBuilder();
        SubjectConfirmation subjectConfirmation = subjectConfirmationBuilder.buildObject();
        subjectConfirmation.setMethod(subjectConfirmation.METHOD_BEARER);
        subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);

        // create subject element
        SubjectBuilder subjectBuilder = new SubjectBuilder();
        Subject subject = subjectBuilder.buildObject();
        subject.setNameID(nameId);
        subject.getSubjectConfirmations().add(subjectConfirmation);

        return subject;
    }

    private Conditions buildConditions(final DateTime issueInstance) {
        Audience audience = new AudienceBuilder().buildObject();
        audience.setAudienceURI(spEntity);

        AudienceRestriction audienceRestriction = new AudienceRestrictionBuilder().buildObject();
        audienceRestriction.getAudiences().add(audience);

        Conditions conditions = new ConditionsBuilder().buildObject();
        conditions.getAudienceRestrictions().add(audienceRestriction);
        conditions.setNotBefore(issueInstance.minusSeconds(VALID_NOT_BEFORE_IN_SECONDS));
        conditions.setNotOnOrAfter(issueInstance.plusSeconds(VALID_NOT_AFTER_IN_SECONDS));
        return conditions;
    }

    private AuthnStatement buildAuthnStatement(final DateTime issueInstance) {
        // create authcontextclassref object
        AuthnContextClassRefBuilder classRefBuilder = new AuthnContextClassRefBuilder();
        AuthnContextClassRef classRef = classRefBuilder.buildObject();
        classRef.setAuthnContextClassRef(AuthnContext.PASSWORD_AUTHN_CTX);

        // create authcontext object
        AuthnContextBuilder authContextBuilder = new AuthnContextBuilder();
        AuthnContext authnContext = authContextBuilder.buildObject();
        authnContext.setAuthnContextClassRef(classRef);

        // create authenticationstatement object
        AuthnStatementBuilder authStatementBuilder = new AuthnStatementBuilder();
        AuthnStatement authnStatement = authStatementBuilder.buildObject();
        authnStatement.setAuthnInstant(issueInstance);
        authnStatement.setAuthnContext(authnContext);
        authnStatement.setSessionNotOnOrAfter(issueInstance.plusSeconds(VALID_NOT_AFTER_IN_SECONDS));
        return authnStatement;
    }

    private AttributeStatement buildAttributeStatement(final String username) {
        AttributeStatementBuilder attributeStatementBuilder = new AttributeStatementBuilder();
        AttributeStatement attributeStatement = attributeStatementBuilder.buildObject();
        attributeStatement.getAttributes().add(buildAttribute(USER_ID_ATTRIBUTE_NAME, username));
        return attributeStatement;
    }

    private Status buildStatus() {
        StatusCodeBuilder statusCodeBuilder = new StatusCodeBuilder();
        StatusCode statusCode = statusCodeBuilder.buildObject();
        statusCode.setValue(StatusCode.SUCCESS_URI);

        StatusBuilder statusBuilder = new StatusBuilder();
        Status status = statusBuilder.buildObject();
        status.setStatusCode(statusCode);

        return status;
    }

    private static Attribute buildAttribute(String name, String value) {
        AttributeBuilder attributeBuilder = new AttributeBuilder();
        Attribute attribute = attributeBuilder.buildObject();
        attribute.setName(name);

        XSStringBuilder stringBuilder = new XSStringBuilder();
        XSString attributeValue = stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
        attributeValue.setValue(value);
        attribute.getAttributeValues().add(attributeValue);

        return attribute;
    }

    private static String base64Encode(String stringToEncode) {
        Base64.Encoder encoder = Base64.getEncoder();
        log.info(stringToEncode);
        return encoder.encodeToString(stringToEncode.getBytes());
    }

    public static String encodeSAMLResponse(Response response) {
        return base64Encode(stringify(response));
    }

    private static String stringify(Response response) {

        ResponseMarshaller marshaller = new ResponseMarshaller();
        Element element = null;
        try {
            element = marshaller.marshall(response);
        } catch (MarshallingException e) {
            log.error("Cannot stringify SAML response", e);
        }

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        XMLHelper.writeNode(element, outputStream);
        return new String(outputStream.toByteArray());
    }

    public static void main(String[] args) {
        Credential credential = CertManager.getSigningCredential(CertManager.class.getClassLoader().getResourceAsStream("certificate.crt"), CertManager.class.getClassLoader().getResourceAsStream("privateKey.pkcs8"));

        SAMLAssertionBuilder builder = new SAMLAssertionBuilder("https://sample.com", credential, "2", "https://2");
        Response response = builder.buildResponse("a@sample.com");

        System.out.println(stringify(response));
        System.out.println(base64Encode(stringify(response)));
    }
}
