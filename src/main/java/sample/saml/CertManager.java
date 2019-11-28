package sample.saml;

import org.apache.commons.io.IOUtils;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.x509.BasicX509Credential;

import java.io.InputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;

public class CertManager {
    private static final Logger log = LogManager.getLogger(CertManager.class);

    // read public and private keys
    public static Credential getSigningCredential(InputStream publicKeyStream, InputStream privateKeyStream) {
        try {
            // create public key (cert) portion of credential
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate publicKey = (X509Certificate) cf.generateCertificate(publicKeyStream);

            // create private key
            PKCS8EncodedKeySpec kspec = new PKCS8EncodedKeySpec(IOUtils.toByteArray(privateKeyStream));
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = kf.generatePrivate(kspec);

            BasicX509Credential credential = new BasicX509Credential();
            credential.setEntityCertificate(publicKey);
            credential.setPrivateKey(privateKey);
            return credential;
        } catch (Exception e) {
            log.error("Cannot load keys", e);
            return null;
        }
    }

    public static void main(String[] args) {
        final Credential credential = CertManager.getSigningCredential(CertManager.class.getClassLoader().getResourceAsStream("certificate.crt"), CertManager.class.getClassLoader().getResourceAsStream("privateKey.pkcs8"));
        System.out.println(credential);
    }
}