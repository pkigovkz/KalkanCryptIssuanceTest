package kz.gov.pki.kalkan.issuance;


import static kz.gov.pki.kalkan.issuance.TestConstants.*;
import static org.junit.Assert.*;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;
import java.util.logging.Logger;
import org.junit.BeforeClass;
import org.junit.Test;
import kz.gov.pki.kalkan.Storage;
import kz.gov.pki.kalkan.asn1.ASN1Object;
import kz.gov.pki.kalkan.asn1.ASN1Sequence;
import kz.gov.pki.kalkan.asn1.DERBitString;
import kz.gov.pki.kalkan.asn1.DERInteger;
import kz.gov.pki.kalkan.asn1.DERObjectIdentifier;
import kz.gov.pki.kalkan.asn1.DERSequence;
import kz.gov.pki.kalkan.asn1.x509.BasicConstraints;
import kz.gov.pki.kalkan.asn1.x509.KeyUsage;
import kz.gov.pki.kalkan.asn1.x509.PolicyInformation;
import kz.gov.pki.kalkan.asn1.x509.PolicyQualifierInfo;
import kz.gov.pki.kalkan.asn1.x509.SubjectKeyIdentifier;
import kz.gov.pki.kalkan.asn1.x509.TBSCertificateStructure;
import kz.gov.pki.kalkan.asn1.x509.Time;
import kz.gov.pki.kalkan.asn1.x509.V3TBSCertificateGenerator;
import kz.gov.pki.kalkan.asn1.x509.X509Extensions;
import kz.gov.pki.kalkan.asn1.x509.X509ExtensionsGenerator;
import kz.gov.pki.kalkan.asn1.x509.X509Name;
import kz.gov.pki.kalkan.jce.PKCS10CertificationRequest;
import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import kz.gov.pki.kalkan.openssl.PEMWriter;
import kz.gov.pki.kalkan.util.encoders.Hex;
import kz.gov.pki.kalkan.x509.X509V3CertificateGenerator;

public class RootCertIssuanceTest {

    private static final Logger log = Logger.getLogger(RootCertIssuanceTest.class.getName());
    private static Provider provider;

    @BeforeClass
    public static void setUp() {
        System.setProperty("java.util.logging.SimpleFormatter.format",
//                "[%1$tF %1$tT] "
                "[%4$s] %5$s %n");
        provider = new KalkanProvider();
        Security.addProvider(provider);
    }

    @Test
    public void generateRoot() throws Exception {
        Storage storage = Storage.PKCS12;
        log.info("***** Generate a keypair");
        String sigAlg = SIG_ALG_OID;
        log.info(sigAlg);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(sigAlg, provider.getName());
        kpg.initialize(KEY_SIZE);
//        alternative ways to initialize KPG for GOST 2015 and GOST 2004
//        kpg.initialize(new ECGenParameterSpec("Gost3410-2015-512-ParamSetA"));
//        kpg.initialize(new ECGenParameterSpec("Gost34310-2004-PKIGOVKZ-A"));
        KeyPair keyPair = kpg.generateKeyPair();
        PrivateKey privKey = keyPair.getPrivate();
        PublicKey pubKey = keyPair.getPublic();
        log.info(privKey.toString());
        log.info(pubKey.toString());
        log.info(Base64.getEncoder().encodeToString(privKey.getEncoded()));
        log.info(Base64.getEncoder().encodeToString(pubKey.getEncoded()));

        log.info("***** Generate a request");
        ASN1Sequence seq = (ASN1Sequence) ASN1Object.fromByteArray(pubKey.getEncoded());
        DERBitString derString = (DERBitString) seq.getObjectAt(1);
        log.info(Hex.encodeStr(derString.getBytes()));
        PKCS10CertificationRequest request = new PKCS10CertificationRequest(sigAlg, new X509Name(ROOT_SUBJECT_DN), pubKey,
                null, privKey, provider.getName());
        SubjectKeyIdentifier subjKeyId = new SubjectKeyIdentifier(
                request.getCertificationRequestInfo().getSubjectPublicKeyInfo());
        String keyId = Hex.encodeStr(subjKeyId.getKeyIdentifier());
        log.info("keyId = " + keyId);
        log.info("encoded request: " + Hex.encodeStr(request.getEncoded()));
        assertTrue(request.verify());

        log.info("***** Generate a certificate");

        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
        certGen.setSignatureAlgorithm(request.getSignatureAlgorithm().getObjectId().getId());
        TBSCertificateStructure tbsCert = generetaTBSCertStruct(request);

        Signature sig = Signature.getInstance(sigAlg, provider);
        sig.initSign(privKey);
        sig.update(tbsCert.getDEREncoded());
        byte[] certSgn = sig.sign();

        X509Certificate cert = certGen.generate(tbsCert, certSgn);
        log.info("encoded cert: " + Hex.encodeStr(cert.getEncoded()));
        log.info(cert.toString());
        assertEquals(cert.getSubjectDN(), cert.getIssuerDN());
        cert.verify(cert.getPublicKey());
        String certPath = ROOT_PATH + ".cer";
        Files.write(Paths.get(certPath), cert.getEncoded(), StandardOpenOption.CREATE);

        log.info("***** Create a keystore");

        KeyStore keyStore = KeyStore.getInstance(storage.getName(), provider);
        keyStore.load(null);
        keyStore.setKeyEntry(keyId, privKey, ROOT_PASSWORD, new Certificate[] { cert });
        String path = ROOT_PATH + ".p12";
        log.info(path);
        keyStore.store(new FileOutputStream(path), ROOT_PASSWORD);

        log.info("***** Load the keystore");
        keyStore.load(new FileInputStream(path), ROOT_PASSWORD);
        Enumeration<String> aliases = keyStore.aliases();
        String alias = aliases.nextElement();
        log.info("alias = " + alias);

        PrivateKey privKey12 = (PrivateKey) keyStore.getKey(alias, ROOT_PASSWORD);
        assertEquals(privKey, privKey12);
        X509Certificate cert12 = (X509Certificate) keyStore.getCertificate(alias);
        assertEquals(cert, cert12);

        log.info("***** Sign with a key from the keystore");
        sig.initSign(privKey12);
        sig.update("test".getBytes());
        byte[] sgn = sig.sign();
        log.info(Hex.encodeStr(sgn));

        sig.initVerify(cert12.getPublicKey());
        sig.update("test".getBytes());
        assertTrue(sig.verify(sgn));

        StringWriter stringWriter = new StringWriter();
        PEMWriter pemWriter = new PEMWriter(stringWriter);
        pemWriter.writeObject(privKey);
        pemWriter.writeObject(pubKey);
        pemWriter.writeObject(request);
        pemWriter.writeObject(cert);
        pemWriter.flush();
        String pem = stringWriter.toString();
        log.info(pem);
    }

    private TBSCertificateStructure generetaTBSCertStruct(PKCS10CertificationRequest request) {
        V3TBSCertificateGenerator tbsCertGen = new V3TBSCertificateGenerator();
        Calendar cal = Calendar.getInstance();
        Date nowDate = cal.getTime();
        cal.add(Calendar.DAY_OF_YEAR, 180);
        Date nextDate = cal.getTime();
        tbsCertGen.setStartDate(new Time(nowDate));
        tbsCertGen.setEndDate(new Time(nextDate));
        SecureRandom random = new SecureRandom();
        byte[] serNum = new byte[20];
        while (serNum[0] < 16) {
            random.nextBytes(serNum);
        }
        tbsCertGen.setSerialNumber(new DERInteger(serNum));
        tbsCertGen.setSignature(request.getSignatureAlgorithm());
        tbsCertGen.setIssuer(request.getCertificationRequestInfo().getSubject());
        tbsCertGen.setSubjectPublicKeyInfo(request.getCertificationRequestInfo().getSubjectPublicKeyInfo());
        tbsCertGen.setSubject(request.getCertificationRequestInfo().getSubject());
        tbsCertGen.setExtensions(generateExtensions(request));
        TBSCertificateStructure tbsCert = tbsCertGen.generateTBSCertificate();
        return tbsCert;
    }

    private X509Extensions generateExtensions(PKCS10CertificationRequest request) {
        X509ExtensionsGenerator x509ExtGen = new X509ExtensionsGenerator();
        x509ExtGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(true));
        x509ExtGen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        SubjectKeyIdentifier subjectKeyIdentifier = new SubjectKeyIdentifier(
                request.getCertificationRequestInfo().getSubjectPublicKeyInfo());
        x509ExtGen.addExtension(X509Extensions.SubjectKeyIdentifier, false, subjectKeyIdentifier);
        PolicyQualifierInfo policyQualifierInfo = new PolicyQualifierInfo(ROOT_POLICY_URL);
        PolicyInformation policyInformation = new PolicyInformation(new DERObjectIdentifier("1.2.398.3.1.2"),
                new DERSequence((ASN1Sequence) policyQualifierInfo.toASN1Object()));
        x509ExtGen.addExtension(X509Extensions.CertificatePolicies, false, new DERSequence(policyInformation));

        return x509ExtGen.generate();
    }

}
