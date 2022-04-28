package kz.gov.pki.kalkan.issuance;


import static kz.gov.pki.kalkan.issuance.TestConstants.*;
import static org.junit.Assert.*;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
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
import kz.gov.pki.kalkan.asn1.DEROctetString;
import kz.gov.pki.kalkan.asn1.DERSequence;
import kz.gov.pki.kalkan.asn1.x509.AuthorityInformationAccess;
import kz.gov.pki.kalkan.asn1.x509.AuthorityKeyIdentifier;
import kz.gov.pki.kalkan.asn1.x509.BasicConstraints;
import kz.gov.pki.kalkan.asn1.x509.CRLDistPoint;
import kz.gov.pki.kalkan.asn1.x509.DistributionPoint;
import kz.gov.pki.kalkan.asn1.x509.DistributionPointName;
import kz.gov.pki.kalkan.asn1.x509.GeneralName;
import kz.gov.pki.kalkan.asn1.x509.GeneralNames;
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

public class InterCertIssuanceTest {

    private static final Logger log = Logger.getLogger(InterCertIssuanceTest.class.getName());
    
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
    public void generateIntermediate() throws Exception {
        Storage storage = Storage.PKCS12;
        log.info("***** Load the root keystore");
        KeyStore rootKeyStore = KeyStore.getInstance(storage.getName(), provider.getName());
        String rootPath = ROOT_PATH + ".p12";
        log.info(rootPath);
        rootKeyStore.load(new FileInputStream(rootPath), ROOT_PASSWORD);
        Enumeration<String> rootAliases = rootKeyStore.aliases();
        String rootAlias = rootAliases.nextElement();
        log.info("root alias = " + rootAlias);
        PrivateKey rootPrivKey = (PrivateKey) rootKeyStore.getKey(rootAlias, ROOT_PASSWORD);
        X509Certificate rootCert = (X509Certificate) rootKeyStore.getCertificate(rootAlias);
        log.info("root subject = " + rootCert.getSubjectDN());

        log.info("***** Generate a keypair");
        String sigAlg = rootCert.getSigAlgOID();
        log.info(sigAlg);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(sigAlg, provider.getName());
        kpg.initialize(KEY_SIZE);
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
        PKCS10CertificationRequest request = new PKCS10CertificationRequest(sigAlg, new X509Name(INTER_SUBJECT_DN), pubKey,
                null, privKey, provider.getName());
        SubjectKeyIdentifier subjKeyId = new SubjectKeyIdentifier(
                request.getCertificationRequestInfo().getSubjectPublicKeyInfo());
        String keyId = Hex.encodeStr(subjKeyId.getKeyIdentifier());
        log.info("keyId = " + keyId);
        log.info("encoded request:" + Hex.encodeStr(request.getEncoded()));
        assertTrue(request.verify());

        log.info("***** Generate a certificate");

        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
        certGen.setSignatureAlgorithm(request.getSignatureAlgorithm().getObjectId().getId());
        TBSCertificateStructure tbsCert = generetaTBSCertStruct(request, rootCert);

        Signature sig = Signature.getInstance(sigAlg, provider.getName());
        sig.initSign(rootPrivKey);
        sig.update(tbsCert.getDEREncoded());
        byte[] certSgn = sig.sign();

        X509Certificate cert = certGen.generate(tbsCert, certSgn);
        log.info("encoded cert: " + Hex.encodeStr(cert.getEncoded()));
        log.info(cert.toString());
        assertEquals(cert.getIssuerDN(), rootCert.getSubjectDN());
        cert.verify(rootCert.getPublicKey());
        String certPath = INTER_PATH + ".cer";
        Files.write(Paths.get(certPath), cert.getEncoded(), StandardOpenOption.CREATE);

        log.info("***** Create a keystore");

        KeyStore keyStore = KeyStore.getInstance(storage.getName(), provider.getName());
        keyStore.load(null);
        keyStore.setKeyEntry(keyId, privKey, INTER_PASSWORD, new Certificate[] { cert });
        String path = INTER_PATH + ".p12";
        keyStore.store(new FileOutputStream(path), INTER_PASSWORD);
        log.info(path);

        log.info("***** Load the keystore");
        keyStore.load(new FileInputStream(path), INTER_PASSWORD);
        Enumeration<String> aliases = keyStore.aliases();
        String alias = aliases.nextElement();
        log.info("alias = " + alias);

        PrivateKey privKey12 = (PrivateKey) keyStore.getKey(alias, INTER_PASSWORD);
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

    private TBSCertificateStructure generetaTBSCertStruct(PKCS10CertificationRequest request, X509Certificate cert)
            throws IOException {
        V3TBSCertificateGenerator tbsCertGen = new V3TBSCertificateGenerator();
        Calendar cal = Calendar.getInstance();
        Date nowDate = cal.getTime();
        cal.add(Calendar.DAY_OF_YEAR, 150);
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
        tbsCertGen.setIssuer(new X509Name(cert.getSubjectDN().getName()));
        tbsCertGen.setSubjectPublicKeyInfo(request.getCertificationRequestInfo().getSubjectPublicKeyInfo());
        tbsCertGen.setSubject(request.getCertificationRequestInfo().getSubject());
        tbsCertGen.setExtensions(generateExtensions(request, cert));
        TBSCertificateStructure tbsCert = tbsCertGen.generateTBSCertificate();
        return tbsCert;
    }

    private X509Extensions generateExtensions(PKCS10CertificationRequest request, X509Certificate cert)
            throws IOException {
        X509ExtensionsGenerator x509ExtGen = new X509ExtensionsGenerator();
        DEROctetString octetString = (DEROctetString) ASN1Object
                .fromByteArray(cert.getExtensionValue(X509Extensions.SubjectKeyIdentifier.getId()));
        byte[] authKeyIdBytes = ((DEROctetString) ASN1Object.fromByteArray(octetString.getOctets())).getOctets();
        SubjectKeyIdentifier subjectKeyIdentifier = new SubjectKeyIdentifier(
                request.getCertificationRequestInfo().getSubjectPublicKeyInfo());
        x509ExtGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(true));
        x509ExtGen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        x509ExtGen.addExtension(X509Extensions.SubjectKeyIdentifier, false, subjectKeyIdentifier);
        x509ExtGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false,
                new AuthorityKeyIdentifier(authKeyIdBytes));
        PolicyQualifierInfo policyQualifierInfo = new PolicyQualifierInfo(POLICY_URL);
        PolicyInformation policyInformation = new PolicyInformation(new DERObjectIdentifier("1.2.398.3.3.1.1"),
                new DERSequence((ASN1Sequence) policyQualifierInfo.toASN1Object()));
        x509ExtGen.addExtension(X509Extensions.CertificatePolicies, false, new DERSequence(policyInformation));
        AuthorityInformationAccess authorityInformationAccess = new AuthorityInformationAccess(
                new DERObjectIdentifier("1.3.6.1.5.5.7.48.2"), new GeneralName(GeneralName.uniformResourceIdentifier,
                        ROOT_CERT_URL));
        x509ExtGen.addExtension(X509Extensions.AuthorityInfoAccess, false, authorityInformationAccess);
        CRLDistPoint crlDistPoint = new CRLDistPoint(new DistributionPoint[] { new DistributionPoint(
                new DistributionPointName(new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier,
                        ROOT_CRL_URL))),
                null, null) });
        x509ExtGen.addExtension(X509Extensions.CRLDistributionPoints, false, crlDistPoint);

        return x509ExtGen.generate();
    }

}
