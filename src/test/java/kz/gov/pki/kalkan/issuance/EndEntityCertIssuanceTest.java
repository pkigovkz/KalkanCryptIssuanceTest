package kz.gov.pki.kalkan.issuance;


import static kz.gov.pki.kalkan.issuance.TestConstants.*;
import static org.junit.Assert.*;

import java.io.ByteArrayOutputStream;
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
import java.util.List;
import java.util.logging.Logger;
import org.junit.BeforeClass;
import org.junit.Test;
import kz.gov.pki.kalkan.Storage;
import kz.gov.pki.kalkan.asn1.ASN1Encodable;
import kz.gov.pki.kalkan.asn1.ASN1EncodableVector;
import kz.gov.pki.kalkan.asn1.ASN1Object;
import kz.gov.pki.kalkan.asn1.ASN1Sequence;
import kz.gov.pki.kalkan.asn1.ASN1Set;
import kz.gov.pki.kalkan.asn1.DERBitString;
import kz.gov.pki.kalkan.asn1.DEREncodable;
import kz.gov.pki.kalkan.asn1.DERInteger;
import kz.gov.pki.kalkan.asn1.DERNull;
import kz.gov.pki.kalkan.asn1.DERObject;
import kz.gov.pki.kalkan.asn1.DERObjectIdentifier;
import kz.gov.pki.kalkan.asn1.DEROctetString;
import kz.gov.pki.kalkan.asn1.DERSequence;
import kz.gov.pki.kalkan.asn1.DERSequenceGenerator;
import kz.gov.pki.kalkan.asn1.DERSet;
import kz.gov.pki.kalkan.asn1.knca.KNCAObjectIdentifiers;
import kz.gov.pki.kalkan.asn1.ocsp.OCSPObjectIdentifiers;
import kz.gov.pki.kalkan.asn1.x509.AccessDescription;
import kz.gov.pki.kalkan.asn1.x509.AuthorityKeyIdentifier;
import kz.gov.pki.kalkan.asn1.x509.CRLDistPoint;
import kz.gov.pki.kalkan.asn1.x509.DistributionPoint;
import kz.gov.pki.kalkan.asn1.x509.DistributionPointName;
import kz.gov.pki.kalkan.asn1.x509.GeneralName;
import kz.gov.pki.kalkan.asn1.x509.GeneralNames;
import kz.gov.pki.kalkan.asn1.x509.KeyPurposeId;
import kz.gov.pki.kalkan.asn1.x509.KeyStoreInfo;
import kz.gov.pki.kalkan.asn1.x509.PolicyInformation;
import kz.gov.pki.kalkan.asn1.x509.PolicyQualifierInfo;
import kz.gov.pki.kalkan.asn1.x509.SubjectKeyIdentifier;
import kz.gov.pki.kalkan.asn1.x509.TBSCertificateStructure;
import kz.gov.pki.kalkan.asn1.x509.Time;
import kz.gov.pki.kalkan.asn1.x509.V3TBSCertificateGenerator;
import kz.gov.pki.kalkan.asn1.x509.X509Extension;
import kz.gov.pki.kalkan.asn1.x509.X509Extensions;
import kz.gov.pki.kalkan.asn1.x509.X509ExtensionsGenerator;
import kz.gov.pki.kalkan.asn1.x509.X509Name;
import kz.gov.pki.kalkan.jce.PKCS10CertificationRequest;
import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import kz.gov.pki.kalkan.openssl.PEMWriter;
import kz.gov.pki.kalkan.pcsc.PCSCUtils;
import kz.gov.pki.kalkan.pcsc.Smartcard;
import kz.gov.pki.kalkan.pcsc.generators.AKAlgorithmParameterSpec;
import kz.gov.pki.kalkan.util.encoders.Hex;
import kz.gov.pki.kalkan.util.io.Streams;
import kz.gov.pki.kalkan.x509.X509Attribute;
import kz.gov.pki.kalkan.x509.X509V3CertificateGenerator;

public class EndEntityCertIssuanceTest {

    private static final Logger log = Logger.getLogger(EndEntityCertIssuanceTest.class.getName());
    private static final String EMAIL = "knca@pki.gov.kz";
    private static final char[] PASSWORD = "123456".toCharArray();
    private static final String PATH = "/tmp";
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
    public void generateUser() throws Exception {
        generate(SUBJECT_DN,
                new DERObjectIdentifier[] { KeyPurposeId.id_kp_emailProtection,
                        new DERObjectIdentifier("1.2.398.3.3.4.1.1") },
                new DERObjectIdentifier("1.2.398.3.3.2.3"), PATH, "user");
    }

    @Test
    public void generateLegalChief() throws Exception {
        generate(SUBJECT_LEGAL_CHIEF_DN,
                new DERObjectIdentifier[] { KeyPurposeId.id_kp_emailProtection,
                        new DERObjectIdentifier("1.2.398.3.3.4.1.2"), new DERObjectIdentifier("1.2.398.3.3.4.1.2.1") },
                new DERObjectIdentifier("1.2.398.3.3.2.1"), PATH, "legal_chief");
    }
    
    @Test
    public void generateLegalSigner() throws Exception {
        generate(SUBJECT_LEGAL_SIGNER_DN,
                new DERObjectIdentifier[] { KeyPurposeId.id_kp_emailProtection,
                        new DERObjectIdentifier("1.2.398.3.3.4.1.2"), new DERObjectIdentifier("1.2.398.3.3.4.1.2.2") },
                new DERObjectIdentifier("1.2.398.3.3.2.1"), PATH, "legal_signer");
    }

    @Test
    public void generateLegalStaff() throws Exception {
        generate(SUBJECT_LEGAL_STAFF_DN,
                new DERObjectIdentifier[] { KeyPurposeId.id_kp_emailProtection,
                        new DERObjectIdentifier("1.2.398.3.3.4.1.2"), new DERObjectIdentifier("1.2.398.3.3.4.1.2.5") },
                new DERObjectIdentifier("1.2.398.3.3.2.1"), PATH, "legal_staff");
    }
    
    @Test
    public void generateOcspSigning() throws Exception {
        generate(SUBJECT_OCSP_RESPONDER_DN,
                new DERObjectIdentifier[] { KeyPurposeId.id_kp_OCSPSigning }, null, PATH, "ocsp_responder");
    }
    
    @Test
    public void generateTspSigning() throws Exception {
        generate(SUBJECT_TSA_DN,
                new DERObjectIdentifier[] { KeyPurposeId.id_kp_timeStamping },
                KNCAObjectIdentifiers.tsa_policy_id, PATH, "tsa");
    }

    public void generate(String subjectDn, DERObjectIdentifier[] ekus, DERObjectIdentifier policyInfo, String folder,
            String filename) throws Exception {
        Storage storage = Storage.PKCS12;
        log.info("***** Load the root keystore");
        KeyStore rootKeyStore = KeyStore.getInstance("PKCS12", provider);
        String interPath = INTER_PATH + ".p12";
        log.info(interPath);
        rootKeyStore.load(new FileInputStream(interPath), INTER_PASSWORD);
        Enumeration<String> rootAliases = rootKeyStore.aliases();
        String rootAlias = rootAliases.nextElement();
        log.info("root alias = " + rootAlias);
        PrivateKey rootPrivKey = (PrivateKey) rootKeyStore.getKey(rootAlias, INTER_PASSWORD);
        X509Certificate rootCert = (X509Certificate) rootKeyStore.getCertificate(rootAlias);
        log.info("root subject = " + rootCert.getSubjectDN());

        Smartcard smartcard = null;
        if (storage.isToken()) {
            List<Smartcard> smartcards = PCSCUtils.loadSlotListByStorage(storage.getName());
            smartcard = smartcards.get(0);
            System.out.println(smartcard);
        }

        log.info("***** Generate a keypair");
        String sigAlg = rootCert.getSigAlgOID();
        log.info(sigAlg);
        String keyId = null;
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(sigAlg, provider);
        if (storage.isToken()) {
            AKAlgorithmParameterSpec params = new AKAlgorithmParameterSpec(smartcard, PASSWORD);
            params.setKeyLength(KEY_SIZE);  // ignored if not RSA
            kpg.initialize(params);
            keyId = params.getAlias();
            log.info("keyId = " + keyId);
        } else {
            kpg.initialize(KEY_SIZE);
        }
        KeyPair keyPair = kpg.generateKeyPair();
        PrivateKey privKey = keyPair.getPrivate();
        PublicKey pubKey = keyPair.getPublic();

        ASN1Sequence seq = (ASN1Sequence) ASN1Object.fromByteArray(pubKey.getEncoded());
        DERBitString derString = (DERBitString) seq.getObjectAt(1);
        log.info(Hex.encodeStr(derString.getBytes()));

        log.info(privKey.toString());
        log.info(pubKey.toString());
        if (!storage.isToken()) {
            log.info(Base64.getEncoder().encodeToString(privKey.getEncoded()));
        }
        log.info(Base64.getEncoder().encodeToString(pubKey.getEncoded()));

        log.info("***** Generate a request");

        X509ExtensionsGenerator generator = new X509ExtensionsGenerator();

        ASN1EncodableVector sanVector = new ASN1EncodableVector();
        GeneralName generalName = new GeneralName(GeneralName.rfc822Name, EMAIL);
        sanVector.add(generalName);
        DERSequence san = new DERSequence(sanVector);
        GeneralNames generalNames = new GeneralNames(san);
        generator.addExtension(X509Extensions.SubjectAlternativeName, false, generalNames);

        generator.addExtension(KNCAObjectIdentifiers.keystore_branch, false,
                new KeyStoreInfo(storage.getOid(), storage.isToken() ? null : folder));

        ASN1Set exReqSet = new DERSet(
                new X509Attribute(PKCS10CertificationRequest.extensionRequest.getId(), generator.generate()));

        PKCS10CertificationRequest request = new PKCS10CertificationRequest(sigAlg, new X509Name(subjectDn), pubKey,
                exReqSet, privKey, provider.getName());
        if (!storage.isToken()) {
            SubjectKeyIdentifier subjKeyId = new SubjectKeyIdentifier(
                    request.getCertificationRequestInfo().getSubjectPublicKeyInfo());
            keyId = Hex.encodeStr(subjKeyId.getKeyIdentifier());
            log.info("keyId = " + keyId);
        }
        log.info("encoded request:" + Hex.encodeStr(request.getEncoded()));
        assertTrue(request.verify());

        log.info("***** Generate a certificate");

        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
        certGen.setSignatureAlgorithm(rootCert.getSigAlgOID());
        TBSCertificateStructure tbsCert = generetaTBSCertStruct(request, rootCert, ekus, policyInfo);

        Signature sig = Signature.getInstance(rootCert.getSigAlgOID(), provider);
        sig.initSign(rootPrivKey);
        sig.update(tbsCert.getDEREncoded());
        byte[] certSgn = sig.sign();

        X509Certificate cert = certGen.generate(tbsCert, certSgn);
        log.info("encoded cert: " + Hex.encodeStr(cert.getEncoded()));
        log.info(cert.toString());
        assertEquals(cert.getIssuerDN(), rootCert.getSubjectDN());
        cert.verify(rootCert.getPublicKey());
        String outPath = folder + "/" + filename + "_" + keyId;
        Files.write(Paths.get(outPath + ".cer"), cert.getEncoded(), StandardOpenOption.CREATE_NEW);

        log.info("***** Create a keystore");

        KeyStore keyStore = KeyStore.getInstance(storage.getName(), provider);
        if (storage.isToken()) {
            keyStore.load(Streams.fromString(smartcard.getTerminalName()), PASSWORD);
        } else {
            keyStore.load(null);
        }

        String path = outPath + ".p12";
        log.info(path);
        if (storage.isToken()) {
            keyStore.setCertificateEntry(keyId, cert);
            keyStore.store(null, null);
        } else {
            keyStore.setKeyEntry(keyId, privKey, PASSWORD, new Certificate[] { cert });
            keyStore.store(new FileOutputStream(path), PASSWORD);
        }

        log.info("***** Load the keystore");
        if (storage.isToken()) {
            keyStore.load(Streams.fromString(smartcard.getTerminalName()), PASSWORD);
        } else {
            keyStore.load(new FileInputStream(path), PASSWORD);
        }

        String alias = keyId;
        if (!storage.isToken()) {
            Enumeration<String> aliases = keyStore.aliases();
            alias = aliases.nextElement();
        }
        log.info("alias = " + alias);

        PrivateKey privKey12 = (PrivateKey) keyStore.getKey(alias, PASSWORD);
        if (!storage.isToken()) {
            assertEquals(privKey, privKey12);
        }
        X509Certificate cert12 = (X509Certificate) keyStore.getCertificate(alias);
        assertEquals(cert, cert12);

        log.info("***** Sign with a key from the keystore");
        sig = Signature.getInstance(sigAlg, provider);
        sig.initSign(privKey12);
        sig.update("test".getBytes());
        byte[] sgn = sig.sign();
        log.info(Hex.encodeStr(sgn));

        sig.initVerify(cert12.getPublicKey());
        sig.update("test".getBytes());
        assertTrue(sig.verify(sgn));

        StringWriter stringWriter = new StringWriter();
        PEMWriter pemWriter = new PEMWriter(stringWriter);
        if (!storage.isToken()) {
            pemWriter.writeObject(privKey);
        }
        pemWriter.writeObject(pubKey);
        pemWriter.writeObject(request);
        pemWriter.writeObject(cert);
        pemWriter.flush();
        String pem = stringWriter.toString();
        log.info(pem);
    }

    private TBSCertificateStructure generetaTBSCertStruct(PKCS10CertificationRequest request, X509Certificate cert,
            DERObjectIdentifier[] ekus, DERObjectIdentifier policyInfo) throws IOException {
        V3TBSCertificateGenerator tbsCertGen = new V3TBSCertificateGenerator();
        Calendar cal = Calendar.getInstance();
        Date nowDate = cal.getTime();
        cal.add(Calendar.DAY_OF_YEAR, 120);
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
        tbsCertGen.setExtensions(generateExtensions(request, cert, ekus, policyInfo));
        TBSCertificateStructure tbsCert = tbsCertGen.generateTBSCertificate();
        return tbsCert;
    }

    private X509Extensions generateExtensions(PKCS10CertificationRequest request, X509Certificate cert,
            DERObjectIdentifier[] ekus, DERObjectIdentifier policyInfo) throws IOException {
        X509ExtensionsGenerator x509ExtGen = new X509ExtensionsGenerator();
        DEROctetString octetString = (DEROctetString) ASN1Object
                .fromByteArray(cert.getExtensionValue(X509Extensions.SubjectKeyIdentifier.getId()));
        byte[] authKeyIdBytes = ((DEROctetString) ASN1Object.fromByteArray(octetString.getOctets())).getOctets();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        SubjectKeyIdentifier subjectKeyIdentifier = new SubjectKeyIdentifier(
                request.getCertificationRequestInfo().getSubjectPublicKeyInfo());
        log.info("cert keyId = " + Hex.encodeStr(subjectKeyIdentifier.getKeyIdentifier()));
        
        boolean isOcspSigning = false;
        boolean isTimeStamping = false;
        
        DERSequenceGenerator extKeyUsageSeq = new DERSequenceGenerator(baos);
        if (ekus.length == 1) {
            x509ExtGen.addExtension(X509Extensions.KeyUsage, true, SERVICE_KEY_USAGE);
            if (KeyPurposeId.id_kp_OCSPSigning.equals(ekus[0])) {
                isOcspSigning = true;
                x509ExtGen.addExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nocheck, false, new DERNull());
            } else if (KeyPurposeId.id_kp_timeStamping.equals(ekus[0])) {
                isTimeStamping = true;
            } else {
                throw new IllegalArgumentException("A service certificate requires a particular key purpose!");
            }
            extKeyUsageSeq.addObject(ekus[0]);
        } else {
            x509ExtGen.addExtension(X509Extensions.KeyUsage, true, END_ENTITY_KEY_USAGE);
            for (int i = 0; i < ekus.length; i++) {
                extKeyUsageSeq.addObject(ekus[i]);
            }
        }
        extKeyUsageSeq.close();
        x509ExtGen.addExtension(X509Extensions.ExtendedKeyUsage, isTimeStamping, baos.toByteArray());
        x509ExtGen.addExtension(X509Extensions.SubjectKeyIdentifier, false, subjectKeyIdentifier);
        x509ExtGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false,
                new AuthorityKeyIdentifier(authKeyIdBytes));
        
        if (policyInfo != null) {
            PolicyQualifierInfo policyQualifierInfo = new PolicyQualifierInfo(POLICY_URL);
            PolicyInformation policyInformation = new PolicyInformation(policyInfo,
                    new DERSequence((ASN1Sequence) policyQualifierInfo.toASN1Object()));
            x509ExtGen.addExtension(X509Extensions.CertificatePolicies, false, new DERSequence(policyInformation));
        }
        
        if (!isOcspSigning) {
        
            AccessDescription accessDescriptionOcsp = new AccessDescription(AccessDescription.id_ad_ocsp,
                    new GeneralName(GeneralName.uniformResourceIdentifier, OCSP_URL));
            AccessDescription accessDescriptionIssuer = new AccessDescription(AccessDescription.id_ad_caIssuers,
                    new GeneralName(GeneralName.uniformResourceIdentifier,
                            INTER_CERT_URL));
            baos.reset();
            DERSequenceGenerator infoAccessSeq = new DERSequenceGenerator(baos);
            infoAccessSeq.addObject(accessDescriptionOcsp);
            infoAccessSeq.addObject(accessDescriptionIssuer);
            infoAccessSeq.close();
            x509ExtGen.addExtension(X509Extensions.AuthorityInfoAccess, false, baos.toByteArray());
            CRLDistPoint crlDistPoint = new CRLDistPoint(new DistributionPoint[] { new DistributionPoint(
                    new DistributionPointName(new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier,
                            INTER_CRL_URL))),
                    null, null) });
            x509ExtGen.addExtension(X509Extensions.CRLDistributionPoints, false, crlDistPoint);
            CRLDistPoint deltaDistPoint = new CRLDistPoint(new DistributionPoint[] { new DistributionPoint(
                    new DistributionPointName(new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier,
                            INTER_DELTA_CRL_URL))),
                    null, null) });
            x509ExtGen.addExtension(X509Extensions.FreshestCRL, false, deltaDistPoint);
    
            if (!isTimeStamping) {
                ASN1Set criAttributes = request.getCertificationRequestInfo().getAttributes();
                Enumeration<DEREncodable> objects = criAttributes.getObjects();
                X509Attribute extensionRequest = null;
                while (objects.hasMoreElements()) {
                    X509Attribute attribute = (X509Attribute) objects.nextElement();
                    if (PKCS10CertificationRequest.extensionRequest.getId().equals(attribute.getOID())) {
                        extensionRequest = attribute;
                        break;
                    }
                }
                if (extensionRequest == null) {
                    throw new IllegalArgumentException("extensionRequest not found.");
                }
                ASN1Encodable[] values = extensionRequest.getValues();
        
                if (values.length != 1) {
                    throw new IllegalArgumentException("extensionRequest should contain only X509Extensions value.");
                }
        
                X509Extensions extensions = X509Extensions.getInstance(values[0]);
        
                X509Extension subjectAltNameExt = extensions.getExtension(X509Extensions.SubjectAlternativeName);
                DERObject subjectAltNameSeq = ASN1Object.fromByteArray(subjectAltNameExt.getValue().getOctets());
                GeneralNames generalNames = GeneralNames.getInstance(subjectAltNameSeq);
                GeneralName[] names = generalNames.getNames();
                ASN1EncodableVector sanVector = new ASN1EncodableVector();
                for (int i = 0; i < names.length; i++) {
                    GeneralName generalName = names[i];
                    int tag = generalName.getTagNo();
                    if (tag == GeneralName.dNSName || tag == GeneralName.rfc822Name) {
                        sanVector.add(generalName);
                    }
                }
        
                if (sanVector.size() > 0) {
                    DERSequence allowedGeneralNames = new DERSequence(sanVector);
                    x509ExtGen.addExtension(X509Extensions.SubjectAlternativeName, false, allowedGeneralNames);
                }
        
                X509Extension extension = extensions.getExtension(KNCAObjectIdentifiers.keystore_branch);
                if (extension == null) {
                    throw new IllegalArgumentException("keystore extension not found.");
                }
                DERObject derObject = ASN1Object.fromByteArray(extension.getValue().getOctets());
                KeyStoreInfo keyStoreInfo = KeyStoreInfo.getInstance(derObject);
        
                x509ExtGen.addExtension(KNCAObjectIdentifiers.keystore_branch, false,
                        new KeyStoreInfo(keyStoreInfo.getKeyStoreId()));
            }

        }
        
        return x509ExtGen.generate();
    }

}
