package kz.gov.pki.kalkan.issuance;


import kz.gov.pki.kalkan.asn1.knca.KNCAObjectIdentifiers;
import kz.gov.pki.kalkan.asn1.x509.KeyUsage;

public interface TestConstants {

    String ROOT_PATH = "/tmp/rca_gost2022";
    String INTER_PATH = "/tmp/nca_gost2022";

    String ROOT_SUBJECT_DN = "C=KZ, CN=НЕГІЗГІ КУӘЛАНДЫРУШЫ ОРТАЛЫҚ (GOST) TEST 2022";
    String INTER_SUBJECT_DN = "C=KZ, CN=ҰЛТТЫҚ КУӘЛАНДЫРУШЫ ОРТАЛЫҚ (GOST) TEST 2022";

    char[] ROOT_PASSWORD = "123456".toCharArray();
    char[] INTER_PASSWORD = "123456".toCharArray();

    //  supported algorithms
    //  KNCAObjectIdentifiers.gost34311_95_with_gost34310_2004
    //  KNCAObjectIdentifiers.gost3411_2015_with_gost3410_2015_512
    //  PKCSObjectIdentifiers.sha256WithRSAEncryption
    String SIG_ALG_OID = KNCAObjectIdentifiers.gost3411_2015_with_gost3410_2015_512.getId();
    //  supported values
    //  GOST 2004 -> 256
    //  GOST 2015 -> 512
    //  RSA -> eligible values for RSA
    int KEY_SIZE = 512;
    
    String ROOT_CRL_URL = "http://test.pki.gov.kz/crl/rca_gost2022_test.crl";
    String ROOT_CERT_URL = "http://test.pki.gov.kz/cert/rca_gost2022_test.cer";
    String ROOT_POLICY_URL = "http://root.gov.kz/cps";
    
    
    KeyUsage END_ENTITY_KEY_USAGE = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation);
    KeyUsage SERVICE_KEY_USAGE = new KeyUsage(KeyUsage.digitalSignature);
    String POLICY_URL = "http://pki.gov.kz/cps";
    String INTER_DELTA_CRL_URL = "http://test.pki.gov.kz/crl/nca_gost2022_d_test.crl";
    String INTER_CRL_URL = "http://test.pki.gov.kz/crl/nca_gost2022_test.crl";
    String INTER_CERT_URL = "http://test.pki.gov.kz/cert/nca_gost2022_test.cer";
    String OCSP_URL = "http://test.pki.gov.kz/ocsp/";
    String SUBJECT_DN = "CN=ҚҰНАНБАЙ АБАЙ, SURNAME=ҚҰНАНБАЙ, SN=IIN123456789012, C=KZ, G=ҚҰНАНБАЙҰЛЫ";
    String SUBJECT_LEGAL_CHIEF_DN = "CN=БӨКЕЙХАН ӘЛИХАН, SURNAME=БӨКЕЙХАН, SN=IIN123456789012, C=KZ, O=\"АЛАШ\" ПАРТИЯСЫ, OU=BIN012345678912, G=НҰРМҰХАМЕДҰЛЫ";
    String SUBJECT_LEGAL_SIGNER_DN = "CN=БАЙТҰРСЫН АХМЕТ, SURNAME=БАЙТҰРСЫН, SN=IIN123456789012, C=KZ, O=\"АЛАШ\" ПАРТИЯСЫ, OU=BIN012345678912, G=БАЙТҰРСЫНҰЛЫ";
    String SUBJECT_LEGAL_STAFF_DN = "CN=ДУЛАТ МІРЖАҚЫП, SURNAME=ДУЛАТ, SN=IIN123456789012, C=KZ, O=\"АЛАШ\" ПАРТИЯСЫ, OU=BIN012345678912, G=ДУЛАТҰЛЫ";
    String SUBJECT_OCSP_RESPONDER_DN = "CN=OCSP RESPONDER, C=KZ";
    String SUBJECT_TSA_DN = "CN=TIME-STAMPING AUTHORITY, C=KZ";
    String EMAIL = "knca@pki.gov.kz";
    
}
