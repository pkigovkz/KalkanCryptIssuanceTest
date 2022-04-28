package kz.gov.pki.kalkan.issuance;


import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.junit.runners.Suite.SuiteClasses;

@SuiteClasses({ RootCertIssuanceTest.class, InterCertIssuanceTest.class, EndEntityCertIssuanceTest.class })
@RunWith(Suite.class)
public class IssuanceSuiteTest {
    
}
