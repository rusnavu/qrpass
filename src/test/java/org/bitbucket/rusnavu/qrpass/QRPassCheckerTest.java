package org.bitbucket.rusnavu.qrpass;

import static org.junit.Assert.*;

import java.security.cert.Certificate;
import java.util.Arrays;

import org.junit.*;

public class QRPassCheckerTest extends QRPassChecker {

	private static Certificate[] certificates;

	public QRPassCheckerTest() {
		super(ISignatureFactory.getInstance(QRPassTests.ALGORITHM));
	}

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		certificates = new Certificate[]{QRPassTests.loadCertificate("/test.crt"),
				QRPassTests.loadCertificate("/root.crt")};
	}

	@AfterClass
	public static void tearDownAfterClass() throws Exception {
	}

	@Before
	public void setUp() throws Exception {
		super.setCertificates(Arrays.asList(certificates));
	}

	@After
	public void tearDown() throws Exception {
	}

	@Test
	public void testCrt() throws Exception {
		assertTrue(verify("Name: Иванов Иван Иванович\n" + 
				"Document: паспорт 4507 123456\n" + 
				"Crt: 00DF05C1337A5AFBCD\n" + 
				"Sig: B137CA0BAA9DB359376FD1FE008973793110D4136511817F0EDEA4160A44F23FFA7339984B8ED1EDFA518E114F01E7A5E6C01B04F27B3273EB361CF5C2924A28"));
	}

	@Test
	public void testNoCrt() throws Exception {
		assertTrue(verify("Name: Иванов Иван Иванович\n" + 
				"Document: паспорт 4507 123456\n" + 
				"Sig: A7B4C17086803BEAA4C74DA02E5024FA97EB3708D9E418D29C48CBE43FBF794D61A3C51E86593B05414FDB37390A74BACDBE2A5B1D99E4D4AF9D0017182E181F"));
	}

	@Test
	public void testFail() throws Exception {
		assertFalse(verify("Name: Иванов Иван Иванович\n" + 
				"Document: паспорт 4507 123457\n" + 
				"Sig: A7B4C17086803BEAA4C74DA02E5024FA97EB3708D9E418D29C48CBE43FBF794D61A3C51E86593B05414FDB37390A74BACDBE2A5B1D99E4D4AF9D0017182E181F"));
	}
}
