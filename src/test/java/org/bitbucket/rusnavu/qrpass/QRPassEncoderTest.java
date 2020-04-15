package org.bitbucket.rusnavu.qrpass;

import static org.junit.Assert.*;

import java.security.PrivateKey;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.bitbucket.rusnavu.qrpass.QRPassEncoder;
import org.junit.*;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public class QRPassEncoderTest extends QRPassEncoder {

	private static final String PRIVATE_KEY_RESOURCE = "/private.pem";
	private static PrivateKey privateKey;

	@Parameters
	public static Iterable<Object[]> cases() {
		String[][] pass1 = {
					{"Name", "Иванов Иван Иванович"},
					{"Document", "паспорт 4507 123456"},
					{"Crt", "00DF05C1337A5AFBCD"}
				},
				pass2 = {
						{"Name    ", "Иванов      Иван     Иванович"},
						{"Document", "паспорт     4507     123456"},
						{"Crt", "00DF05C1337A5AFBCD"}
				},
				pass3 = {
						{"ФИО", "Иванов      Иван     Иванович"},
						{"Паспорт", "4507 123456"},
						{"Проживает", "Красная площадь, 1"},
						{"МестоНазначения", "Зубовский, 4"},
						{"Цель", "Подача обращения"},
						{"Crt", "00DF05C1337A5AFBCD"}
				},
				pass4 = {
						{"Name    ", "Иванов      Иван     Иванович"},
						{"Document", "паспорт     4507     123456"}
				};
		return Arrays.asList(new Object[][] {
			{pass1, "B137CA0BAA9DB359376FD1FE008973793110D4136511817F0EDEA4160A44F23FFA7339984B8ED1EDFA518E114F01E7A5E6C01B04F27B3273EB361CF5C2924A28"},
			{pass2, "B137CA0BAA9DB359376FD1FE008973793110D4136511817F0EDEA4160A44F23FFA7339984B8ED1EDFA518E114F01E7A5E6C01B04F27B3273EB361CF5C2924A28"},
			{pass3, "9A842AC000907B94E6E7846D9297378F1ECDC9C0F4235703D6B30C2E8E6C18D348FCD16B5EB99D18266EF5B0BDB2C201930E5D8E460A9BF9202EF4DC9F839E45"},
			{pass4, "A7B4C17086803BEAA4C74DA02E5024FA97EB3708D9E418D29C48CBE43FBF794D61A3C51E86593B05414FDB37390A74BACDBE2A5B1D99E4D4AF9D0017182E181F"}
		});
	}

	public QRPassEncoderTest() {
		super(ISignatureFactory.getInstance(QRPassTests.ALGORITHM));
	}

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		privateKey = QRPassTests.loadPrivateKey(PRIVATE_KEY_RESOURCE);
	}

	@AfterClass
	public static void tearDownAfterClass() throws Exception {
	}

	@Parameter(0)
	public String[][] pass;
	@Parameter(1)
	public String signature;

	@Before
	public void setUp() throws Exception {
		setPrivateKey(privateKey);
	}

	private Map<String, String> toMap(String[][] array) {
		Map<String, String> data = new LinkedHashMap<>(array.length);
		for (String[] row : array) {
			assertTrue(row.length == 2);
			data.put(row[0], row[1]);
		}
		return data;
	}

	@After
	public void tearDown() throws Exception {
	}

	@Test
	public void testEncode() throws Exception {
		String encoded = encode(toMap(pass));
		assertTrue("Too large", encoded.length() < 1000);
		for (String[] row : pass) {
			String expected = transform(row[0]) + ": " + transform(row[1]);
			assertTrue(encoded.contains(expected));
		}
		assertTrue(encoded.contains(QRBase.SIGNATURE_KEY + ": "));
		Matcher matcher = Pattern.compile("(?i)" + QRBase.SIGNATURE_KEY + ": ([0-9a-f]+)").matcher(encoded);
		assertTrue(matcher.find());
		assertEquals(signature, matcher.group(1));
	}

}
