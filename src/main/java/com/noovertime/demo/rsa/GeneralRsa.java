package com.noovertime.demo.rsa;

import lombok.extern.slf4j.Slf4j;

import javax.crypto.Cipher;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

@Slf4j
public class GeneralRsa {
	/**
	 * 공개키와 비밀키 생성
	 * @throws Exception 처리 중 예외
	 */
	public void create() throws Exception {
		// 공개키/비밀키 쌍 생성
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance( Constant.ALGORITHM );
		keyPairGenerator.initialize( 2048 );
		KeyPair keyPair = keyPairGenerator.generateKeyPair();


		// keySpec으로 감싸기
		KeyFactory keyFactory = KeyFactory.getInstance( Constant.ALGORITHM );
		// publicKey
		X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec( keyPair.getPublic().getEncoded());
//		KeySpec pubKeySpec = new RSAPublicKeySpec(
//				new BigInteger("18880040408878474925194433633143741098009491583122801467415871340389329596786303677475867551036416110082462043325305181821226092403473667554802862496371015124459397553174226703248073838693582288017798714836252638704062561944492166655644138324749037760163940041058703601095601460828704464036213465425959109701787207810253289206205489640305813454294489866238976441502776507751476581040612820742392745150037043125689283888778320032817177796984533833521994265752751098764971819663809956984119464648516012645292561942707157912846280436687316439536816972098880484924994489057888570339076951885707950987258103713021886745279"),
//				new BigInteger("65537"));
		// Only RSAPublicKeySpec and X509EncodedKeySpec supported for RSA public keys
		PublicKey publicKey = keyFactory.generatePublic(pubKeySpec);


		// privateKey
		PKCS8EncodedKeySpec priKeySpec = new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded());
		PrivateKey privateKey = keyFactory.generatePrivate(priKeySpec);


		// 확인용
//		Utils.log( publicKey );
//		Utils.log( privateKey );


		// 파일로 출력
		Utils.saveBase64Encode("PUBLIC", Path.of(Constant.GENERAL_RSA_PUBLIC_FILE), publicKey.getEncoded());
		Utils.saveBase64Encode("PRIVATE", Path.of(Constant.GENERAL_RSA_PRIVATE_FILE), privateKey.getEncoded());
	}

	/**
	 * 공개키로 암호화
	 * @param value 암호화할 대상
	 * @return 암호화한 결과  (Base64 encoding)
	 * @throws Exception 처리 중 예외
	 */
	public String encrypt(String value) throws Exception {
		// public key 로드
		File publicFile = new File( Constant.GENERAL_RSA_PUBLIC_FILE);
		byte[] publicBytes = Utils.loadBody( publicFile);

		// key로 만들기
		KeyFactory keyFactory = KeyFactory.getInstance( Constant.ALGORITHM);
		EncodedKeySpec keySpec = new X509EncodedKeySpec( Base64.getDecoder().decode(publicBytes) );
		Key publicKey = keyFactory.generatePublic( keySpec );

		// 암호화
		Cipher cipher = Cipher.getInstance( Constant.ALGORITHM );
		cipher.init( Cipher.ENCRYPT_MODE, publicKey);
		byte[] encBytes = cipher.doFinal( value.getBytes(StandardCharsets.UTF_8));


		return new String(Base64.getEncoder().encode( encBytes));
	}

	/**
	 * 복호화
	 * @param encText base64 인코딩된 암호화 문자열
	 * @return 복화화 결과
	 * @throws Exception 처리 중 예외
	 */
	public String decrypt(String encText) throws Exception {
		// privateKey 로드
		File privateFile = new File( Constant.GENERAL_RSA_PRIVATE_FILE);
		byte[] privateBytes = Utils.loadBody( privateFile );

		// key로 만들기
		KeyFactory keyFactory = KeyFactory.getInstance( Constant.ALGORITHM );
		EncodedKeySpec keySpec = new PKCS8EncodedKeySpec( Base64.getDecoder().decode(privateBytes) );
		Key privateKey = keyFactory.generatePrivate( keySpec );

		// base64 decoding
		byte[] encBytes = Base64.getDecoder().decode( encText.getBytes(StandardCharsets.UTF_8));

		// 복호화
		Cipher cipher = Cipher.getInstance( Constant.ALGORITHM);
		cipher.init( Cipher.DECRYPT_MODE, privateKey);
		byte[] decBytes = cipher.doFinal( encBytes );

		return new String(decBytes);
	}
}
