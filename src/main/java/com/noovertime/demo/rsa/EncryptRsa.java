package com.noovertime.demo.rsa;

import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class EncryptRsa {


	private PBEParameterSpec createPBEParameterSpec() {
		SecureRandom random = new SecureRandom();
		byte[] salt = new byte[8];
		random.nextBytes( salt );

		return new PBEParameterSpec(salt, 20);
	}

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
		// Only RSAPublicKeySpec and X509EncodedKeySpec supported for RSA public keys
		PublicKey publicKey = keyFactory.generatePublic( pubKeySpec);

		// privateKey
		PBEParameterSpec pbParamSpec = this.createPBEParameterSpec();
		SecretKeyFactory priKeyFactory = SecretKeyFactory.getInstance( Constant.ENCRYPT_RSA_KEY_ALGORITHM);
		SecretKey priSecretKey = priKeyFactory.generateSecret( new PBEKeySpec( Constant.ENCRYPT_RSA_PASSWORD) );
		Cipher priCipher = Cipher.getInstance( Constant.ENCRYPT_RSA_KEY_ALGORITHM);
		priCipher.init( Cipher.ENCRYPT_MODE, priSecretKey, pbParamSpec);
		byte[] priEncBytes = priCipher.doFinal( keyPair.getPrivate().getEncoded() );

		AlgorithmParameters algoParam = AlgorithmParameters.getInstance( Constant.ENCRYPT_RSA_KEY_ALGORITHM);
		algoParam.init( pbParamSpec );
		EncryptedPrivateKeyInfo enPriInfo = new EncryptedPrivateKeyInfo( algoParam, priEncBytes );
		byte[] priBytes = enPriInfo.getEncoded();

		// 확인용
//		Utils.log( publicKey );


		// 파일로 출력
		Utils.saveBase64Encode( "PUBLIC", Path.of( Constant.ENCRYPT_RSA_PUBLIC_FILE), publicKey.getEncoded());
		Utils.saveBase64Encode( "ENCRYPTED PRIVATE", Path.of( Constant.ENCRYPT_RSA_PRIVATE_FILE), priBytes);
	}

	/**
	 * 공개키로 암호화
	 * @param value 암호화할 대상
	 * @return 암호화한 결과  (Base64 encoding)
	 * @throws Exception 처리 중 예외
	 */
	public String encrypt(String value) throws Exception {
		// public key 로드
		File publicFile = new File( Constant.ENCRYPT_RSA_PUBLIC_FILE);
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
		File privateFile = new File( Constant.ENCRYPT_RSA_PRIVATE_FILE);
		byte[] privateBytes = Utils.loadBody( privateFile );

		// 암호화된 개인 키 읽어오고
		EncryptedPrivateKeyInfo encPriInfo = new EncryptedPrivateKeyInfo( Base64.getDecoder().decode( privateBytes));

		// 사용하기 위해 복호화
		SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance( encPriInfo.getAlgName());
		SecretKey secretKey = secretKeyFactory.generateSecret( new PBEKeySpec( Constant.ENCRYPT_RSA_PASSWORD));
		Cipher cipher = Cipher.getInstance( encPriInfo.getAlgName());
		cipher.init( Cipher.DECRYPT_MODE, secretKey, encPriInfo.getAlgParameters() );
		PKCS8EncodedKeySpec pkcsKeySpec = encPriInfo.getKeySpec( cipher );

		// 사용할 수 있게 개인키로 뽑기
		PrivateKey privateKey = KeyFactory.getInstance( Constant.ALGORITHM )
				.generatePrivate( pkcsKeySpec );

		// base64 decoding
		byte[] encBytes = Base64.getDecoder().decode( encText.getBytes(StandardCharsets.UTF_8));

		// 복호화
		cipher = Cipher.getInstance( Constant.ALGORITHM);
		cipher.init( Cipher.DECRYPT_MODE, privateKey);
		byte[] decBytes = cipher.doFinal( encBytes );

		return new String(decBytes);
	}
}
