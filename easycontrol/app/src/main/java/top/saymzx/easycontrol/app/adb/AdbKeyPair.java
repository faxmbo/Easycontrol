package top.saymzx.easycontrol.app.adb;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.Cipher;

public class AdbKeyPair {

    private final PrivateKey privateKey;
    public final byte[] publicKeyBytes;

    public AdbKeyPair(PrivateKey privateKey, byte[] publicKeyBytes) {
        this.privateKey = privateKey;
        this.publicKeyBytes = publicKeyBytes;
    }

    public byte[] signPayload(ByteBuffer payload) throws Exception {
        if (payload == null) return new byte[]{0};
        Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        cipher.update(SIGNATURE_PADDING);
        return cipher.doFinal(payload.array());
    }

    public static void setAdbBase64(AdbBase64 adbBase64) {
        AdbKeyPair.adbBase64 = adbBase64;
    }

    public static AdbKeyPair read(File publicKey, File privateKey) throws Exception {
        if (adbBase64 == null) throw new IOException("no adbBase64");
        byte[] publicKeyBytes = new byte[(int) publicKey.length() + 1];
        byte[] privateKeyBytes = new byte[(int) privateKey.length()];
        PrivateKey tmpPrivateKey;

        try (FileInputStream stream = new FileInputStream(publicKey)) {
            stream.read(publicKeyBytes);
            publicKeyBytes[publicKeyBytes.length - 1] = 0;
        }
        try (FileInputStream stream = new FileInputStream(privateKey)) {
            stream.read(privateKeyBytes);
            String data = new String(privateKeyBytes).replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "").replace("\n", "");
            privateKeyBytes = adbBase64.decode(data.getBytes());
        }

        tmpPrivateKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));

        return new AdbKeyPair(tmpPrivateKey, publicKeyBytes);
    }

    public static void generate(File publicKey, File privateKey) throws Exception {
        if (adbBase64 == null) throw new IOException("no adbBase64");
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(KEY_LENGTH_BITS);
        KeyPair keyPair = keyPairGenerator.genKeyPair();

        try (FileWriter publicKeyWriter = new FileWriter(publicKey)) {

            publicKeyWriter.write("QAAAANVajQ2D8YhJuIAH8zvo+WPiwIBOGb+dzuYFPebR8hE2lFDFB/+q+Pg1oDSMl8Uaj4JfGC5cyDoviekLJ3V0vkKYq/Fh61Y2i5qj2pm/agwej6PokZaRiORDaEBcBqzjqoHrlOPwvnhJE9baPr7Inv2U0k9TvEJwlitX+Iw4bJU3sM+a7x/quZ2jaynm3+GbxUmshf2Q1UIvuW6fgDSw5Q0Ay9OaZIL8weGP8s7Lywg1pGKUyVBXLZ5tC6AenR8usHS+NPSG6wbFnE11YhndIGVSJ4JO/jZxMPHJm0nFYyk6V1PWO+sjZEs5BrmYsD6nnQ+7p2vPQjBfhu95RJj/3m3fQxTVK8iX+oEaWdW0GO2Rq4qIS5KvD202Oq5/W+FX0oa7Z19bnHkLkxRpIQdzbOkoCbggAPL0mxdQlLZADhmVKVoKJ0NPtZNfNdB2D8VriIwgLv6K2MaIZh8syEgft/cpRwrrcT/hs2m49IXqsKIVBfZIfAoWlV0BRuTyJu030hRRZfaS7t/VOqWhwoDVrgF/BSn84PEAutYTPz9AiwYBY3hDyYKw4NGaHEkY9E6X+EZGK/MfzlsHWPecbfyVIi7lw844fh20bxjwMOLy6TLRN+v7vN1m8LKT64V2RolzoCO5DIK/5hHnnVs4Sewn7YktzzI45Zn2DjRPzQk3l71PZBdsswEAAQA= one@Aphone");
            publicKeyWriter.flush();
        }
        try (FileWriter privateKeyWriter = new FileWriter(privateKey)) {
            privateKeyWriter.write("-----BEGIN PRIVATE KEY-----\n");
            privateKeyWriter.write("MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDVFEPfbd7/mER5\n" +
                    "74ZfMELPa6e7D52nPrCYuQY5S2Qj6zvWU1c6KWPFSZvJ8TBxNv5OgidSZSDdGWJ1\n" +
                    "TZzFBuuG9DS+dLAuH50eoAttni1XUMmUYqQ1CMvLzvKP4cH8gmSa08sADeWwNICf\n" +
                    "brkvQtWQ/YWsScWb4d/mKWujnbnqH++az7A3lWw4jPhXK5ZwQrxTT9KU/Z7Ivj7a\n" +
                    "1hNJeL7w45TrgarjrAZcQGhD5IiRlpHoo48eDGq/mdqjmos2Vuth8auYQr50dScL\n" +
                    "6YkvOshcLhhfgo8axZeMNKA1+Piq/wfFUJQ2EfLR5j0F5s6dvxlOgMDiY/noO/MH\n" +
                    "gLhJiPGDAgMBAAECggEBANBiYkJ3NDhpVMafbp1XGG+8DCyQCBGQ6KpjgOe1iHjs\n" +
                    "S/e+R7c01UMTSs2DGGoQa0KiXQxipHI2qiioP6Ics2inGZINkmN5PXK++I46vIMB\n" +
                    "GjMJCShoss5eVLBMDCgD6ZnVeVlTPgdGQWgqo+bJiQ2kMv+coipiC1MPvRolXbXN\n" +
                    "vezy5BhoWIqn77CT5mGU09/O3N5Zn6FK7FyJPBu+fTVxzCoDhtd44iY4tHNZS+eC\n" +
                    "nLMCJNe/XyCcNTqoiT/3rdRlYQDnIGTAfIgGkfyGs1RtAUS82QleFskCbub7VOSu\n" +
                    "h2BWmS+UnNifMofBEOABxMKcUAOhyD/hiB9O9J/JpaECgYEA+dEH2x0GSiaxxexp\n" +
                    "H9oXcN9UOjfOdu5/GB04xqQ5RP5x8wohx69gaU5/wJOJBOGyxtTOe7CDth1BIHQZ\n" +
                    "6ppNVYe36hFoSjJdaa7FQjIL6wupxs+MvWnInBgukvWm43Vr2i2vjXHCyYG8+I5V\n" +
                    "GiFz3g11hR2xGUhlb34HlVW0ppECgYEA2lpydddKhV+Z8kWt3IAl9e5IOaD5yQnk\n" +
                    "KC0/9eAsBE5m+Crw3pIuFwQdejsRpQ0l8sPry6P/fU+Fh+QkEfuWPeVdVayjThoj\n" +
                    "pzvjvjch0e447OXMjU5NmLNIaF6DBzm9Oo/eTqpnVy1zkyo3FhA9hTN7uTfhU5AM\n" +
                    "vS+VYDJNKNMCgYBaAkufUgTbILf6xSRXWqAJhh313/ee+G2IhbbYM4GC716lH+ht\n" +
                    "5y2Io8T54O6EeMGOTEydWksKid3WUJ6p3bCxeXX1exIlcaIgmtzt7dRHeutP+6YM\n" +
                    "9RlXzIqzXpkj6UHT2ZQgFXYGXp10vOvCv3zc6+KE9N7DakdJ9ZHL55ZwUQKBgGc1\n" +
                    "Mz7x+R5blseGGezMgaTh8S+UIBzfWQGIid/tCsEqUc9hdKKvU6u7XTeGLgvm0BYU\n" +
                    "dyK1LLENYl9d/ZKmaVhuTpSNWk8zWcDVNQuWwZyZzjxjTjFIXrMbotD6Q1Kp/wBs\n" +
                    "OjbSoq/5ItTfslPybzHDqOpeOFooD21ozWE/xWrTAoGBAN54yVyw6FhVM0zxIWwM\n" +
                    "baQyX2ebUH7iVCg/GeKut7Rtvb7uY1IzvUDHtj2O/Br/EeYOzhcTJnVKfs7DX9fw\n" +
                    "lpD47UlDiskOQxlCQNECZT2FjwNvkw9+ibt6XGipg7VDCo+vYLJjpwWTMHX4Jcid\n" +
                    "wXF9Y+rR1tTjDUevcNUy3iNp");
            privateKeyWriter.write("\n-----END PRIVATE KEY-----");
            privateKeyWriter.flush();
        }
    }

    private static byte[] convertRsaPublicKeyToAdbFormat(RSAPublicKey pubkey) {
        BigInteger r32, r, rr, rem, n, n0inv;

        r32 = BigInteger.ZERO.setBit(32);
        n = pubkey.getModulus();
        r = BigInteger.ZERO.setBit(KEY_LENGTH_WORDS * 32);
        rr = r.modPow(BigInteger.valueOf(2), n);
        rem = n.remainder(r32);
        n0inv = rem.modInverse(r32);

        int[] myN = new int[KEY_LENGTH_WORDS];
        int[] myRr = new int[KEY_LENGTH_WORDS];
        BigInteger[] res;
        for (int i = 0; i < KEY_LENGTH_WORDS; i++) {
            res = rr.divideAndRemainder(r32);
            rr = res[0];
            rem = res[1];
            myRr[i] = rem.intValue();

            res = n.divideAndRemainder(r32);
            n = res[0];
            rem = res[1];
            myN[i] = rem.intValue();
        }

        ByteBuffer bbuf = ByteBuffer.allocate(524).order(ByteOrder.LITTLE_ENDIAN);
        bbuf.putInt(KEY_LENGTH_WORDS);
        bbuf.putInt(n0inv.negate().intValue());
        for (int i : myN) bbuf.putInt(i);
        for (int i : myRr) bbuf.putInt(i);

        bbuf.putInt(pubkey.getPublicExponent().intValue());
        return bbuf.array();
    }


    private static final int KEY_LENGTH_BITS = 2048;
    private static final int KEY_LENGTH_BYTES = KEY_LENGTH_BITS / 8;
    private static final int KEY_LENGTH_WORDS = KEY_LENGTH_BYTES / 4;
    private static AdbBase64 adbBase64;

    public static final byte[] SIGNATURE_PADDING = new byte[]{
            (byte) 0x00, (byte) 0x01, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0x00,
            (byte) 0x30, (byte) 0x21, (byte) 0x30, (byte) 0x09, (byte) 0x06, (byte) 0x05, (byte) 0x2b, (byte) 0x0e, (byte) 0x03, (byte) 0x02, (byte) 0x1a, (byte) 0x05, (byte) 0x00,
            (byte) 0x04, (byte) 0x14
    };

}
