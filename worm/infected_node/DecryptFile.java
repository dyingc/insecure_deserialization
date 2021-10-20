import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.SecretKeySpec;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class DecryptFile {

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

  public static void main(String[] args) throws IOException, GeneralSecurityException, Exception {
    DecryptFile startEnc = new DecryptFile();
    String targetID = "QAsrI6fePOBC5N1UPw5cRiW7pi9ACErO4SKU9Vc42qU";
    if (args.length == 1)
      targetID = args[0];
    String secretKeyFileName = "/tmp/test/Symmetric/encSecretKey";
    String privKeyFileName = "/tmp/test/KeyPair/privKey";
    String originFile = "/tmp/test/myfile";
    File encryptedKeyReceived = new File(secretKeyFileName + "_" + targetID);
    File decreptedKeyFile = new File(secretKeyFileName);
    new DecryptKey(startEnc.getPrivate(privKeyFileName + "_" + targetID, "RSA")
        , encryptedKeyReceived, decreptedKeyFile, "RSA");

    File encryptedFileReceived = new File(originFile + "_" + targetID);
    File decryptedFile = new File("/tmp/test/decrypted/myfile");
    new DecryptData(encryptedFileReceived, decryptedFile, 
        startEnc.getSecretKey(secretKeyFileName, "AES"), "AES");
    // remove the decrypted symmetric key
    try {
      new File(secretKeyFileName).delete();
      // System.out.println("Secret key file: \"" + secretKeyFileName +"\" has been deleted!\n");
    } catch (Exception e) {
      e.printStackTrace();
    }
  }
}

class DecryptData {
  private Cipher cipher;

  public DecryptData(File encryptedFileReceived, File decryptedFile, SecretKeySpec secretKey, String algorithm)
      throws IOException, GeneralSecurityException {
    this.cipher = Cipher.getInstance(algorithm);
    decryptFile(getFileInBytes(encryptedFileReceived), decryptedFile, secretKey);
  }

  public void decryptFile(byte[] input, File output, SecretKeySpec key) throws IOException, GeneralSecurityException {
    this.cipher.init(Cipher.DECRYPT_MODE, key);
    writeToFile(output, this.cipher.doFinal(input));
  }

  private void writeToFile(File output, byte[] toWrite)
      throws IllegalBlockSizeException, BadPaddingException, IOException {
    output.getParentFile().mkdirs();
    FileOutputStream fos = new FileOutputStream(output);
    fos.write(toWrite);
    fos.flush();
    fos.close();
    System.out.println("The file was successfully decrypted. You can view it in: " + output.getPath());
  }

  public byte[] getFileInBytes(File f) throws IOException {
    FileInputStream fis = new FileInputStream(f);
    byte[] fbytes = new byte[(int) f.length()];
    fis.read(fbytes);
    fis.close();
    return fbytes;
  }

}

class DecryptKey {
  private Cipher cipher;

  public DecryptKey(PrivateKey privateKey, File encryptedKeyReceived, File decreptedKeyFile, String algorithm)
      throws IOException, GeneralSecurityException {
    this.cipher = Cipher.getInstance(algorithm);
    decryptFile(getFileInBytes(encryptedKeyReceived), decreptedKeyFile, privateKey);
  }

  public void decryptFile(byte[] input, File output, PrivateKey key) throws IOException, GeneralSecurityException {
    this.cipher.init(Cipher.DECRYPT_MODE, key);
    writeToFile(output, this.cipher.doFinal(input));
  }

  private void writeToFile(File output, byte[] toWrite)
      throws IllegalBlockSizeException, BadPaddingException, IOException {
    output.getParentFile().mkdirs();
    FileOutputStream fos = new FileOutputStream(output);
    fos.write(toWrite);
    fos.flush();
    fos.close();
  }

  public byte[] getFileInBytes(File f) throws IOException {
    FileInputStream fis = new FileInputStream(f);
    byte[] fbytes = new byte[(int) f.length()];
    fis.read(fbytes);
    fis.close();
    return fbytes;
  }
}
