package net.slightlymagic.thefiremind;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.MissingOptionException;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class ZedToZip {
  // Public Key
  private static final BigInteger n = new BigInteger("0095BC0FDBB0EEF370ACE10BB8241FB6102BB9B67EA8FE65237785C9FCA453D2ACEBFF8929C2F5F5834BB2141EDFCA370403831324872F89D08A9B893E2CD5EA2B6F862BE6375BD1955F764E077C1E1913DF226E5BA7FA7DEBFD703E4560085D4D4612A7D6EC27FB6F4A4CE4BBF079DA7E87FDD2FD6E80AFEB2F1977D3A3C83C8D9E12EBC63446C12E37BA47ECD9591145417B3754C056EB7C64DAFEA0A4222F243A556B99432FF267B020FAC8FA7768B9FA721BCF14DC422F4263F9DD42498C35E1D11E8B3A15249DEB95371AC1E5026E7648284C36F2BB706388DBAD92E83BED21581D0DB553563BC05CE212A1340DA789C25170971190789D349330F11E8E75", 16);
  private static final BigInteger e = new BigInteger("11", 16);

  private static MessageDigest sha1;

  public static void main(String[] args) {
    Options options = new Options();
    options.addOption("h", "help", false, "Print this message");
    options.addOption("i", "input", true, "Specify input ZED file");
    options.addOption("o", "output", true, "Specify output ZIP file");
    options.addOption("f", "force", false, "Override output file if exist");

    boolean printHelp;
    boolean force = false;
    Path inputFilePath = null;
    Path outputFilePath = null;
    CommandLineParser parser = new DefaultParser();
    try {
      CommandLine cmd = parser.parse(options, args);

      printHelp = cmd.hasOption("h");

      if (cmd.hasOption("i")) {
        inputFilePath = Paths.get(cmd.getOptionValue("i"));
      } else {
        throw new MissingOptionException("Missing required option: i");
      }

      if (cmd.hasOption("o")) {
        outputFilePath = Paths.get(cmd.getOptionValue("o"));
      } else {
        String inputFileName = inputFilePath.getFileName().toString();
        String outputFileName = inputFileName.substring(0, inputFileName.lastIndexOf('.')) + ".zip";

        outputFilePath = inputFilePath.resolveSibling(outputFileName);
      }

      force = cmd.hasOption("f");

      if (Files.exists(outputFilePath) && !force) {
        throw new IllegalAccessError("Output file exist: " + outputFilePath.toString());
      }
    } catch (ParseException ex) {
      System.err.println(ex.getLocalizedMessage());
      printHelp = true;
    }

    if (printHelp) {
      String selfName = new java.io.File(ZedToZip.class.getProtectionDomain()
        .getCodeSource()
        .getLocation()
        .getPath())
        .getName();
      HelpFormatter formatter = new HelpFormatter();
      formatter.printHelp("java -jar " + selfName, options);
    } else {
      try {
        sha1 = MessageDigest.getInstance("SHA-1");
      } catch (NoSuchAlgorithmException ex) {
        System.err.println("Cannot initialize SHA-1 digest algorithm on your device.");
        System.exit(2);
      }

      try {
        convert(inputFilePath.toFile(), outputFilePath.toFile());
      } catch (IOException ex) {
        ex.printStackTrace();
      }
    }
  }

  private static void convert(File inputFile, File outputFile) throws IOException {
    // Files
    RandomAccessFile zedFile = new RandomAccessFile(inputFile, "r");
    RandomAccessFile zipFile = new RandomAccessFile(outputFile, "rw");

    // Read Offset and Size of Central Directory
    byte[] fileContent;
    zedFile.seek(zedFile.length() - 8);
    zedFile.read(fileContent = new byte[8]);
    for (int i = 7; i > 0; i--)
      fileContent[i] ^= fileContent[i - 1];
    fileContent[0] ^= fileContent[7];
    int centralDirOffset = ((fileContent[7] & 0xFF) << 24) | ((fileContent[5] & 0xFF) << 16) | ((fileContent[3] & 0xFF) << 8) | (fileContent[1] & 0xFF);
    int centralDirSize = ((fileContent[6] & 0xFF) << 24) | ((fileContent[4] & 0xFF) << 16) | ((fileContent[2] & 0xFF) << 8) | (fileContent[0] & 0xFF);

    // Read first 256 bytes of Central Directory
    zedFile.seek(centralDirOffset);
    fileContent = new byte[257];
    zedFile.read(fileContent, 1, 256);
    fileContent[0] = 0;     // c must be considered positive
    // Decode first 256 bytes
    fileContent = DecodeFirst256B(fileContent);
    centralDirSize -= 256 - fileContent.length;       // New Central Directory Size
    byte[] centralDir = new byte[centralDirSize];
    System.arraycopy(fileContent, 0, centralDir, 0, fileContent.length);
    // Read rest of Central Directory
    zedFile.read(centralDir, fileContent.length, centralDirSize - fileContent.length);
    // Xor
    for (int i = centralDirSize - 1; i > 0; i--)
      centralDir[i] ^= centralDir[i - 1];
    centralDir[0] ^= centralDir[centralDirSize - 1];

    int pt = 0;
    int localFileCompSize;
    int localFileOffset;
    int localFileNameLen;
    byte[] localFileData;
    byte[] localFileHeader;
    int entries = 0;
    while (pt < centralDirSize - 1) {     //Scan Central Dir
      localFileOffset = ((centralDir[pt + 45] & 0xFF) << 24) | ((centralDir[pt + 44] & 0xFF) << 16) | ((centralDir[pt + 43] & 0xFF) << 8) | (centralDir[pt + 42] & 0xFF);
      localFileCompSize = ((centralDir[pt + 23] & 0xFF) << 24) | ((centralDir[pt + 22] & 0xFF) << 16) | ((centralDir[pt + 21] & 0xFF) << 8) | (centralDir[pt + 20] & 0xFF);
      localFileData = new byte[0];
      if (localFileCompSize > 0) {        // Not a Directory
        if (centralDir[pt + 10] == 8) {      // Local File is compressed
          // Read first 256 bytes of Local File
          zedFile.seek(localFileOffset);
          fileContent = new byte[257];
          zedFile.read(fileContent, 1, 256);
          fileContent[0] = 0; // c must be considered positive
          // Decode first 256 bytes
          fileContent = DecodeFirst256B(fileContent);
          localFileCompSize -= 256 - fileContent.length;        // New Local File Compressed Size
          centralDir[pt + 20] = (byte) (localFileCompSize & 0xFF);
          centralDir[pt + 21] = (byte) ((localFileCompSize >> 8) & 0xFF);
          centralDir[pt + 22] = (byte) ((localFileCompSize >> 16) & 0xFF);
          centralDir[pt + 23] = (byte) ((localFileCompSize >> 24) & 0xFF);
          localFileData = new byte[localFileCompSize];
          System.arraycopy(fileContent, 0, localFileData, 0, fileContent.length);
          // Read rest of Local File
          zedFile.read(localFileData, fileContent.length, localFileCompSize - fileContent.length);
          // Xor
          for (int i = localFileCompSize - 1; i > 0; i--)
            localFileData[i] ^= localFileData[i - 1];
          localFileData[0] ^= 0x53;
        } else {
          // Read Local File
          localFileData = new byte[localFileCompSize];
          zedFile.read(localFileData, 0, localFileCompSize);
        }
      }
      localFileOffset = (int) zipFile.getFilePointer();     // New Local File Offset
      centralDir[pt + 42] = (byte) (localFileOffset & 0xFF);
      centralDir[pt + 43] = (byte) ((localFileOffset >> 8) & 0xFF);
      centralDir[pt + 44] = (byte) ((localFileOffset >> 16) & 0xFF);
      centralDir[pt + 45] = (byte) ((localFileOffset >> 24) & 0xFF);

      // Create Local File Header
      localFileNameLen = ((centralDir[pt + 29] & 0xFF) << 8) | (centralDir[pt + 28] & 0xFF);
      localFileHeader = new byte[30 + localFileNameLen];
      localFileHeader[0] = 0x50;
      localFileHeader[1] = 0x4B;       // Signature
      localFileHeader[2] = 0x03;
      localFileHeader[3] = 0x04;       // Signature
      System.arraycopy(centralDir, pt + 6, localFileHeader, 4, 24);
      localFileHeader[28] = 0;
      localFileHeader[29] = 0;       // Extra Field Length
      System.arraycopy(centralDir, pt + 46, localFileHeader, 30, localFileNameLen);     //Local File Name

      // Write Local File
      zipFile.write(localFileHeader);
      zipFile.write(localFileData);
      entries += 1;
      pt += localFileNameLen + 82;
    }

    // Write Central Directory
    centralDirOffset = (int) zipFile.getFilePointer();       // New Central Directory Offset
    zipFile.write(centralDir);

    // Write End of Central Directory
    byte[] endOfCentralDir = new byte[22];
    endOfCentralDir[0] = 0x50;
    endOfCentralDir[1] = 0x4B;       // Signature
    endOfCentralDir[2] = 0x05;
    endOfCentralDir[3] = 0x06;       // Signature
    endOfCentralDir[4] = 0;
    endOfCentralDir[5] = 0;
    endOfCentralDir[6] = 0;
    endOfCentralDir[7] = 0;
    endOfCentralDir[8] = (byte) (entries & 0xFF);            // Disk Entries
    endOfCentralDir[9] = (byte) ((entries >> 8) & 0xFF);       // Disk Entries
    endOfCentralDir[10] = endOfCentralDir[8];       // Total Entries
    endOfCentralDir[11] = endOfCentralDir[9];       // Total Entries
    endOfCentralDir[12] = (byte) (centralDirSize & 0xFF);            // Central Directory Size
    endOfCentralDir[13] = (byte) ((centralDirSize >> 8) & 0xFF);       // Central Directory Size
    endOfCentralDir[14] = (byte) ((centralDirSize >> 16) & 0xFF);      // Central Directory Size
    endOfCentralDir[15] = (byte) ((centralDirSize >> 24) & 0xFF);      // Central Directory Size
    endOfCentralDir[16] = (byte) (centralDirOffset & 0xFF);              // Central Directory Offset
    endOfCentralDir[17] = (byte) ((centralDirOffset >> 8) & 0xFF);         // Central Directory Offset
    endOfCentralDir[18] = (byte) ((centralDirOffset >> 16) & 0xFF);        // Central Directory Offset
    endOfCentralDir[19] = (byte) ((centralDirOffset >> 24) & 0xFF);        // Central Directory Offset
    endOfCentralDir[20] = 0;
    endOfCentralDir[21] = 0;       // Comment Length
    zipFile.write(endOfCentralDir);
    zipFile.close();
    zedFile.close();
  }

  @SuppressWarnings("ConstantConditions")
  private static byte[] DecodeFirst256B(byte[] content) {
    BigInteger c = new BigInteger(content);
    BigInteger r = c.modPow(e, n);
    content = r.toByteArray();
    byte[] result = new byte[256];
    if (content.length == 256)
      result = content;
    else if (content.length > 256)
      System.arraycopy(content, 1, result, 0, 256);
    else if (content.length < 256)
      System.arraycopy(content, 0, result, 256 - content.length, content.length);
    byte[] m = new byte[24];
    System.arraycopy(result, 235, m, 0, 20);
    m[20] = 0;
    m[21] = 0;
    m[22] = 0;
    byte[] mask = new byte[240];
    for (int i = 0; i < 12; i++) {
      m[23] = (byte) i;
      content = sha1.digest(m);
      System.arraycopy(content, 0, mask, i * 20, 20);
    }
    for (int i = 0; i < 235; i++)
      result[i] ^= mask[i];
    int zeroes = 0;
    // Remove non-data bytes
    if (result[zeroes] == -0x80)
      zeroes++;
    while (result[zeroes] == 0)
      zeroes++;
    byte[] decoded = new byte[214 - zeroes];
    System.arraycopy(result, zeroes + 1, decoded, 0, decoded.length);
    return decoded;
  }
}
