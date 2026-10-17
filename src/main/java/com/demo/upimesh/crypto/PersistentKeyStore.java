package com.demo.upimesh.crypto;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.*;
import java.security.spec.*;
import java.io.*;
import java.util.Properties;
import java.util.Base64;
/** Persistent prototype keys. Protect the key directory and its backups. */
@Component
public class PersistentKeyStore {
    @Value("${upi.mesh.key-directory:./data/keys}") private String directory;
    public synchronized KeyPair loadOrCreate(String name, String algorithm) throws Exception {
        Path dir = Path.of(directory);
        Files.createDirectories(dir);
        boolean posix = Files.getFileStore(dir).supportsFileAttributeView("posix");
        if (posix) Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwx------"));
        Path file = dir.resolve(name + ".properties");
        if (Files.exists(file)) {
            Properties props = new Properties();
            try (InputStream in = Files.newInputStream(file)) { props.load(in); }
            KeyFactory factory = KeyFactory.getInstance(algorithm);
            return new KeyPair(factory.generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(props.getProperty("public")))),
                factory.generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(props.getProperty("private")))));
        }
        KeyPairGenerator gen = KeyPairGenerator.getInstance(algorithm);
        if (algorithm.equals("EC")) gen.initialize(new ECGenParameterSpec("secp256r1")); else gen.initialize(2048);
        KeyPair pair = gen.generateKeyPair();
        Properties props = new Properties();
        props.setProperty("public", Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()));
        props.setProperty("private", Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()));
        Path temp = Files.createTempFile(dir, name, ".tmp");
        try {
            if (posix) Files.setPosixFilePermissions(temp, PosixFilePermissions.fromString("rw-------"));
            try (OutputStream out = Files.newOutputStream(temp)) { props.store(out, "Prototype key material"); }
            Files.move(temp, file, StandardCopyOption.ATOMIC_MOVE);
        } finally { Files.deleteIfExists(temp); }
        return pair;
    }
}
