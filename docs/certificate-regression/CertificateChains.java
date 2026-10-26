import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.time.Instant;
import java.util.*;
import javax.net.ssl.*;

public class CertificateChains {
  static final CertificateFactory FACTORY;
  static { try { FACTORY = CertificateFactory.getInstance("X.509"); } catch (Exception e) { throw new ExceptionInInitializerError(e); } }
  static List<X509Certificate> certificates(Path path) throws Exception {
    try (var stream = Files.newInputStream(path)) {
      return FACTORY.generateCertificates(stream).stream().map(c -> (X509Certificate)c).toList();
    }
  }
  static String digest(byte[] bytes) throws Exception { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
  static String quote(String value) { return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r") + "\""; }
  static void validate(List<X509Certificate> chain, Set<TrustAnchor> anchors, Date date) throws Exception {
    if (chain.size() < 2) throw new Exception("Incomplete certificate chain");
    for (var cert : chain) cert.checkValidity(date);
    for (int i = 0; i < chain.size() - 1; i++) chain.get(i).verify(chain.get(i + 1).getPublicKey());
    var target = new X509CertSelector(); target.setCertificate(chain.get(0));
    var params = new PKIXBuilderParameters(anchors, target);
    params.setDate(date); params.setRevocationEnabled(false);
    params.addCertStore(CertStore.getInstance("Collection", new CollectionCertStoreParameters(chain)));
    CertPathBuilder.getInstance("PKIX").build(params);
  }
  public static void main(String[] args) throws Exception {
    if (args.length != 3) throw new Exception("Expected fixture directory, incident validation time and normal-control time");
    if (Runtime.version().feature() != 25) throw new Exception("Expected the published image Java 25");
    var dir = Path.of(args[0]); var date = Date.from(Instant.parse(args[1])); var positiveDate = Date.from(Instant.parse(args[2]));
    var factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()); factory.init((KeyStore)null);
    var manager = Arrays.stream(factory.getTrustManagers()).filter(t -> t instanceof X509TrustManager).map(t -> (X509TrustManager)t).findFirst().orElseThrow();
    var anchors = new HashSet<TrustAnchor>();
    for (var cert : manager.getAcceptedIssuers()) {
      if (cert.getSubjectX500Principal().getName().matches(".*CN=(emSign ECC Root CA - G3|AAA Certificate Services)(,.*)?")) throw new Exception("Distrusted root remains in default anchors");
      anchors.add(new TrustAnchor(cert, null));
    }
    if (anchors.isEmpty()) throw new Exception("Default trust store is empty");
    validate(certificates(dir.resolve("positive.crt")), anchors, positiveDate);
    var restored = new HashSet<>(anchors); var roots = certificates(dir.resolve("restored-roots.crt"));
    if (roots.size() != 2) throw new Exception("Expected exactly two restored control roots");
    for (var root : roots) restored.add(new TrustAnchor(root, null));
    var rows = new ArrayList<String>();
    try (var files = Files.list(dir.resolve("chains"))) {
      for (var file : files.filter(p -> p.toString().endsWith(".pem")).sorted().toList()) {
        var chain = certificates(file); String reason;
        try { validate(chain, anchors, date); throw new Exception("Compromised chain was trusted: " + file.getFileName()); }
        catch (CertPathBuilderException rejected) {
          reason = rejected.getMessage();
          if (!reason.contains("unable to find valid certification path")) throw rejected;
        }
        // The identical certificates/date/algorithms must succeed when only the
        // removed anchors are restored. Expiry, invalid signatures and a broken
        // validator cannot masquerade as successful distrust.
        validate(chain, restored, date);
        rows.add("{\"name\":" + quote(file.getFileName().toString()) + ",\"sha256\":" + quote(digest(Files.readAllBytes(file))) +
          ",\"defaultTrust\":\"rejected\",\"reason\":" + quote(reason) + ",\"restoredRootsControl\":\"accepted\"}");
      }
    }
    if (rows.size() != 14) throw new Exception("Expected exactly 14 tested incident chains");
    var home = Path.of(System.getProperty("java.home")); var store = home.resolve("lib/security/cacerts").toRealPath();
    System.out.println("{\"schemaVersion\":1,\"status\":\"passed\",\"java\":" + quote(Runtime.version().toString()) +
      ",\"vendor\":" + quote(System.getProperty("java.vendor")) + ",\"os\":" + quote(System.getProperty("os.name")) +
      ",\"architecture\":" + quote(System.getProperty("os.arch")) + ",\"defaultAnchors\":" + anchors.size() +
      ",\"trustStore\":" + quote(store.toString()) + ",\"trustStoreSha256\":" + quote(digest(Files.readAllBytes(store))) +
      ",\"securityConfigurationSha256\":" + quote(digest(Files.readAllBytes(home.resolve("conf/security/java.security")))) +
      ",\"blockedCertificatesSha256\":" + quote(digest(Files.readAllBytes(home.resolve("lib/security/blocked.certs")))) +
      ",\"positiveControl\":\"accepted\",\"revocationChecking\":false,\"incidentValidationTime\":" + quote(args[1]) +
      ",\"positiveValidationTime\":" + quote(args[2]) + ",\"chains\":[" + String.join(",", rows) + "]}");
  }
}
