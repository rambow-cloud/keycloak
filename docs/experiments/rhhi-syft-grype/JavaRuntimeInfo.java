import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import javax.naming.ldap.LdapName;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.Security;
import java.util.*;

public class JavaRuntimeInfo {
    static String json(Object value) {
        if (value == null) return "null";
        if (value instanceof Number || value instanceof Boolean) return value.toString();
        if (value instanceof Map<?,?> map) {
            return "{" + String.join(",", map.entrySet().stream().map(e -> json(e.getKey()) + ":" + json(e.getValue())).toList()) + "}";
        }
        if (value instanceof Collection<?> list) return "[" + String.join(",", list.stream().map(JavaRuntimeInfo::json).toList()) + "]";
        return "\"" + value.toString().replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t") + "\"";
    }
    public static void main(String[] args) throws Exception {
        var result = new LinkedHashMap<String,Object>();
        for (String key : List.of("java.version", "java.runtime.version", "java.vendor", "java.vm.name", "java.home", "os.name", "os.arch")) result.put(key, System.getProperty(key));
        result.put("securityProviders", Arrays.stream(Security.getProviders()).map(p -> p.getName()).toList());
        var factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        factory.init((java.security.KeyStore) null);
        var subjects = new HashSet<String>();
        int anchors = 0;
        for (var manager : factory.getTrustManagers()) if (manager instanceof X509TrustManager tm) {
            anchors += tm.getAcceptedIssuers().length;
            for (var cert : tm.getAcceptedIssuers()) for (var rdn : new LdapName(cert.getSubjectX500Principal().getName()).getRdns()) {
                if (rdn.getType().equalsIgnoreCase("CN")) subjects.add(rdn.getValue().toString());
            }
        }
        result.put("trustAnchorCount", anchors);
        result.put("emSignECCG3Present", subjects.contains("emSign ECC Root CA - G3"));
        result.put("aaaCertificateServicesPresent", subjects.contains("AAA Certificate Services"));
        Path store = Path.of(System.getProperty("java.home"), "lib", "security", "cacerts").toRealPath();
        result.put("trustStorePath", store.toString());
        result.put("trustStoreSha256", HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(store))));
        System.out.println(json(result));
    }
}
