import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.MapMaker;
import com.google.common.base.Splitter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Properties;

// A bounded compatibility probe on the actual distribution classpath, before reaugmentation.
public class GuavaCompatibility {
    public static void main(String[] args) throws Exception {
        Properties metadata = new Properties();
        try (var input = ImmutableList.class.getResourceAsStream("/META-INF/maven/com.google.guava/guava/pom.properties")) {
            if (input == null) throw new IllegalStateException("Guava version metadata missing");
            metadata.load(input);
        }
        if (!args[0].equals(metadata.getProperty("version"))) throw new IllegalStateException("Wrong Guava payload");
        if (!"value".equals(ImmutableMap.of("key", "value").get("key"))) throw new IllegalStateException("ImmutableMap failed");
        if (!ImmutableList.of("one", "two").equals(Splitter.on(',').splitToList("one,two"))) throw new IllegalStateException("Splitter failed");
        var map = new MapMaker().weakKeys().makeMap();
        map.put("key", "value");
        if (!"value".equals(map.get("key"))) throw new IllegalStateException("MapMaker failed");
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (var output = new ObjectOutputStream(bytes)) { output.writeObject(ImmutableList.of("one", "two")); }
        try (var input = new ObjectInputStream(new ByteArrayInputStream(bytes.toByteArray()))) {
            if (!ImmutableList.of("one", "two").equals(input.readObject())) throw new IllegalStateException("Serialization failed");
        }
        System.out.println("Verified Guava " + args[0] + ": collections, splitting, weak keys and serialization.");
    }
}
