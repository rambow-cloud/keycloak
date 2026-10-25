import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import software.amazon.awssdk.http.HttpExecuteRequest;
import software.amazon.awssdk.http.SdkHttpFullRequest;
import software.amazon.awssdk.http.SdkHttpMethod;
import software.amazon.awssdk.http.apache5.Apache5HttpClient;

/** Exercises patched HTTPComponents through the actual AWS SDK transport without cloud access. */
public final class AwsHttpTransport {
    public static void main(String[] args) throws Exception {
        var server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/fixture", exchange -> {
            var body = "aws-transport-ok".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            try (var stream = exchange.getResponseBody()) {
                stream.write(body);
            }
        });
        server.start();
        try (var client = Apache5HttpClient.builder()
                .connectionTimeout(Duration.ofSeconds(5))
                .socketTimeout(Duration.ofSeconds(5)).build()) {
            var request = SdkHttpFullRequest.builder().method(SdkHttpMethod.GET)
                    .uri(URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/fixture")).build();
            var response = client.prepareRequest(HttpExecuteRequest.builder().request(request).build()).call();
            try (var body = response.responseBody().orElseThrow()) {
                if (response.httpResponse().statusCode() != 200 ||
                        !"aws-transport-ok".equals(new String(body.readAllBytes(), StandardCharsets.UTF_8))) {
                    throw new AssertionError("Patched AWS Apache HTTP transport failed its local fixture");
                }
            }
        } finally {
            server.stop(0);
        }
        System.out.println("Verified the AWS Apache HTTP transport against the local fixture.");
    }
}
