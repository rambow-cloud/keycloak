import io.opentelemetry.api.OpenTelemetry;
import io.opentelemetry.api.baggage.Baggage;
import io.opentelemetry.api.baggage.propagation.W3CBaggagePropagator;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.SpanContext;
import io.opentelemetry.api.trace.propagation.W3CTraceContextPropagator;
import io.opentelemetry.context.Context;
import io.opentelemetry.context.propagation.ContextPropagators;
import io.opentelemetry.context.propagation.TextMapGetter;
import io.opentelemetry.context.propagation.TextMapPropagator;
import io.opentelemetry.sdk.OpenTelemetrySdk;
import io.opentelemetry.sdk.common.CompletableResultCode;
import io.opentelemetry.sdk.trace.SdkTracerProvider;
import io.opentelemetry.sdk.trace.data.SpanData;
import io.opentelemetry.sdk.trace.export.SimpleSpanProcessor;
import io.opentelemetry.sdk.trace.export.SpanExporter;
import io.opentelemetry.sdk.metrics.SdkMeterProvider;
import io.opentelemetry.sdk.logs.SdkLoggerProvider;
import java.util.*;

// Runs only in the build stage on the real distribution classpath, without network I/O.
public class OpenTelemetryCompatibility {
    static final TextMapGetter<Map<String,String>> GETTER = new TextMapGetter<>() {
        public Iterable<String> keys(Map<String,String> carrier) { return carrier.keySet(); }
        public String get(Map<String,String> carrier,String key) { return carrier.get(key); }
    };
    static final String TRACE="0af7651916cd43dd8448eb211c80319c";
    static final String PARENT="b7ad6b7169203331";
    static void require(boolean value,String message) { if(!value)throw new IllegalStateException(message); }
    public static void main(String[] args) throws Exception {
        for(String module:List.of("api","context","common")) {
            Properties p=new Properties();
            try(var in=OpenTelemetry.class.getResourceAsStream("/io/opentelemetry/"+module+"/version.properties")) {
                require(in!=null,"Missing "+module+" version metadata");p.load(in);
            }
            require(args[0].equals(p.getProperty("sdk.version")),"Unexpected "+module+" payload");
        }
        require(args[1].equals(OpenTelemetrySdk.class.getPackage().getImplementationVersion()),"SDK version drift requires exception review");
        var propagator=TextMapPropagator.composite(W3CTraceContextPropagator.getInstance(),W3CBaggagePropagator.getInstance());
        Map<String,String> headers=new HashMap<>();
        headers.put("traceparent","00-"+TRACE+"-"+PARENT+"-01");
        headers.put("tracestate","vendor=one,other=two");headers.put("baggage","tenant=test,mode=staging");
        Context remote=propagator.extract(Context.root(),headers,GETTER);
        SpanContext parent=Span.fromContext(remote).getSpanContext();
        require(parent.isRemote()&&parent.isSampled()&&TRACE.equals(parent.getTraceId()),"Traceparent extraction changed");
        require("one".equals(parent.getTraceState().get("vendor")),"Tracestate extraction changed");
        require("test".equals(Baggage.fromContext(remote).getEntryValue("tenant")),"Baggage extraction changed");
        Map<String,String> injected=new HashMap<>();propagator.inject(remote,injected,Map::put);
        require(headers.get("traceparent").equals(injected.get("traceparent")),"Traceparent round-trip changed");
        List<SpanData> exported=new ArrayList<>();
        SpanExporter exporter=new SpanExporter() {
            public CompletableResultCode export(Collection<SpanData> spans){exported.addAll(spans);return CompletableResultCode.ofSuccess();}
            public CompletableResultCode flush(){return CompletableResultCode.ofSuccess();}
            public CompletableResultCode shutdown(){return CompletableResultCode.ofSuccess();}
        };
        try(var tracing=SdkTracerProvider.builder().addSpanProcessor(SimpleSpanProcessor.create(exporter)).build();
            var metrics=SdkMeterProvider.builder().build();var logs=SdkLoggerProvider.builder().build()) {
            var sdk=OpenTelemetrySdk.builder().setTracerProvider(tracing).setMeterProvider(metrics).setLoggerProvider(logs)
                .setPropagators(ContextPropagators.create(propagator)).build();
            Span span=sdk.getTracer("compatibility").spanBuilder("repair-regression").setParent(remote).startSpan();span.end();
            require(exported.size()==1&&PARENT.equals(exported.get(0).getParentSpanId())&&TRACE.equals(exported.get(0).getTraceId()),"Existing SDK propagation/export failed");
            sdk.getMeter("compatibility").counterBuilder("repair.test").build().add(1);
            sdk.getLogsBridge().get("compatibility").logRecordBuilder().setBody("repair-test").emit();
        }
        long started=System.nanoTime();
        for(int size:new int[]{2048,8192,32768,131072}) for(String whitespace:List.of(" ","\t")) {
            headers.put("tracestate","vendor=value"+whitespace.repeat(size));
            for(int i=0;i<8;i++) {
                var extracted=Span.fromContext(propagator.extract(Context.root(),headers,GETTER)).getSpanContext();
                require(TRACE.equals(extracted.getTraceId()),"Malformed tracestate broke valid traceparent");
            }
        }
        long millis=(System.nanoTime()-started)/1_000_000;
        require(millis<5000,"Tracestate parsing exceeded the bounded regression budget");
        System.out.println("Verified OpenTelemetry "+args[0]+" with SDK "+args[1]+": propagation, in-memory export, metrics/log linkage and bounded tracestate parsing ("+millis+" ms).");
    }
}
