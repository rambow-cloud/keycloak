const {test}=require('node:test');
const assert=require('node:assert/strict');
const modulePromise=import('../docs/experiments/rhhi-syft-grype/experiment.mjs');
const inventory=(kind)=>({distro:{id:kind==='rhhi'?'hummingbird':'debian'},artifacts:[
  {name:'libuuid1',type:kind==='rhhi'?'rpm':'deb',version:'2.41.5'},
  {name:'guava',type:'java-archive',version:'33.7.2-jre',locations:[{path:'/opt/keycloak/lib/guava.jar'}]},
  {name:'opentelemetry-api',type:'java-archive',version:'1.67.0',locations:[{path:'/opt/keycloak/lib/otel.jar'}]}
]});
const report=(kind)=>({distro:{name:kind==='rhhi'?'hummingbird':'debian'},descriptor:{name:'grype',version:'0.121.0',db:{status:{valid:true}}},matches:[]});
test('experiment refuses zero-finding results with missing OS or application coverage',async()=>{
  const {summarize}=await modulePromise;
  for(const kind of ['rhhi','distroless']) {
    assert.equal(summarize(report(kind),inventory(kind),kind).status,'complete');
    assert.equal(summarize({...report(kind),distro:{name:'unknown'}},inventory(kind),kind).status,'coverage-failed');
    assert.equal(summarize(report(kind),{...inventory(kind),artifacts:[]},kind).status,'coverage-failed');
    assert.equal(summarize({...report(kind),descriptor:{...report(kind).descriptor,db:{status:{valid:false}}}},inventory(kind),kind).status,'coverage-failed');
  }
});
test('experiment counts package findings separately from normalized CVEs and preserves fixes',async()=>{
  const {summarize}=await modulePromise;
  const m={vulnerability:{id:'RHSA-2026:1',severity:'High',fix:{versions:['2.0']}},relatedVulnerabilities:[{id:'CVE-2026-12345'}],artifact:{name:'libuuid',version:'1.0',type:'rpm'}};
  const result=summarize({...report('rhhi'),matches:[m,m]},inventory('rhhi'),'rhhi');
  assert.equal(result.total,2);assert.equal(result.uniqueAdvisories,1);assert.equal(result.uniqueCVEs,1);assert.equal(result.blocking,2);
});
