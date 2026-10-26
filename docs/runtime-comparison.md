# Experimental Java 25 runtime comparison

Issue #34 authorizes a branch-only comparison of UBI 10 Micro, BellSoft Hardened Liberica JRE 25 glibc/nonroot, and DHI Temurin 25 Debian. The linked draft PR holds live CI results and the final recommendation. Do not merge, publish images, create Releases/tags, change production locks or introduce registry credentials.

## Inputs and execution

`experiments/images.lock.json` pins UBI 10.2 Micro and its same-family build root, plus the public BellSoft Java 25 image. The DHI public anonymous token exchange returned HTTP 401 locally. Each DHI CI job independently probes anonymous access using an explicit empty auth file. It must freeze and archive the manifest digest before building; if access fails, the job records a blocked input and does not build from a floating selector. There is no credential fallback.

The runner derives a reviewable experimental Containerfile from the unchanged production file, keeping the same Keycloak version, optimized build stages, providers and Java 25 build image. Each job archives its generated Containerfile, effective inputs, source/head commits, final image metadata, actual JVM version and CPU details. No experimental OCI image is uploaded to any registry; only bounded evidence artifacts are retained for seven days. Normal PR CI provides a current distroless core/aws baseline.

UBI 10 copies the pinned Micro root into a public UBI build stage, adds the headless Java 25 runtime from public UBI repositories, removes actual installation-only shell/package-manager/Python packages with their RPM records, then flattens into a scratch final stage. Retain library metadata, licenses, the unmodified UBI EULA and exact RPM inventory. Repositories are rolling, so OCI pins alone do not snapshot RPM transactions. Before production adoption, a reviewed package snapshot/lock is required. Linux amd64 hosts must support x86-64-v3; the job records loader capabilities and CPU details.

Other candidates retain the vendor runtime contents. A small symlink layer maps the observed absolute JVM path to `/usr/bin/java`; no shell or package manager is added. Direct startup and UID/GID 65532 remain fixed. A vendor image that already contains prohibited tools fails the rootfs policy. Experimental jobs may continue through restricted protocol tests after that failure to collect compatibility evidence, but must still fail afterward; normal CI still fails immediately. This is not an exception permitting shell-bearing production images.

## Coverage and results

Each available candidate/profile uses existing PostgreSQL verified TLS, wrong-CA/hostname rejection, schema/authentication, graceful shutdown and AWS offline IAM tests. No live RDS/PolarDB, extra architecture, FIPS, runtime reaugmentation or additional extensions are certified.

Use the checksum-pinned native Trivy and unchanged vulnerability policy. Archive complete JSON and database metadata before checking OS/Java coverage. RHEL requires actual nonempty RPM and Java package results. Alpaquita is not treated as Alpine or Debian: if pinned Trivy lacks coverage, record the raw output and a failed/unsupported coverage result. Never describe a JAR-only or unsupported-OS scan as a zero-CVE image. Likewise, DHI custom patches and bundled JVM coverage need review rather than trusting a vendor dashboard count. No blanket ignore, VEX suppression or lowered gate is used.

Compare scanner/database timestamps, exact JVM patch, package inventories, findings and functional results. Differences in vendor feeds and JVM binary coverage mean raw totals are not an exploitability ratio. Keep unsuccessful candidates and access/coverage limitations visible in the draft PR.

Sources: [UBI Java 25 downloads](https://developers.redhat.com/products/openjdk/download), [UBI host compatibility](https://access.redhat.com/support/policy/rhel-container-compatibility), [BellSoft hardened containers](https://bell-sw.com/bellsoft-hardened-container-images/), [Trivy Alpaquita coverage discussion](https://github.com/aquasecurity/trivy/discussions/9180), [DHI plans](https://docs.docker.com/dhi/).
