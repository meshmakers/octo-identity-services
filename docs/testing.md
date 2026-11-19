---
description: "Integration-test collections and fixtures, parallel-host rules, test-host leaks (memory, threads, user secrets, signing certificates)"
applies_to: "tests/**"
---

# Integration-test fixtures and parallel hosts

## Integration-Test-Fixtures: fünf Collections, fünf Container

> **State of the code (checked 2026-11-16):** the collection classes this section names
> (`IdentityPersistenceCollection`, `WebFactoryCollection`, the folder `tests/…/Collections/`) do not exist in this
> branch line. The integration tests share one MongoDB container through `Fixtures/SharedMongoDbContainer.cs`, and the
> test classes use `IClassFixture<…>` or `[Collection("Sequential")]`. Look at a neighbouring test class before you
> follow the rule for new test classes below. The rules on process-wide state in the next section apply unchanged.
> The container counts, test counts and run times in this section and in the last section of this file were measured
> with the collection fixtures and do not describe the current code; the advice to re-run serially (`-m:1`) holds.

`IdentityServices.IntegrationTests` teilt seine MongoDB-Testcontainer über **Collection**-Fixtures, nicht
mehr über `IClassFixture` (das erzeugt eine Fixture-Instanz **pro Testklasse** — vorher 32 Container pro
Lauf, davon ~50 % der CI-Testzeit reines Setup). Die Definitionen liegen in `tests/…/Collections/`:

| Collection | Fixture | Wer |
| --- | --- | --- |
| `IdentityPersistence` | `IdentityServicesFixture` | 14 Persistence-Klassen |
| `DataProtectionKeySeed` | `IdentityServicesFixture` | nur `DataProtectionKeySeedIntegrationTests` |
| `DataProtectionKeyEncryption` | `IdentityServicesFixture` | nur `DataProtectionKeyEncryptionIntegrationTests` (leert den Key-Store je Fact) |
| `VirginBootstrap` | `VirginBootstrapFixture` | nur `VirginSystemDatabaseBootstrapIntegrationTests` |
| `ZWebFactory` | `CustomWebApplicationFactory` | 15 HTTP-Klassen (Basis `IntegrationTestBase`) |
| `ZSetupApi` | `CustomWebApplicationFactory` | nur `SetupApiTests` |

**Regel für neue Testklassen:** `[Collection(IdentityPersistenceCollection.Name)]` bzw.
`[Collection(WebFactoryCollection.Name)]` setzen und alle Entitäten mit GUID-Suffix anlegen
(`$"foo-{Guid.NewGuid():N}"`) — dann ist der akkumulierte Zustand der Geschwisterklassen unsichtbar.
Wer auf den Zustand der **ganzen** Datenbank angewiesen ist (leere Collection erwartet, alles löscht,
System-Tenant droppt), bekommt eine **eigene** Collection — so wie die drei Einzelgänger oben. Ein
Container mehr ist billiger als ein flakiger oder vakuum-grüner Test; niemals stattdessen die Assertion
aufweichen. Vorbild: `octo-asset-repo-services` (7 Collections) / `octo-communication-controller-services`
.

## 🔴 Collections laufen PARALLEL — prozessweiter Zustand ist die Fehlerklasse

`xunit.runner.json` hält `parallelizeTestCollections: true` mit `maxParallelThreads: 4`. (Diese Doku
behauptete früher `false`; das war falsch.) Nur **ein** MongoDB-Container lebt
gleichzeitig — die Isolationsgrenze ist die **Datenbank**, nicht der Server —, aber bis zu
vier Collections bauen gleichzeitig Hosts hoch und ab.

Damit ist **jeder prozessweite Zustand ein Race**, und das ist die einzige Fehlerklasse, die diese
Suite wirklich flakig macht. Bisher dreimal getreten:

| Geteilter Zustand | Symptom | Behandlung |
| --- | --- | --- |
| Test-Tenant-ID `test-tenant` (⇒ DB-Name, serverweiter Namensraum) | Fixtures überschreiben sich | GUID-Suffix |
| System-Tenant-ID `octosystem` ⇒ statisches `DefaultConfigurationCreatorServiceBase.TenantsInHandling` | Fixtures überspringen still den CK-Import, dann `CkCacheException` | GUID-Suffix, Präfix gekürzt |
| **statisches `NLog.LogManager.Configuration`** | `ConfigurationException: LogManager configuration not found` aus `HostedInitializer.StartAsync`, wandernde Testmenge | Aufrufer tolerant |

**Machine-wide state counts too.** In the Development environment `OpenIddictConfiguration`
calls `AddDevelopmentSigningCertificate()`, which publishes **every** certificate with subject
`CN=OpenIddict Server Signing Certificate` from the current user's X509 store — expired ones and
duplicates created by concurrently starting hosts included. On a long-lived CI agent that store
persists across builds, so the JWKS depended on the agent (`TokenShapeGoldenTests.JwksDocument_*` saw
two keys on one long-lived CI agent only). `CustomWebApplicationFactory` therefore replaces the
signing and encryption credentials with one in-memory certificate (`Infrastructure/TestSigningCertificate.cs`),
and the JWKS test asserts that this is the only published key. Never let a test host read key material
from the user/machine store.

**Linux agents: inotify instance limit.** Every in-process host (each `CustomWebApplicationFactory` and each
`WithWebHostBuilder` derivative) used to load `appsettings*.json` with reload-on-change, i.e. one file watcher per file and host.
On the Linux CI agents the inotify instance limit (128) was reached across the suite and unrelated tests failed at host start
(`The configured user limit (128) on the number of inotify instances has been reached`). The static constructor of
`CustomWebApplicationFactory` therefore sets `DOTNET_hostBuilder__reloadConfigOnChange=false` for the test process (tests never
change configuration files at run time); `TestHostConfigurationTests` pins it. Dispose derived factories a test creates
(`WithWebHostBuilder`) at the end of the test (`GroupMethodTestBase`, `ClientMirrorReconciliationTests`, `UserRoleMethodTests`,
`UserChangePasswordMethodTests`); otherwise they live until the class fixture ends.

**No developer user secrets in the test hosts.** The factory runs the host in the Development environment, so
`WebApplication.CreateBuilder` adds the user secrets of `IdentityServices` (and `Program.cs` adds them again). A developer's
secret changed the host on that machine only: with `Identity:DataProtectionKeysPath` set, the key store imported an old unencrypted
`key-*.xml` and `DataProtectionKeyEncryptionHostTests` failed locally while CI (no user secrets) stayed green.
`CustomWebApplicationFactory` therefore passes the host setting `DisableUserSecrets=true` (`UseSetting`, inherited by every
`WithWebHostBuilder` derivative). A host setting reaches `Program` as a command-line argument, so `Program.cs` removes every
`secrets.json` source right after `CreateBuilder` and skips its own `AddUserSecrets`
(`Configuration/UserSecretsConfiguration.cs`). This happens before the values `Program` reads while it registers the services
(e.g. `Methods:Identity:EnablePasswordMethods`); the factory's `ConfigureAppConfiguration` would come too late for those.
Without the setting nothing changes. `TestHostConfigurationTests` and `UserSecretsConfigurationTests` pin it. A test that needs a
setting puts it into the factory's in-memory configuration or `appsettings.test.json`, never into user secrets.

**Test host memory: every in-process host must be collectable.** ASP.NET Core's `RateLimitingMiddleware`
(`app.UseRateLimiter()`, policies `tenant-discovery` and `dcr`) never disposes its `DefaultPartitionedRateLimiter`, whose 100 ms
heartbeat timer is a GC root for the whole request pipeline and the host's services, and whose captured `ExecutionContext` holds
xUnit's `TestContext` and with it the class fixtures. In production that is one pipeline per process; the suite builds ~300 hosts
and none was ever collected: the live heap after a full GC grew monotonically to **8.6 GB** (dump: 295 live meter providers,
3.6 GB OpenTelemetry `MetricPoint[]` alone), which hit the 9 GiB GC heap hard limit of a 12 Gi CI agent (OutOfMemoryException in
random tests, builds 65745, 65817). `CustomWebApplicationFactory` therefore registers `Infrastructure/RateLimiterReleaser` (hosted
service, last registration, inherited by every `WithWebHostBuilder` derivative): when the host stops it finds the middleware's
limiters by reflection over the built pipeline and disposes them. Measured locally (Mac mini, `GC.GetTotalMemory(true)` every 15 s,
engine-mongodb main incl. the disposal fix): live heap peak **8.6 GB → 3.3-3.5 GB**, suite duration unchanged (~9:40-10:00 min).
`RateLimiterReleaserTests` fails when a framework update changes the internal shape the walk relies on — fix the walk then, never
delete the test. Rules: a `StopAsync` of a test-only hosted service must never throw (it aborts the factory's dispose and leaks the
host); a new background timer or long-running loop in startup code needs a dispose path, or every test host keeps it.
The shared MongoDB container still grows to ~10 GiB per run (outside the test process; a `--wiredTigerCacheSizeGB 1` cap did not
change that and a 4 GiB container limit got mongod OOM-killed), which is tracked with the CI agent memory work.

**A stale DebugL feed starves the suite on driver threads.** Every repository client of the runtime engine is a
MongoDB driver cluster of its own (heartbeat, RTT monitor and pool maintenance thread each). Since the disposal fix
(engine-mongodb #229, 2026-11-05) a disposed host closes all of them; a `Meshmakers.Octo.Runtime.Engine.MongoDb` 999.0.0
in `../nuget` built **before** that keeps every cluster of every host the suite ever built. Measured on a Mac (16 cores,
2026-11-07, same identity commit): with the stale feed the test host passed 3,100 threads after 9.5 min with ~500 of ~1,000
tests done and throughput collapsing (thread stacks: ~390 × `ServerMonitor`, ~390 × `RoundTripTimeMonitor`, ~390 ×
`MaintenanceHelper`; dump: 497 clusters in `ClusterRegistry`, rooted only by the registry); with the library chain rebuilt
from main the same suite stays bounded (measured numbers were recorded with the change). CI is not affected (its feed is built from main). Symptoms of a
stale feed: thousands of threads at ~50 % CPU, transaction aborts, server-selection timeouts and canceled operations in
unrelated classes, a run that never ends. `Infrastructure/TestHostMongoClientReleaseTests` pins the release on the server
(`$currentOp` by the host's system database name) and turns red within seconds against such a feed — then rebuild the chain
(`Invoke-BuildRange` from `octo-construction-kit-engine-mongodb`, or the whole DebugL chain) before you hunt for test defects.

Der NLog-Fall ist der einzige, den man **nicht** per-Fixture eindeutig machen kann: `Program.cs` lädt
die globale Konfiguration am Entry-Point und räumt sie im `finally` mit `LogManager.Shutdown()` wieder
ab (dort gegen den Segfault beim Prozessende auf Linux). Unter `WebApplicationFactory<Program>` läuft
der Entry-Point pro Factory-Instanz und `app.Run()` wird kurzgeschlossen — das `finally` feuert also
direkt nach dem Host-Build, während eine andere Factory die Konfiguration gerade liest. Deshalb fängt
`DefaultConfigurationCreatorService.InitializeAsync` die `ConfigurationException` und warnt nur;
`DiagnosticsService` selbst **wirft weiter**, weil sein anderer Aufrufer der operator-sichtbare
`DiagnosticsController` ist, wo ein stiller No-op der schlimmere Fehler wäre.

**Regel für neue Tests und neuen Startup-Code:** bevor du etwas in einen `static` legst oder aus einem
`static` liest, das ein Host beim Start oder beim Dispose anfasst — annehmen, dass vier Hosts es
gleichzeitig tun. Ein wandernder Satz fehlgeschlagener Tests über mehrere Retry-Versuche ist die
Signatur dieser Klasse, nie ein Testdefekt.

## 🔴 `dotnet test` auf der Solution startet alle vier Testhosts gleichzeitig

`dotnet test <sln>` baut und startet die vier Testprojekte **parallel** (ein Testhost-Prozess pro Projekt).
`IdentityServices.IntegrationTests` fährt dabei seine MongoDB-Testcontainer hoch, während die drei Unit-Test-Hosts
dieselbe Maschine belegen — Container-Kontention, die es beim Einzelaufruf nicht gibt. Vor der Umstellung auf
Collection-Fixtures, als jede Testklasse ihren eigenen Container bekam (32 Container pro Lauf), war das massiv: dasselbe
Integrationsprojekt **einzeln** 4:48 mit 188/188 grün — **in der Solution** 27 min, mit sporadischem `commitTransaction
... has been aborted`, weil der Tenant-Setup in einer Mongo-Transaktion läuft und unter Last das 60-s-Default-Limit
riss.

Die Umstellung hat beide Ursachen entschärft (5 statt 32 Container, `transactionLifetimeLimitSeconds = 300`);
gemessen danach: Solution-Lauf 1:37, alle 681 Tests grün. **Der Mechanismus ist aber nicht weg** — auf
einer belasteten Maschine bleibt der parallele Solution-Lauf die anfälligste Variante. Bei einem
Abbruch aus dieser Ecke (Transaktions-Abort, Testcontainer-Timeout) also erst seriell gegenprüfen,
bevor man ihn für einen echten Testfehler hält:

```bash
dotnet test Octo.Identity.sln -c DebugL -m:1      # Projekte nacheinander
# oder Projekte einzeln:
dotnet test tests/IdentityServices.IntegrationTests/IdentityServices.IntegrationTests.csproj -c DebugL
dotnet test tests/IdentityServices.UnitTests/IdentityServices.UnitTests.csproj -c DebugL
dotnet test tests/IdentityServerPersistence.UnitTests/IdentityServerPersistence.UnitTests.csproj -c DebugL
dotnet test tests/Authentication.UnitTests/Authentication.UnitTests.csproj -c DebugL
```

Das ist eine Empfehlung zur **Ausführungsart**, keine Erlaubnis, Projekte wegzulassen: grün müssen
weiterhin alle vier sein.

## Load on the machine

Several agent lanes or a second checkout often build and test on the same machine. Measured on 2026-11-17: the
integration project took 17 min on a quiet machine and 35 min at a load average of 50-95 (14 cores), all 1309 tests green
with the two rules below. Without them two kinds of failures appeared only under load:

| Symptom | Cause | Rule |
| --- | --- | --- |
| REST role/group/client endpoints answered `METHOD_TIMEOUT` / HTTP 504 | the REST facades run CK methods in process with the CK deadline; methods without `timeoutSeconds` get the CK default of 15 s, and one call took longer on a loaded machine (slowest guard test 49 s in total) | `Infrastructure/TestHostMethodDeadlineFloor`: the factory host waits at least 120 s per method call of its REST facades, and tests that build a `CkMethodRequest` themselves (dispatcher or handler called directly) set `DeadlineUtc = TestHostMethodDeadlineFloor.DeadlineFromNow()`. The factory's HTTP clients (derived hosts included) wait `ClientTimeout` = floor + 60 s, so the client's 100 s default cannot end a call first. Pinned by `TestHostMethodDeadlineFloorTests` (factory and derived host use it; short timeouts raised, long ones and "unknown method" kept). The real deadline is proven in octo-common-services (`Methods.Tests/Dispatching/CkMethodTimeoutResolverTests`, `Methods.Tests/InProcess/InProcessTransportTests`, `Methods.IntegrationTests/CkMethodDispatcherBusTests`). |
| `IdentityCommandConsumerReplicaTests`: the ledger missed commands whose responses had arrived | the consumer responds before the consume observer's `PostConsume` records the message | `WaitUntilRecordedAsync`: wait (at most 30 s) until every expected id is recorded and no CreateIdentityData consume is in flight (a consume still running at the deadline fails the test), then assert exactly once and on which replica, unchanged |

A test that needs the real CK deadline of an identity method builds its own host instead of the factory. A new test that
reads what a consumer, an observer or a background step recorded waits for it with a bound; it never asserts right after
the response.


## Hang evidence in CI

The Test step of `azure-pipelines.yml` has a step timeout of 25 min. A suite that stalls used to end there
without saying which test was running or what MongoDB waited for. A healthy agent needs 10-14 min for the
whole step. A stall now leaves evidence in three places; read them in this order:

1. **Build log of the Test step, `[Long Running Test]` lines.** `xunit.runner.json` sets `longRunningTestSeconds: 120` and
   `diagnosticMessages: true` (the runner prints the notice only with diagnostic messages on), so a test that runs longer
   than 2 min is named in the log while it is still running, and again every further 2 min.
2. **`--blame-hang --blame-hang-timeout 8m --blame-hang-dump-type none`.** The test host is aborted when no test has
   started or finished for 8 min. vstest measures inactivity, not the run time of one test: every start or end of a test
   (also of the other parallel ones) resets the timer, so a hang is caught 8 min after the last test activity. The step then
   fails before its 25 min, and the log names the tests in flight. No memory dump is written (GBs), only
   `Sequence_*.xml`. The steps *Collect hang evidence* and *Publish hang evidence* print the tests that had started and
   not completed and publish the pipeline artifact **`hang-evidence-<attempt>`** (`Sequence_*.xml`, `samples.log`) when the
   job failed.
3. **Step *Mongo hang evidence*, filtered `$currentOp` summary of the Testcontainers MongoDB**
   (`scripts/ci/mongo-hang-diagnostics.sh`). A sampler started before the tests writes one heartbeat line a minute
   (`activeOps`, `notable`) and one line per operation that runs >= 20 s or waits for a lock: `op`, `ns`, `secs_running`,
   `waitingForLock`, `locks` (lock modes) and the resource names of `lockStats`. Nothing else is kept: no command
   documents, client addresses or credentials (`mongosh` runs inside the container and reads the container's own
   `MONGO_INITDB_ROOT_*` variables; no secret is on the agent's command line or in the log). The step runs on a failed or cancelled
   job before the cleanup step removes the container, prints the last 40 samples and one fresh snapshot (time-boxed to 3 min), and never fails the
   build. Reading it: an operation with growing `secs_running` and `waitingForLock: true` waits on a lock (index build or
   transaction of a tenant setup); `waitingForLock: false` with a high `secs_running` is a slow operation itself; no
   notable operation at all means the test host waits on something else (MongoDB is idle: look at the tests in flight).

The Test step no longer has `retryCountOnTaskFailure` (a retry re-ran the whole suite and could hide red tests); restore and
build keep theirs. Locally the sampler works the same way: `scripts/ci/mongo-hang-diagnostics.sh start <dir> 10`, run the
tests, then `scripts/ci/mongo-hang-diagnostics.sh report <dir> Failed`.
