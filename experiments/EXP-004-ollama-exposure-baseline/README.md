# EXP-004 — Passive Ollama exposure baseline

## Purpose

Establish a reproducible passive Windows baseline for a local Ollama runtime using the existing Service Exposure Evidence v1 pipeline.

The experiment asks only what the operating system can independently observe about Ollama:

```text
process identity
    +
listener topology
    +
principal/service evidence
    +
Windows Firewall/network-profile context
    +
Docker publication evidence
    +
collector completeness
```

The governing semantics remain:

```text
listening != reachable
published != reachable
reachable != unauthenticated
reachable != exploitable
```

EXP-004 does not interrogate the Ollama HTTP API and does not add an Ollama-specific production collector unless live evidence demonstrates that the existing evidence surface is insufficient.

## Upstream reference, not observed fact

Current upstream Ollama source/configuration defines the default server endpoint as:

```text
http://127.0.0.1:11434
```

The bind address can be changed with `OLLAMA_HOST`.

Current Windows desktop packaging uses a desktop executable named:

```text
ollama app.exe
```

and a core binary named:

```text
ollama.exe
```

These values are reference expectations only. They must never override captured source evidence.

In particular:

```text
port 11434 != proof of Ollama
```

A listener is associated with native Windows Ollama only when the persisted listener evidence is attributed to a stable process instance whose observed process identity supports that association.

## Existing production path under test

EXP-004 intentionally starts with the existing production capture path:

```text
tools/service_exposure_capture.py
```

The capture requests:

```text
windows_tcp_listeners
windows_listener_process_principals
windows_listener_services
windows_firewall_context
windows_firewall_rules
docker_published_ports
```

and persists exactly one:

```text
SERVICE_EXPOSURE_CAPTURE_MANIFEST
```

when persistence succeeds.

Firewall candidate correlation remains a separate derived layer and is run only after an Ollama-associated listener has been identified from persisted source evidence.

## Phase A — Unmodified passive baseline

Do not change Ollama configuration for the first capture.

Do not start a manual `ollama serve` solely for the experiment unless Ollama is otherwise not running and that intervention is recorded explicitly.

From the repository root:

```powershell
$env:PYTHONPATH = (Resolve-Path .\src).Path

python .\tools\service_exposure_capture.py `
  --db .\.local\ollama-exposure.sqlite3 `
  --source exp004-ollama-baseline `
  --details
```

Record the generated stream id and the command exit code.

Exit-code interpretation remains the production contract:

```text
0 = requested collectors succeeded, or optional Docker was explicitly skipped
1 = fatal capture/EventStore failure
2 = partial capture persisted because at least one requested collector failed
3 = persisted-stream verification failure
```

A partial capture is evidence, not an automatic experiment failure. The failed collector and its error must remain explicit in the manifest.

## Ollama subject identification

Inspect persisted `TCP_LISTENER_OBSERVED` facts.

For a native Windows listener to be called Ollama-associated in this experiment, require all of the following:

1. `attribution_state = attributed`;
2. `owner_identity_basis = stable_process_instance`;
3. a persisted `process = {pid, started_at}` identity exists;
4. the captured process name/path identifies the owning process as the Ollama core binary, normally `ollama.exe` for the current Windows distribution.

Do not identify the service solely from:

- local port `11434`;
- a firewall rule display name;
- an environment variable;
- a Docker container name unrelated to the listener-owning host process;
- an expected vendor default.

If an `ollama app.exe` desktop process is visible elsewhere in endpoint evidence, it may be recorded as related application context but does not by itself prove ownership of the server listener.

## Baseline facts to record

For every Ollama-associated listener found in the persisted stream, record:

```text
listener_event_id
local_address
local_port
bind_scope
owner_pid
process.pid
process.started_at
process_name
executable_path
principal resolution state and SID when available
related Windows service facts, if any
active network-profile context
firewall candidate-correlation status
candidate rule event ids, if any
collector completeness from the manifest
```

Also record Docker publication facts separately. A Docker publication is not silently merged with native host-process evidence.

## Firewall correlation

After the Ollama-associated listener and its actual observed port are known, run the existing read-only candidate inspector against the same stream.

Example only, if the observed listener port is `11434`:

```powershell
python .\tools\firewall_rule_candidates.py `
  --db .\.local\ollama-exposure.sqlite3 `
  --stream-id <EXP-004-STREAM-ID> `
  --port 11434 `
  --details
```

The port argument is only a filter over an already identified listener. It is not service identification.

Interpretation remains:

```text
CANDIDATE_MATCH = one fully-known source-compatible rule candidate
NO_CANDIDATE    = no compatible rule in a confirmed complete rule inventory
AMBIGUOUS       = multiple/unresolved candidates or incomplete/unavailable rule inventory
```

None of these states is an effective allow/block or reachability verdict.

## Expected baseline cases

EXP-004 must tolerate all of these outcomes without inventing conclusions.

### A. Stable Ollama listener observed

Record the listener/process/bind/firewall facts exactly as captured.

### B. Ollama process evidence exists but no stable attributed listener is observed

Record that distinction. Do not claim that Ollama is not listening globally; the bracket may have missed a transient or attribution may have failed.

### C. No Ollama process/listener evidence exists in the capture

Record only that Ollama-associated evidence was not observed in this capture.

Do not conclude that Ollama is not installed.

### D. Collector failure or partial capture

Preserve the manifest status and limit any conclusion that depends on the failed source.

### E. Docker publication observed

Record Docker host/container mapping as a separate source fact. Do not infer host listener ownership from the publication alone.

## PASS criteria

EXP-004 PASS requires all of the following:

1. one production service-exposure stream is persisted or a partial stream is persisted with explicit collector failures;
2. exactly one `SERVICE_EXPOSURE_CAPTURE_MANIFEST` is present;
3. Ollama listener association, if claimed, is based on stable process-instance attribution rather than port-number inference;
4. observed bind scope is preserved as topology only;
5. firewall candidate correlation uses the same persisted stream and does not become a reachability verdict;
6. missing evidence remains unknown/absent rather than negative proof;
7. no Ollama HTTP/API request, model enumeration, prompt generation, authentication test, or remote probe is performed by the experiment.

A PASS means the current evidence model can describe a passive Ollama exposure baseline without violating its semantics.

It does not mean Ollama is secure, insecure, reachable, authenticated, or exploitable.

## Failure / design-gap criteria

Treat any of these as a design finding rather than papering over it:

- listener ownership cannot be tied to a stable Ollama process instance despite a reproducible listener;
- the source evidence cannot distinguish native-host and Docker publication cases needed for the baseline;
- manifest completeness disagrees with persisted facts;
- firewall correlation requires assumptions not supported by persisted evidence;
- the baseline requires application self-reporting to identify a fact that should be externally observable;
- a required conclusion can only be obtained by guessing from port `11434`.

If one of these occurs, document the gap before adding a new production event type or collector.

## Explicit non-goals

EXP-004 does not perform:

```text
Ollama HTTP/API interrogation
model enumeration
prompt or inference requests
authentication testing
remote reachability probing
vulnerability scanning
exploit attempts
severity scoring
automatic containment
```

## Next experiment

After this baseline is validated, a separate experiment may introduce one controlled exposure change, such as a bind/publication change, and compare the resulting persisted topology as exposure drift.

That later experiment must continue to distinguish:

```text
configuration change
observed bind/publication change
network reachability
unauthenticated API access
exploitability
```

These are separate claims and require separate evidence.