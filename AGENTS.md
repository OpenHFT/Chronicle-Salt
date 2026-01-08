# AGENTS.md

## Scope
- Java library providing a libsodium binding for Chronicle Bytes.
- Java sources are in `src/main/java/net/openhft/chronicle/salt`, JNI C in `src/main/c`, tests in `src/test/java/net/openhft/chronicle/salt`.

## Build and test
- Preferred full check:
  - `mkdir -p logs`
  - `mvn verify -l logs/mvn-verify.log`
- Test example:
  - `mvn -Dtest=ClassName test -l logs/mvn-test.log`
- Skip tests when native libs are unavailable:
  - `mvn -DskipTests verify -l logs/mvn-skip-tests.log`
- Review logs:
  - `rg -n '^\[(WARNING|ERROR)\]|SLF4J\(W\)|\bWARNING:|\bwarning:' logs/mvn-verify.log`
- Do not commit logs/.

## Repo map
- `src/main/c/Makefile` runs during `process-classes` to build `target/classes/libbridge.*`.
- Java 11+ uses `src/main/c/Makefile11` with `javac -h` to generate JNI headers.
- Java formatting uses `java-code-formatter.xml` via `formatter-maven-plugin`.

## Constraints
- Java baseline: 8 (avoid newer language features; Java 11+ for JNI headers).
- Source files must stay ISO-8859-1 (code points 0-255). Prefer ASCII; avoid smart quotes and non-breaking spaces.
- Preserve public APIs unless explicitly requested.
- Treat warnings as defects; keep logs clean.
- Keep JNI and off-heap changes minimal; avoid extra allocations or synchronisation on hot paths.
- Ensure libsodium is installed and on the system library path (for example `LD_LIBRARY_PATH`), or supply DLLs on Windows.

## Docs and review checklist
- Reformat with `mvn -q formatter:format` when required.
- For large mechanical changes, declare the transformation rule and keep it consistent.

## References
- `OpenHFT/docs/Company-Wide-Tagging.adoc` for tagging and decision record templates.
