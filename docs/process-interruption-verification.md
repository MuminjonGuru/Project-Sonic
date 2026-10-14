# Process Interruption Verification

The merged benchmark increment exposed a Windows-specific test failure in hosted CI on
14 October 2026. Both failing cases used `psutil.pid_exists(pid)` immediately after an
interrupted subprocess had been terminated and waited for. The Linux job passed.

## What the Test Must Establish

An interruption must propagate the original exception after the host child has terminated.
Reader streams must also be closed. This is separate from Docker-container cleanup and does
not prove termination of every possible descendant or permission to resume a failed scan.

Windows process termination and process-object deletion are different events. An open handle
can keep the terminated process object alive. Microsoft documents both the retained-object
lifetime and the need to wait for termination rather than infer it from the termination call:
[process termination](https://learn.microsoft.com/en-us/windows/win32/procthread/terminating-a-process),
[TerminateProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminateprocess).

The revised test retains the actual `Popen` object, requires its return code to have been set
by the runner, checks a zero-timeout wait and both closed streams, and verifies the original
exception identity. It does not wait for PID disappearance or add a Windows skip. Python
documents return-code and wait behavior in [the subprocess reference](https://docs.python.org/3.13/library/subprocess.html#subprocess.Popen.wait).

A separate negative control launches a real sleeping child and requires the same assertion
to reject it. Test-owned fallback cleanup occurs after assertions, so it cannot conceal a
runner cleanup failure. Mocked success codes are not used.

## Scope of the Correction

Only the process tests change; production execution code, scanner rules, versions, schemas,
admission pins and historical evidence remain unchanged. The tests deliberately retain the
exception and child object to exercise the handle-lifetime condition. This corrects the
termination oracle, not an observed scanner detection or benchmark result.

The earlier local suites and failed hosted runs remain historical observations. A fresh local
pass is not a successful rerun of hosted CI; the latter must be checked after publication.
The next MP-04 feature remains the controlled KICS benchmark handler, followed by other admitted
handlers and scoring. This repair does not complete MP-04 or authorize broader scanning.
