# PracticalAttackSim-Runner

# PAS — Practical Attack Simulation
### Detection Engineering & EDR Evaluation Framework

---

## What This Is

A single executable (`pas_runner.exe`) that  executes MITRE ATT&CK-mapped
behaviors on a Windows host. The runner does not collect telemetry, evaluate itself,
or report on EDR verdicts. **The EDR and SIEM must do all of that.**

An analyst checklist is presented after every test.

---

## Folder Structure

```
PAS/
  pas_runner.exe
  config.yml
  scenarios/
    suites/
      edr_eval_v1.yml         # Full sweep
      persistence_suite.yml   # Focused persistence tests
    persistence/
      T1053.005_scheduled_task.yml
      T1547.001_registry_run_key.yml
      T1547.001_startup_folder.yml
      T1546.003_wmi_subscription.yml
    execution/
      T1059.001_ps_encoded.yml
      T1218.005_mshta.yml
    defense_evasion/
      T1070.006_timestomp.yml
      T1562.001_amsi_bypass_string.yml
    credential_access/
      T1003.001_lsass_handle.yml
    discovery/
      T1082_system_discovery_burst.yml
    lateral_movement/
      T1021.002_service_creation.yml
  artifacts/        # Drop binaries/scripts used by scenarios here
  results/          # JSON output from each run
```

---

## Usage

```bash
# Run a single scenario
pas_runner.exe --scenario scenarios/persistence/T1053.005_scheduled_task.yml --vendor CrowdStrike

# Run a full suite
pas_runner.exe --suite scenarios/suites/edr_eval_v1.yml --vendor SentinelOne --out results/

# Dry run (print steps, don't execute)
pas_runner.exe --suite scenarios/suites/edr_eval_v1.yml --dry-run
```

---

## Build

```bash
cd runner
dotnet publish -c Release -r win-x64 --self-contained true /p:PublishSingleFile=true
# Output: runner/bin/Release/net8.0/win-x64/publish/pas_runner.exe
```

---

## Workflow: EDR Vendor Comparison

1. Set up two clean VMs — identical OS, same Sysmon config, different EDR
2. Copy the full `PAS/` folder to each
3. Run: `pas_runner.exe --suite scenarios/suites/edr_eval_v1.yml --vendor <VendorName>`
4. After each scenario, check EDR console and SIEM for the events in the analyst checklist
5. Populate `vendor_results` in the result JSON manually (detected/blocked/notes)
6. Compare `results/` across vendors — your evaluation matrix

---

## Adding New Scenarios

Copy any existing YAML and modify. Step types available:

| Type | Description |
|---|---|
| `exec` | Run a binary with args |
| `exec_powershell` | Run PowerShell (auto-encodes command) |
| `sleep` | Wait N seconds |
| `marker` | Print message (no execution) |
| `file_write` | Write text file to path |
| `file_delete` | Delete a file |
| `reg_write` | Write registry value |
| `reg_delete` | Delete registry value |

---

## Sigma Rule Scaffold (manual, after testing)

After running a scenario and finding the relevant events, use this template:

```yaml
title: <Behavior Name>
status: experimental
description: Detected by PAS scenario <scenario_id>
references:
  - https://attack.mitre.org/techniques/<mitre_id>/
logsource:
  category: process_creation   # or registry_set, file_event, etc.
  product: windows
detection:
  selection:
    Image|endswith: '\<binary>.exe'
    CommandLine|contains: '<key argument>'
  condition: selection
falsepositives:
  - <list known FPs here>
level: medium
tags:
  - attack.<mitre_id>
```

---

## What the Runner Does NOT Do

- Does not exfiltrate data
- Does not connect to C2 or external infrastructure
- Does not read credential material
- Does not persist itself
- Does not disable or tamper with security products
- Does not evaluate its own detection — that's your job

---

## Roadmap

- [ ] `exec_wmi` step type
- [ ] `exec_com` step type (COM object invocation)
- [ ] More scenarios: T1055 process injection variants, T1078 valid accounts, T1566 phishing sim
- [ ] Sigma scaffold auto-generation from analyst checklist fields
