# Phase 4 Automation

Run static tests on the main machine:

```powershell
python -m unittest discover -s tests -p "test_*.py" -v
```

Run the three-VM health check:

```powershell
python tests/e2e/lab_health.py
```

The health check uses SSH for Kali/Ubuntu and WinRM for Windows. Scenario 1 is opt-in and runs the controlled RDP regression test:

```powershell
python -m pip install -r requirements-e2e.txt
python tests/e2e/scenario_rdp_bruteforce.py --execute
```

The default accounts are `./socrunner` for WinRM and `regression-test` for the RDP test user. No passwords are stored in the repository.
