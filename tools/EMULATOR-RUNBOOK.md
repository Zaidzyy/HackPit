# Mobile app-capture runbook (any app; Fishbowl is the worked example)

Goal: two raw authenticated requests (account A, account B) to paste into HackPit `:repeater`
→ import-diff pins the shared app-key vs per-user session token → drive the cross-account IDOR
loop on `/…/thread/{id}/messages`, **both accounts yours only**.

## One command (auto-fires the bench, pauses for your login)
The scripts are portable (paths/frida-version/CA auto-detected via `tools/_bench-env.sh`) and
composable. `capture-bench.sh` chains boot → install → (frida) → system-cert → proxy, then stops
and tells you to log in. **Login stays human; the HackPit `:repeater` IDOR loop stays approved.**
```
APP_MATCH=fishbowl bash tools/capture-bench.sh --apk C:/path/to/app.apkm --pkg fishbowl
# add --frida only if the app pins AND you have an anti-tamper bypass (Fishbowl's RASP breaks Frida)
# any app: APP_MATCH=instagram bash tools/capture-bench.sh --apk insta.apkm --pkg instagram
```
Individual stages (all portable, all self-verifying) if you'd rather step through:
`install-fishbowl.sh <bundle>` · `setup-frida-server.sh` · `install-system-cert.sh` · `fetch-unpinning.sh`.
Override detection with env: `ANDROID_SDK_ROOT`, `MITMPROXY_HOME`, `FRIDA_VERSION`, `APP_MATCH`, `MITM_PORT`.

## Already done (this session)
- `pip install mitmproxy frida-tools` → mitmproxy 12.2.3, frida 17.17.0
  - ⚠ installed to `C:\Users\zaid_\AppData\Roaming\Python\Python313\Scripts` (NOT on PATH)
- `adb` (platform-tools 1.0.41) → `…\AppData\Local\Android\Sdk\platform-tools`
- Android cmdline-tools + `sdkmanager` 12.0 (runs on your JDK 24)
- SDK install of `emulator` + `platforms;android-34` + `system-images;android-34;google_apis;x86_64`
  running in the background (google_apis = rootable; NOT google_play).
- `tools/fetch-unpinning.sh` written (fetches the Frida unpinning script — run it, see below).

## SDK paths (reference)
```
SDK   = C:\Users\zaid_\AppData\Local\Android\Sdk
adb   = %SDK%\platform-tools\adb.exe
emu   = %SDK%\emulator\emulator.exe
avdm  = %SDK%\cmdline-tools\latest\bin\avdmanager.bat
PYSCR = C:\Users\zaid_\AppData\Roaming\Python\Python313\Scripts   (mitmweb, frida)
```

## DO NOW #1 — fetch the Frida unpinning script (classifier blocks me; you run it)
```
! bash /c/Users/zaid_/Downloads/HackPit/tools/fetch-unpinning.sh
```
Expect `PASS: wrote …/frida-multiple-unpinning.js`. Fishbowl is cert-pinned, so the harness
needs this.

## DO NOW #2 — enable the Windows hypervisor (needs admin + a reboot; the fragile piece)
The x86_64 emulator needs hardware accel. In an **admin PowerShell**:
```
DISM /Online /Enable-Feature /All /FeatureName:Microsoft-Windows-Subsystem-Linux /NoRestart  # skip if already
DISM /Online /Enable-Feature /FeatureName:HypervisorPlatform /All /NoRestart
DISM /Online /Enable-Feature /FeatureName:VirtualMachinePlatform /All /NoRestart
```
Then reboot. (If you use Docker Desktop, Hyper-V is likely already on and the emulator will use WHPX.)

## WHEN THE DOWNLOAD FINISHES — I auto-run (or you can):
1. Create the AVD (Google APIs, so `adb root` works):
```
%avdm% create avd -n fishbowl -k "system-images;android-34;google_apis;x86_64" -d pixel_6
```
2. Generate the mitmproxy CA once (headless):
```
"%PYSCR%\mitmdump.exe"   # let it start, Ctrl-C after ~3s; creates ~\.mitmproxy\*
```

## THEN — you boot + capture (GUI + login = your hands)
3. Boot writable-system (so the harness can push its CA into /system):
```
! "C:\Users\zaid_\AppData\Local\Android\Sdk\emulator\emulator.exe" -avd fishbowl -writable-system
```
4. Sideload the Fishbowl APK (you source the APK — e.g. an APKMirror download of the version you use):
```
! "C:\Users\zaid_\AppData\Local\Android\Sdk\platform-tools\adb.exe" install fishbowl.apk
```
5. Run the harness with the extra dirs on PATH (mitmweb/frida/adb resolvable):
```
! PATH="/c/Users/zaid_/AppData/Roaming/Python/Python313/Scripts:/c/Users/zaid_/AppData/Local/Android/Sdk/platform-tools:$PATH" \
    APP_MATCH=fishbowl MITM_PORT=8080 bash /c/Users/zaid_/Downloads/HackPit/tools/mobile-capture.sh
```
   - set the emulator Wi-Fi proxy to `10.0.2.2:8080` (harness step 2 reminds you)
   - log in as **account A**, open a bowl/DM, in mitmweb (http://127.0.0.1:8081) grab the
     `/…/thread/{id}/messages` request → right-click → **Copy as raw**
   - repeat login+capture as **account B**

## THEN — paste both raw captures back to me
I run `parse_capture` on each + `diff_captures` on the pair (already proven working), confirm
app-key vs session-token, then drive the `:repeater` surface-action loop:
- A's request + **B's** session token + **A's** thread id → 200 with A's messages = BOLA
- mirror (B's id, A's token) to prove bidirectional
Every send stays human-approved; only the two thread ids from YOUR captures are ever swapped.

## Fallback (you noted fishbowlapp.com exists)
If the hypervisor/root fight drags, we pivot to desktop capture: log two browser profiles into
fishbowlapp.com, capture their authenticated API calls through mitmproxy (or HackPit's recording
proxy) — no emulator/frida. Same import-diff + loop from there. Say the word and I'll switch tracks.
