
# Desktop SMS Lite for Android PC Sync API allows remote network adjacent unauthenticated attackers to send and read arbitrary SMS messages

**Vulnerability Report**  
**Vendor:** Zerogic Inc.  
**Product:** SMS Forwarder for Android (`com.frzinapps.smsforward`)  
**Affected Version:** 10.08.06 (versionCode 20257)  
**Report Date:** 10 September 2026 UTC  
**Reporter:** Edward "Actuator" Warren  
**VulnCheck ID:** 5a61c617-2ea7-4ac3-aaf7-6a894897319a  
**Severity:** High  
**CVSS v3.1:** 8.1 (`AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`)

## Summary

The PC Sync feature of SMS Forwarder for Android opens a cleartext HTTP service on a wildcard socket and exposes message-read and message-send commands **without pairing, authentication, or per-request authorization**.

An adjacent LAN client can read SMS data and cause a controlled SMS to be sent. Any Android app holding only the `INTERNET` permission can also retrieve SMS conversation data via `127.0.0.1`, creating a same-device cross-application privilege bridge.

Once PC Sync is enabled, the unauthenticated HTTP API remains reachable even while the device is locked. No pairing, credential, session, or on-device approval is required.

## Affected Component

- **Feature:** View and Reply on PC (PC Sync)
- **Primary Endpoint:** HTTP `/getData` (default TCP port 8888)
- **Primary Weakness:** Missing Authentication for Critical Function
- **Primary CWE:** [CWE-306](https://cwe.mitre.org/data/definitions/306.html) – Missing Authentication for Critical Function
- **Related CWEs:** CWE-862 (Missing Authorization), CWE-319 (Cleartext Transmission of Sensitive Information)

## Technical Analysis

### Listener Boundary

`PCSyncService.S` selects TCP port 8888 (or a nearby available port) and starts an embedded NanoHTTPD implementation. A null hostname is passed into `kj.e.U`, resulting in a wildcard bind (`*:8888`) rather than a bind restricted to the Wi-Fi address shown in the UI.

The service is reachable via the displayed IPv4 Wi-Fi address **and** via `127.0.0.1`.

### Unauthenticated Command Dispatch

`kj.e.H` handles `/getData`, extracts the caller-controlled `command` parameter, and passes it directly to `e4.d.e`. No password, pairing key, bearer token, session cookie, client certificate, source-address allowlist, or Android caller identity is checked.

| Command          | Behavior                                              | Security Boundary Crossed              |
|------------------|-------------------------------------------------------|----------------------------------------|
| `getdualsim`     | Returns SIM metadata                                  | Low-sensitivity reachability           |
| `getchatlist`    | Returns thread ID, address, display name, latest body, date, read state | SMS confidentiality                    |
| `getchatmessages`| Returns message type, body, and date for a selected thread | Message-history confidentiality        |
| `sendmessage`    | Accepts destination, body, and SIM slot; enters normal outbound pipeline | SMS integrity / possible cost          |
| `checkchanged`   | Waits for change state                                | Unauthenticated long-poll resource use |

### Privileged Data & Send Paths

Conversation and message commands obtain data from Android Telephony SMS/MMS providers (and Samsung RCS providers where available). The caller receives data its own Android permissions would not allow it to read.

The `sendmessage` path constructs a `SendNode`, persists it, and reaches `SmsManager.sendTextMessage` / `sendMultipartTextMessage` through the application’s normal outbound pipeline.

### Transport

The feature advertises an `http://` URL. Responses are Base64-encoded and returned as `text/plain`. Base64 provides reversible encoding only — not encryption, integrity, or peer authentication.

### Key Code Locations

- `PCSyncService.S`
- `kj.e.U`
- `kj.b$r.run`
- `kj.e.H`
- `e4.d.e`
- `e4.d.h`
- `e4.d.i`
- `e4.d.l`
- `z3.m.d`

## Dynamic Evidence

| ID | Source                  | Result |
|----|-------------------------|--------|
| D1 | LAN browser             | PC Sync UI exposed real conversation previews over HTTP on the phone’s Wi-Fi address |
| D2 | Burp capture            | `POST /getData` with `getchatmessages` returned HTTP 200 with no Authorization or Cookie headers; Base64 response decoded to JSON |
| D3 | Controlled send         | Unauthenticated `sendmessage` request caused a generated marker to reach a researcher-controlled destination |
| D4 | Socket inspection       | `ss` showed `LISTEN` on `*:8888` while PC Sync was active |
| D5 | Loopback transport      | ADB shell TCP probe to `127.0.0.1:8888` returned success |
| D6 | Ordinary Android app    | Helper app requesting only `INTERNET` called `getchatlist` via `127.0.0.1` and received 10 conversation records (HTTP 200) |
| D7 | Negative boundary       | No application-driven NAT traversal, relay, or tunnel found; public WAN reachability not established |

### Same-Device Evidence Record

- **Endpoint:** `http://127.0.0.1:8888`
- **Command:** `getchatlist` (`pageKey=0`, `pageSize=10`)
- **HTTP Result:** 200
- **Authorization:** None (no Authorization header, no session cookie)
- **Wire Response:** 2764 bytes (SHA-256: `4022aa64044bc371fd68b2dbf108a26a924f87d9cc185edb66a299e6d8061e21`)
- **Decoded Response:** 2071 bytes (SHA-256: `7db5559ca26acdf6e47b3cc400267abc5346ebf828cd74fa53022d033a32c368`)
- **Returned Records:** 10 conversation objects (pseudonymized)
- **Elapsed Time:** 33 ms

> The `I_AM_AUTHORIZED` phrase used by the helper is a researcher safety control only. It is **not** transmitted to or validated by PC Sync.

## Reproduction

**Preconditions**

1. Install `com.frzinapps.smsforward` version 10.08.06 (build 20257).
2. Grant the permissions required for reading and sending SMS.
3. Open **View and Reply on PC** and start PC Sync.
4. Note the displayed local address and TCP port (normally 8888).

**Low-sensitivity LAN control**

```powershell
$cmd = '{"command":"getdualsim"}'
$encoded = curl.exe -sS -X POST "http://PHONE_LAN_IP:8888/getData" `
  --data-urlencode "command=$cmd"
[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encoded.Trim()))
```

**Expected:** HTTP 200 and a decoded response with no authentication challenge.

**Synthetic conversation read**

```powershell
$cmd = '{"command":"getchatlist","pageKey":"0","pageSize":"10"}'
$encoded = curl.exe -sS -X POST "http://PHONE_LAN_IP:8888/getData" `
  --data-urlencode "command=$cmd"
[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encoded.Trim()))
```

**Same-device Android read**

1. Install a helper app that holds only the `INTERNET` permission.
2. With PC Sync active, probe `127.0.0.1:8888`.
3. Invoke `getchatlist`.
4. Observe HTTP 200 and conversation metadata with no authentication.

**Controlled integrity proof**

1. Use only a researcher-controlled destination.
2. Invoke `sendmessage` with a unique marker.
3. Confirm the marker arrives at the controlled destination.

**Negative control**

Stop PC Sync and repeat the TCP probe. Connection should fail.

## Security Impact

| Property       | Assessment | Practical Consequence |
|----------------|------------|-----------------------|
| Confidentiality| High       | Unauthorized retrieval of correspondents, message previews, bodies, timestamps, and read state |
| Integrity      | High       | Unauthorized SMS transmission through the victim device/subscription |
| Availability   | Not scored | Long-polling and unbounded history materialization create secondary risk |

### Attack Scenarios

- Untrusted user on the same Wi-Fi / local segment discovers TCP 8888 and reads or sends SMS without pairing.
- Co-located Android app with only `INTERNET` permission connects to `127.0.0.1` and borrows the target’s `READ_SMS` / `SEND_SMS` capabilities.
- On-path local network observer reads or modifies cleartext commands and Base64 responses.
- VPN, mesh, hotspot, or other routed interface exposes the wildcard listener beyond the address shown in the UI.

## Severity (CVSS v3.1)

**Base Score:** 8.1 High  
**Vector:** `AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`

| Metric | Rationale |
|--------|-----------|
| AV:A   | Strongest demonstrated remote path requires reachability on an adjacent/routed local network |
| AC:L   | Endpoint and JSON command structure are deterministic |
| PR:N   | No pairing credential, token, or authenticated session required |
| UI:N   | After PC Sync is enabled, no further user interaction is needed |
| S:U    | Impact occurs through the vulnerable application’s own SMS privileges |
| C:H    | Conversation metadata and message bodies are exposed |
| I:H    | Controlled test confirmed attacker-directed SMS transmission |
| A:N    | Availability impact intentionally excluded from primary score |

## Root Cause

| Control            | Intended Trust              | Implemented Boundary                     |
|--------------------|-----------------------------|------------------------------------------|
| Peer identity      | A chosen paired PC          | Any socket client that reaches the listener |
| Listener scope     | Displayed Wi-Fi address     | Wildcard socket (LAN + loopback)         |
| Read authorization | User-authorized PC session  | No check before `getchatlist` / `getchatmessages` |
| Send authorization | User-authorized reply       | No per-request confirmation              |
| Transport security | Private message channel     | Cleartext HTTP + reversible Base64       |

## Remediation Recommendations

1. Require explicit pairing before returning message data or accepting a send command. Use a high-entropy, short-lived secret displayed on the phone and bind it cryptographically to the client session.
2. Authenticate every API request and apply command-specific authorization (read-capable clients should not automatically receive send authority).
3. Bind to loopback by default. If LAN operation is required, demand explicit user activation, show connected clients, and expire the listener after a short idle period.
4. Use an authenticated encrypted channel (TLS identity established during pairing). Do not treat Base64 as protection.
5. Require phone-side confirmation for a new client, new destination, or first state-changing command. Provide an immediate revoke/disconnect control.
6. Close the listener during service destruction, permission revocation, network transitions, logout, and explicit Stop. Verify the port is closed before reporting the feature stopped.
7. Validate page/thread parameters, apply limits before provider materialization, use a bounded worker pool, and rate-limit authenticated clients.
8. Return the minimum fields necessary and maintain a visible, privacy-preserving audit log of client reads and sends.
