# DesktopSMS Lite Local Pairing Authorization Bypass

> **An unprivileged Android application with only `INTERNET` can forge DesktopSMS Lite pairing approval, then use DesktopSMS Lite as a privileged SMS proxy to send SMS and retrieve SMS-derived conversation content without `SEND_SMS` or `READ_SMS`.**

**Product:** DesktopSMS Lite for Android (`net.mrpear.apps.desktopsmslite`)  
**Tested version:** `1.11.0` (`versionCode 49`)  
**Attack surface:** Same-device loopback service at `127.0.0.1:8000`  
**VulnCheck ID:** `1cb652c2-d4f9-4f26-bc93-0a0afc201864`  
**Reporter:** Edward "Actuator" Warren

## Summary

DesktopSMS Lite contains a local pairing authorization flaw. A second Android application can forge a successful pairing result for an attacker-selected identity and then reach privileged SMS functionality exposed through DesktopSMS Lite.

The helper used for validation requested only:

```xml
<uses-permission android:name="android.permission.INTERNET" />
```

It requested **no `SEND_SMS` or `READ_SMS` permission**.

The demonstrated chain allows the helper to:

- forge pairing approval for a fresh `DeviceGuid`;
- **send attacker-controlled SMS through DesktopSMS Lite's privileges**;
- **retrieve SMS-derived conversation content through DesktopSMS Lite's query interface**; and
- persist the attacker-selected paired identity.

## Proof of Concept

<img width="1996" height="1416" alt="image" src="https://github.com/actuator/net.mrpear.apps.desktopsmslite/blob/main/DESKTOPSMS_poc.gif?raw=true" />


> **Google Voice demo note:** The message popup visible in the recording is from **Google Voice**. I sent the PoC SMS to **my own Google Voice number** so I could independently confirm successful receipt. The popup is external delivery confirmation on an account I control; it is **not** a DesktopSMS Lite UI artifact.


## Demonstrated Impact

### Arbitrary SMS sending without `SEND_SMS`

After the forged pair is accepted, the helper invokes:

```text
sendsms.dsms.cmd.icl
```

DesktopSMS Lite submits the attacker-controlled message using its own SMS privileges. In the PoC, `POC TXT` was sent successfully with `StatusCode 0`, while the helper held no `SEND_SMS` permission.

The Google Voice notification shown in the demo independently confirms that the test SMS reached the researcher-controlled destination.

### SMS content access without `READ_SMS`

The same forged identity invokes:

```text
search-conversations-request.dsms.cmd.icl
```

DesktopSMS Lite returns SMS-derived conversation content to the helper. The PoC retrieved `POC TXT` even though the helper held no `READ_SMS` permission.

### Persistent attacker-controlled pairing

The attacker supplies a fresh `DeviceGuid`. Once the forged approval is accepted, that identity is treated as paired and can reach the privileged command surface.

## Attack Chain

```text
Unprivileged Android app
        |
        | INTERNET only
        v
127.0.0.1:8000
DesktopSMS Lite local service
        |
        | attacker-selected DeviceGuid
        v
COM_PAIR_REQUEST_RESULT
result=true
        |
        v
Forged identity accepted as paired
        |
        +-------------------------------+
        |                               |
        v                               v
sendsms.dsms.cmd.icl          search-conversations-request.dsms.cmd.icl
        |                               |
        v                               v
SMS sent without SEND_SMS     SMS content returned without READ_SMS
```

The attacker never obtains Android SMS permissions directly. DesktopSMS Lite performs the privileged operations on the attacker's behalf after the pairing boundary is bypassed.

## Scope and Required Conditions

DesktopSMS Lite must already be configured and its local service must be running. Once active, the demonstrated flow requires:

- no pairing confirmation;
- no `SEND_SMS` permission in the helper;
- no `READ_SMS` permission in the helper; and
- no additional user interaction during exploitation.

This disclosure demonstrates **same-device loopback exploitation** against `127.0.0.1:8000`. It does **not** claim WAN reachability.

## Reproduction

1. Configure DesktopSMS Lite 1.11.0 (`versionCode 49`) on an authorized test phone and start its local service.
2. Install the same-device helper whose manifest declares `INTERNET` only.
3. Run the PoC after confirming the controlled SMS destination ending in `6567`.
4. The helper connects to `127.0.0.1:8000` and submits a fresh `DeviceGuid`.
5. The helper sends `net.mrpear.libs.intercomlib.COM_PAIR_REQUEST_RESULT` with `result=true`.
6. DesktopSMS Lite accepts the forged pair.
7. The helper invokes `sendsms.dsms.cmd.icl`, causing DesktopSMS Lite to send `POC TXT`.
8. The helper invokes `search-conversations-request.dsms.cmd.icl`, and DesktopSMS Lite returns SMS-derived content.

## Observed Results

| Stage | Observed Result | Security Meaning |
|---|---|---|
| Pair | Forged approval accepted | Attacker-selected identity becomes paired |
| Send | `StatusCode 0` | SMS submitted without helper holding `SEND_SMS` |
| Delivery | Google Voice received `POC TXT` | Independent confirmation of actual SMS receipt |
| Read | `POC TXT` returned | SMS-derived content exposed without helper holding `READ_SMS` |
| Persistence | Attacker-selected `DeviceGuid` accepted | Attacker controls the paired identity |

## Root Cause

The pairing-result receiver accepts an unauthenticated external result and does not securely bind approval to a legitimate pairing transaction.

An external application can submit:

```text
net.mrpear.libs.intercomlib.COM_PAIR_REQUEST_RESULT
result=true
```

for an attacker-selected identity. Once accepted, that identity can reach DesktopSMS Lite's privileged SMS commands.

The vulnerable trust transition is:

```text
Untrusted local app
      |
      | forged pairing result
      v
Trusted paired identity
      |
      v
Privileged SMS send / read functionality
```

## Recommended Remediation

- Replace externally forgeable pairing-result broadcasts with an app-private callback.
- Bind pairing approval to a cryptographically unpredictable, single-use nonce.
- Authenticate local service sessions and bind them to the approved pairing transaction.
- Reauthorize sensitive commands such as SMS send and conversation retrieval at the command boundary.
- Do not treat possession of a user-supplied `DeviceGuid` as proof of authorization.


## Weakness Classification

- **CWE-306 - Missing Authentication for Critical Function**
- **CWE-862 - Missing Authorization**

