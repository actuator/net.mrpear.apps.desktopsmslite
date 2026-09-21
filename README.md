# DesktopSMS Lite Allows Any Installed App With No CALL or SMS Permissions to Send and Receive Arbitrary SMS Messages via Local Pairing Authorization Bypass

> **An unprivileged Android application with only `INTERNET` can forge DesktopSMS Lite pairing approval, then use DesktopSMS Lite as a privileged SMS proxy to send SMS and retrieve SMS conversation content without `SEND_SMS` or `READ_SMS`.**

**Product:** DesktopSMS Lite for Android (`net.mrpear.apps.desktopsmslite`)  
**Tested version:** `1.11.0` (`versionCode 49`)  
**Attack surface:** Same-device loopback service at `127.0.0.1:8000`  
**VulnCheck ID:** `1cb652c2-d4f9-4f26-bc93-0a0afc201864`  
**Reporter:** Edward "Actuator" Warren

## Summary

DesktopSMS Lite contains a local pairing authorization flaw that allows **any installed Android application with only the normal `INTERNET` permission** to forge a successful pairing result and reach privileged SMS functionality.

The validation helper requested only:

```xml
<uses-permission android:name="android.permission.INTERNET" />
```

Android classifies `INTERNET` as a **normal** permission, not a dangerous/runtime permission. Normal permissions are granted automatically at install time when declared in the manifest and do not trigger the runtime permission prompt used for dangerous permissions. In practical terms, the helper does not need the user to approve any phone or SMS capability before reaching the vulnerable local interface.

It requested **no `SEND_SMS` or `READ_SMS` permission**.

The demonstrated chain allows the helper to:

- forge pairing approval for a fresh attacker-controlled `DeviceGuid`;
- **send attacker-controlled SMS through DesktopSMS Lite without `SEND_SMS`;**
- **retrieve SMS conversation content through DesktopSMS Lite without `READ_SMS`;** and
- persist the attacker-selected paired identity.

The result is that an otherwise unprivileged installed application can use DesktopSMS Lite as a **privileged SMS proxy for both sending messages and accessing received SMS content**.

## Proof of Concept

<img width="1996" height="1416" alt="DesktopSMS Lite pairing bypass PoC" src="https://github.com/actuator/net.mrpear.apps.desktopsmslite/blob/main/DESKTOPSMS_poc.gif?raw=true" />

[View the PoC GIF directly](https://github.com/actuator/net.mrpear.apps.desktopsmslite/blob/main/DESKTOPSMS_poc.gif?raw=true)

> **Google Voice demo note:** The message popup visible in the recording is from **Google Voice**. I sent the PoC SMS to **my own Google Voice number** so I could independently confirm successful receipt. The popup is external delivery confirmation on an account I control; it is **not** a DesktopSMS Lite UI artifact.

## Demonstrated Impact

### Arbitrary SMS Sending Without `SEND_SMS`

After the forged pair is accepted, the helper invokes:

```text
sendsms.dsms.cmd.icl
```

DesktopSMS Lite sends the attacker-controlled message using its own SMS privileges.

In the PoC:

```text
POC TXT
StatusCode 0
```

was successfully sent while the helper held **no `SEND_SMS` permission**.

The Google Voice notification shown in the demo independently confirms that the SMS reached the researcher-controlled destination.

### SMS Content Access Without `READ_SMS`

The same forged identity invokes:

```text
search-conversations-request.dsms.cmd.icl
```

DesktopSMS Lite returns SMS-derived conversation content to the helper.

The PoC retrieved:

```text
POC TXT
```

even though the helper held **no `READ_SMS` permission**.

This allows an installed application that cannot directly read SMS under Android's permission model to obtain SMS content through DesktopSMS Lite instead.

### Persistent Attacker-Controlled Pairing

The attacker supplies a fresh `DeviceGuid`.

Once the forged approval is accepted, that attacker-selected identity is treated as paired and can access the privileged command surface.

## Attack Chain

```text
Unprivileged Android app
        |
        | INTERNET only
        | no SEND_SMS
        | no READ_SMS
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

The attacker never obtains Android SMS permissions directly. DesktopSMS Lite performs the privileged SMS operations on the attacker's behalf after the pairing authorization boundary is bypassed.

## Scope and Required Conditions

DesktopSMS Lite must already be configured and its local service must be running.

Once active, the demonstrated flow requires:

- an installed Android application;
- only the normal `INTERNET` permission, which Android grants at install time without a runtime dangerous-permission prompt;
- no pairing confirmation;
- no `SEND_SMS`;
- no `READ_SMS`; and
- no additional user interaction during exploitation.

This disclosure demonstrates **same-device loopback exploitation** against `127.0.0.1:8000`. It does **not** claim WAN reachability.

## Reproduction

1. Configure DesktopSMS Lite `1.11.0` (`versionCode 49`) on an authorized test phone and start its local service.
2. Install the same-device helper whose manifest declares `INTERNET` only.
3. Run the PoC after confirming the controlled SMS destination ending in `6567`.
4. The helper connects to `127.0.0.1:8000` and submits a fresh attacker-controlled `DeviceGuid`.
5. The helper sends `net.mrpear.libs.intercomlib.COM_PAIR_REQUEST_RESULT` with `result=true`.
6. DesktopSMS Lite accepts the forged pair.
7. The helper invokes `sendsms.dsms.cmd.icl`, causing DesktopSMS Lite to send `POC TXT`.
8. The SMS is received by the researcher-controlled Google Voice destination.
9. The helper invokes `search-conversations-request.dsms.cmd.icl`.
10. DesktopSMS Lite returns SMS-derived content despite the helper holding no `READ_SMS`.

## Observed Results

| Stage | Observed Result | Security Meaning |
|---|---|---|
| Pair | Forged approval accepted | Attacker-selected identity becomes paired |
| Send | `StatusCode 0` | SMS sent without helper holding `SEND_SMS` |
| Delivery | Google Voice received `POC TXT` | Independent confirmation of actual SMS receipt |
| Read | `POC TXT` returned | SMS content exposed without helper holding `READ_SMS` |
| Persistence | Attacker-selected `DeviceGuid` accepted | Attacker controls the paired identity |

## Root Cause

The pairing-result receiver accepts an unauthenticated external result and does not securely bind approval to a legitimate pairing transaction.

An external application can submit:

```text
net.mrpear.libs.intercomlib.COM_PAIR_REQUEST_RESULT
result=true
```

for an attacker-selected identity.

Once accepted, that identity can access DesktopSMS Lite's privileged SMS commands, allowing SMS transmission and SMS content retrieval without the attacking application holding Android's corresponding SMS permissions.

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

- Make the pairing-result receiver non-exported where external access is unnecessary
- Replace externally forgeable pairing-result broadcasts with an app-private callback
- Bind pairing approval to a cryptographically unpredictable, single-use nonce
- Authenticate local service sessions and bind them to the approved pairing transaction
- Reauthorize sensitive commands such as SMS send and conversation retrieval
- Do not treat possession of a user-supplied `DeviceGuid` as proof of authorization


## Weakness Classification

- **CWE-306 - Missing Authentication for Critical Function**
