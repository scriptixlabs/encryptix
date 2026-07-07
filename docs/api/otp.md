---
title: OTP (TOTP / HOTP)
description: RFC 6238 TOTP and RFC 4226 HOTP — authenticator-compatible one-time passwords.
---

# One-Time Passwords (TOTP / HOTP)

Generate and verify time-based (TOTP) and counter-based (HOTP) one-time passwords, compatible with Google Authenticator, 1Password, Authy, and other authenticator apps.

## Enrolment

```ts
// 1. Generate a secret for the user (Base32)
const secret = enc.generateTOTPSecret();          // 20 random bytes → Base32

// 2. Build an otpauth:// URI to render as a QR code
const uri = enc.totpKeyUri(secret, 'user@example.com', 'MyApp', { digits: 6, period: 30 });
// → 'otpauth://totp/MyApp:user@example.com?secret=...&issuer=MyApp'
```

## Verify a code

```ts
const code   = await enc.generateTOTP(secret);            // current 6-digit code
const result = await enc.verifyTOTP(userCode, secret, { skew: 1 });

if (result.valid) {
  // result.delta tells you which time-step matched (-1, 0, +1 with skew:1)
}
```

The `skew` option accepts codes from adjacent time steps to tolerate clock drift.

## HOTP (counter-based)

```ts
const code = await enc.generateHOTP(secret, counter);
```

```ts
generateTOTPSecret(bytes?: number): string
totpKeyUri(secret: string, account: string, issuer: string, options?: Pick<TOTPOptions, 'digits' | 'period'>): string
generateTOTP(secret: string, options?: TOTPOptions): Promise<string>
verifyTOTP(code: string, secret: string, options?: TOTPOptions & { skew?: number }): Promise<TOTPVerifyResult>
generateHOTP(secret: string, counter: number, options?: HOTPOptions): Promise<string>
```

<div class="callout callout-info"><span class="ic">ℹ️</span><p>Base32 helpers <code>toBase32</code> / <code>fromBase32</code> are exported standalone if you need to encode/decode secrets yourself. <code>TOTPOptions</code> covers <code>digits</code>, <code>period</code>, and the HMAC <code>algorithm</code>.</p></div>
