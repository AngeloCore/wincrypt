# WinCrypt

⚠️ Windows Only

> **[WinCrypt](https://npmjs.com/wincrypt)** is built in [rust](https://www.rust-lang.org/) and uses the native windows api's [CryptProtectData](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata) and [CryptUnprotectData](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptunprotectdata) functions

## Example

```js
const wincrypt = require("wincrypt");

const text = Buffer.from("test");
const pass = Buffer.from("123");

const encrypted = wincrypt.protectData(text, pass);

console.log(wincrypt.unprotectData(encrypted, pass).toString()); // Prints "test"
```

## Types

```ts
export const enum Flags {
  CurrentUser = "CurrentUser",
  LocalMachine = "LocalMachine"
}

export function protectData(
  data: Buffer,
  optionalEntropy?: Buffer | undefined | null,
  flags?: Flags | undefined | null
): Buffer;

export function unprotectData(
  data: Buffer,
  optionalEntropy?: Buffer | undefined | null,
  flags?: Flags | undefined | null
): Buffer;
```

## Usage

### Without password

```js
wincrypt.protectData(Buffer.from("test"));
```

### With custom flag (only `CRYPTPROTECT_LOCAL_MACHINE` supported)

```js
wincrypt.protectData(Buffer.from("test"), null, wincrypt.Flags.LocalMachine);
// or
wincrypt.protectData(Buffer.from("test"), null, "LocalMachine");
```

> The usage for `unprotectData` method is the same as `protectData`

© (C) Angelo II Apache-2.0 license, all right reserved
