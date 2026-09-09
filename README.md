# Client-Side Hasher for Google Tag Manager

A lightweight, fully sandboxed Google Tag Manager (Web Container) custom variable template that synchronously hashes any input string using **SHA-256**, **SHA-512**, or **SHA-128 (MD5)**.

Designed specifically for client-side privacy compliance, data normalization, and PII hashing before sending data to analytics and marketing destinations.

---

## Features

- **100% Synchronous:** Unlike the asynchronous native web APIs, this variable computes hashes synchronously, making it fully compatible with standard GTM Variable resolution.
- **Multiple Algorithms Supported:**
  - `SHA-256` (Default, 64-character hex)
  - `SHA-512` (128-character hex)
  - `SHA-128` (MD5, 32-character hex)
- **Full UTF-8 Support:** Accurately encodes special characters, accents, and unicode strings.
- **Zero Permissions Required:** Operates strictly within the sandboxed JavaScript environment without requiring access to `window`, cookies, or external network requests.
- **Clean Output:** Generates standardized lowercase hexadecimal strings.

---

## Common Use Cases

- **Enhanced Conversions (Google Ads):** Hash normalized email addresses and phone numbers on the client side before tag execution.
- **Meta Pixel / CAPI (Event Match Quality):** Hash customer data (emails, phone numbers, names) directly in the browser.
- **TikTok & Pinterest Tag Matching:** Prepare hashed user identifiers for conversion tracking.
- **Privacy Compliance:** Obfuscate sensitive user parameters or identifiers before passing them to third-party vendors.

---

## Template Fields

| Field Name | Type | Description |
| :--- | :--- | :--- |
| **Input value** (`inputValue`) | Text / Variable | The raw string value or GTM variable you wish to hash (e.g., `{{dlv - email}}`). |
| **Hash algorithm** (`algorithm`) | Radio | Choose between `SHA-256` (default), `SHA-512`, or `SHA-128`. |

---

## Example Outputs

| Input Value | Algorithm | Result (Hexadecimal) |
| :--- | :--- | :--- |
| `hello` | SHA-256 | `2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824` |
| `hello` | SHA-128 (MD5) | `5d41402abc4b2a76b9719d911017c592` |
| `hello` | SHA-512 | *(128-character hex digest)* |

*Note: If the input value is empty or `undefined`, the variable gracefully returns `undefined`.*

---

## Installation

### From the Community Template Gallery (Recommended)
1. In your GTM Web Container, navigate to **Templates** > **Variable Templates**.
2. Click **Search Gallery**.
3. Search for **Client-Side Hasher** and click **Add to workspace**.

### Manual Import
1. Download `template.tpl` from this repository.
2. In GTM, go to **Templates** > **Variable Templates** > **New**.
3. Click the three dots menu (`⋮`) in the top right corner and select **Import**.
4. Select the downloaded `template.tpl` file and click **Save**.

---

## Issues & Contributing

If you encounter any issues or have feature suggestions, please open an issue in the [GitHub Issues](https://github.com/YOUR-USERNAME/YOUR-REPO/issues) section.

---

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
