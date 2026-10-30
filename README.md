# Scrappy

Strip secrets and personal data from text before you paste it into ChatGPT, Claude or any other AI tool. Sensitive values become typed placeholders, so the AI still understands the text:

```
Payment failed for john@example.com, key sk-ant-api03-…
Payment failed for [EMAIL_1], key [API_KEY_1]
```

Everything runs locally. Scrappy makes no network calls, and nothing is written to disk.

## Install

Requires Node.js 22 or later.

```sh
npm install -g scrappy-redact
```

The command is `scrappy`.

## Use

**Clipboard, the everyday flow.** Copy the text, run this, then paste:

```sh
scrappy sanitize --clipboard
```

**Get real values back in the AI's reply.** `scrappy session` remembers what it replaced until you quit:

```
$ scrappy session
  s  sanitize the clipboard in place (then paste it into your AI tool)
  r  restore originals into the clipboard (after copying the AI's reply)
  q  quit
```

The originals live only in that process's memory and are discarded when you press `q`. Placeholders the AI invents, such as `[EMAIL_7]`, are left untouched.

**Pipes and files:**

```sh
cat app.log | scrappy sanitize > safe.log
scrappy sanitize --input request.json --format json   # keeps the JSON structure
scrappy inspect --input app.log                       # what was found, never the values
```

**IP addresses (opt-in).** IPs are left alone by default because they're often useful debugging context. Mask them for one run:

```sh
scrappy sanitize --ip -i access.log      # 196.188.12.44 → [IP_ADDRESS_1], 10.0.4.17:8080 → [IP_ADDRESS_2]:8080
```

Or turn masking on for every run. The setting is saved in `~/.config/scrappy/config.json`; only the preference is stored, never your text:

```sh
scrappy config --global --enable-ip-masking    # always mask IPs
scrappy config                                 # show current settings
scrappy config --global --disable-ip-masking   # back to the default
```

IPv4 and IPv6 are both covered, including `::1`, `fe80::1%eth0` and `::ffff:192.0.2.128`. Ports and brackets stay visible. Version numbers, times like `12:30:45`, MAC addresses and invalid values like `999.1.1.1` are not touched.

**All commands and options:**

```sh
scrappy help        # or scrappy --help, or just scrappy
```

Stdout carries only sanitized content. Exit codes are `0` for success, `1` for an input, config or processing error, and `2` for invalid usage. Your input file is never modified.

## What it detects

| Type | Examples |
|---|---|
| `EMAIL` | `john.doe+ci@mail.example.co.uk` |
| `API_KEY` | Anthropic, OpenAI, GitHub, GitLab, Slack, AWS access key IDs, Google, Stripe |
| `JWT` | `eyJhbGciOi….eyJzdWIi….sig` |
| `ACCESS_TOKEN` | `Authorization: Bearer …` |
| `PASSWORD` | `password=…`, `"api_key": "…"`, `DB_PASSWORD: …`, `postgres://user:PASSWORD@host` |
| `PRIVATE_KEY` | PEM and PGP private key blocks, including truncated ones |
| `PAYMENT_CARD` | Visa, Mastercard, Amex, Discover and more; checked with the card checksum (Luhn) |
| `PHONE` | International numbers (`+251 911 234 567`), or any number right after a word like phone, call, mobile or WhatsApp |
| `SECRET` | Random-looking tokens with no known prefix, e.g. `X-Internal-Auth: Hq3Zm8Wv1Ks6…` |
| `IP_ADDRESS` | IPv4 and IPv6. **Only with `--ip` or `scrappy config --global --enable-ip-masking`** |

`SECRET` is a best guess. It skips hashes, UUIDs and code identifiers, but it can flag base64 data, such as certificate fingerprints. To turn it off, list the types you want to keep in `enabledTypes` and leave out `SECRET`:

```json
{ "policy": { "enabledTypes": ["EMAIL", "PHONE", "PAYMENT_CARD", "API_KEY", "ACCESS_TOKEN", "JWT", "PRIVATE_KEY", "PASSWORD"] } }
```

Add your own identifiers, such as account or customer IDs, with a config file:

```json
{
  "customDetectors": [
    { "id": "account", "type": "ACCOUNT_NUMBER", "pattern": "account (?<value>\\d{6})" }
  ],
  "policy": { "allowlist": ["support@mycompany.com"] }
}
```

```sh
scrappy sanitize --clipboard --config scrappy.json
```

If the pattern has a group named `value`, only that part is replaced. Otherwise the whole match is.

## What it does not do

Scrappy reduces what you share. It does not guarantee anonymity.

- It does **not** detect names or street addresses.
- Phone numbers written without `+` and without a nearby phone word (e.g. a bare `0911 234 567`) are not detected. If you need them, add a custom detector.
- Short or word-like secrets (e.g. `Summer2024!` as a bare value, not after `password=`) can slip through. Check the output before you paste anything highly sensitive.
- Combinations of harmless-looking details can still identify a person.
- Clipboard support uses `pbcopy`/`pbpaste` on macOS and `wl-clipboard` or `xclip` on Linux. Windows is untested. Elsewhere, set `SCRAPPY_PASTE_CMD` and `SCRAPPY_COPY_CMD`.

## License

MIT
