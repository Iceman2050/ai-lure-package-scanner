# ai-lure-package-scanner

Scan your `package.json` / `package-lock.json` for **AI-lure malware patterns** — dependencies
with AI-themed names (nebula/llm/gpt/agent-sdk style), published within days, low download
counts, and install hooks. That's the exact signature of the "fake AI SDK" malware wave,
caught by pattern-matching instead of blocklists that lag behind still-live packages.

**News hook (2026-10-09):** CloudSEK's NEBULA campaign — 7 malicious npm packages posing as
AI dev tools (NebulaAI SDK lure) were published via disposable accounts (`nebulallms` →
`nebulallms4`); an obfuscated `preinstall.cjs` deployed a Windows RAT. `api-nebula` (under
advisory MAL-2026-17531) was **still downloadable on Oct 8** — after the advisory.
Source: https://www.iotinsider.com/industries/security/fake-ai-sdk-packages-on-npm-deliver-windows-remote-access-trojan/

## How it works

For every dependency in your lockfile it queries the npm registry API and scores four signals:

| Signal | What it checks |
|---|---|
| `ai_lure_name` | name matches AI-lure regex (`nebula`, `llm`, `gpt`, `openai`, `claude`, `agent-sdk`, …) |
| `published_recently` | latest version published < 14 days ago |
| `low_downloads` | < 1,000 downloads in the last week |
| `install_scripts` | declares `preinstall`/`install`/`postinstall` hooks |

**HIGH** = all 4 signals · **MEDIUM** = 2–3 · **LOW** = 1 · **CLEAN** = 0.

> Scope note: a name match alone is only LOW — legit AI SDKs exist. The tool flags the
> *combination*, and every flag cites its evidence so you can judge for yourself.

## Install & use

```bash
pip install requests
python -m pip install .   # or just run from the repo root
ai-lure-scan scan package-lock.json
```

Live mode hits `https://registry.npmjs.org/<pkg>` and `https://api.npmjs.org/downloads/point/last-week/<pkg>`.

Offline mode (CI-friendly, no network):

```bash
ai-lure-scan scan package.json --offline --fixture tests/fixtures/registry-fixture.json
```

JSON output: add `--json`. Exit code is `1` if any dependency is HIGH.

## Example

```
$ ai-lure-scan scan package.json --offline --fixture tests/fixtures/registry-fixture.json
PACKAGE                             SEVERITY  EVIDENCE
----------------------------------------------------------------------------------------------------
lodash                              CLEAN     no lure signals
nebula-ai-sdk                       HIGH      ai_lure_name: package name matches AI-lure pattern (matched 'nebula')
                                              published_recently: latest version 1.0.3 published 8 day(s) ago (< 14 days)
                                              low_downloads: 212 downloads in the last week (< 1000)
                                              install_scripts: declares install hook(s): preinstall (runs code at install time)
----------------------------------------------------------------------------------------------------
scanned 2 package(s); 1 HIGH severity
```

## Development

```bash
pip install pytest requests
pytest
```

## Built by Ingenious AI

- [DisclosureGuard](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20DisclosureGuard.)
- [ModelMinder](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ModelMinder.)
- [TermsWatch](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20TermsWatch.)
- [Vibe-Code Audit](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Vibe-Code%20Audit.)
- [Rogue-Agent Defense](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Rogue-Agent%20Defense.)
- [BreachHunter](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20BreachHunter.)
- [ChatBreaker](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ChatBreaker.)
- [Agent Flight Recorder](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Agent%20Flight%20Recorder.)
- [Agent Auth Gateway](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Agent%20Auth%20Gateway.)
- [DomainGuard](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20DomainGuard.)
- [ContentCraft AI](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ContentCraft%20AI.)

## License

MIT — see [LICENSE](LICENSE).
