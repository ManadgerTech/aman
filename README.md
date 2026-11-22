# Aman (أمان) 🛡️

**A self-hosted privacy gateway for LLM APIs — with Arabic, French and
Moroccan PII detection.**

Point any application at Aman instead of your LLM provider. Aman finds
personal data in every request — emails, credit cards, API keys, Moroccan
CIN / ICE / phone numbers / MA IBANs, and person names in Arabic and
French — replaces them with stable placeholders, forwards the clean request
to any OpenAI-compatible upstream (OpenAI, Ollama, vLLM, llama.cpp...), and
restores the original values in the response, **including streamed
responses**, before your app sees it.

Your data protection posture changes; your code changes by one line:
`base_url`.

Made in Morocco by [Manadger Tech](https://manadgerhost.com). Zero
dependencies, Python 3.9+, MIT licensed.

## Why

Existing redaction proxies are English-centric. None of them detect
`السيد يوسف العلوي`, `Mme Karima Bennani`, a Moroccan CIN like `AB123456`,
an ICE company ID, a `+212 6...` mobile number or a `MA...` IBAN. If your
users write in Arabic, Darija or French, their personal data goes straight
through. Aman closes that gap.

- **Drop-in**: speaks the OpenAI API (`/v1/chat/completions`, `/v1/completions`),
  streaming included.
- **Deterministic**: rule- and gazetteer-based detection — no model to
  download, no extra latency worth mentioning, no third-party calls.
- **Private by design**: the audit log records redaction *counts by type*,
  never the values. Nothing leaves your machine except the redacted
  request to the upstream you chose.
- **Restores responses**: placeholders are swapped back, even when a token
  stream splits a placeholder across chunks.

## Quickstart

```bash
# Run against a local Ollama
python aman.py serve --upstream http://localhost:11434/v1 --port 8787

# Or against OpenAI (forward your key; Aman passes Authorization through)
python aman.py serve --upstream https://api.openai.com/v1 --port 8787 \
    --audit ./aman-audit.jsonl
```

Then in your application:

```python
from openai import OpenAI
client = OpenAI(base_url="http://127.0.0.1:8787/v1", api_key="...")
# Everything else stays the same.
```

Preview what gets redacted:

```bash
$ python aman.py scan "سميتي إلياس اللمطي، الإيميل ديالي foo@example.com و رقمي 0670472999"
سميتي __AMAN_PII_PERSON_1__، الإيميل ديالي __AMAN_PII_EMAIL_1__ و رقمي __AMAN_PII_PHONE_MA_1__

Redactions:
  PERSON: __AMAN_PII_PERSON_1__ -> <12 chars>
  EMAIL: __AMAN_PII_EMAIL_1__ -> <15 chars>
  PHONE_MA: __AMAN_PII_PHONE_MA_1__ -> <10 chars>
```

## Docker

```bash
docker compose up -d        # serves on :8787, upstream from AMAN_UPSTREAM
```

## What it detects

| Kind | Examples |
| --- | --- |
| `EMAIL` | foo@example.com |
| `CARD` | Luhn-validated card numbers |
| `API_KEY` | `sk-...`, `ghp_...`, `AKIA...`, `AIza...`, `xoxb-...` |
| `CIN_MA` | Moroccan national ID, e.g. `AB123456` |
| `ICE_MA` | 15-digit company ID (matched near an `ICE` hint) |
| `PHONE_MA` | `+212 6...`, `06/07...` mobiles |
| `IBAN_MA` | `MA` + 26 digits |
| `PERSON` | `السيد يوسف العلوي`, `الدكتورة سارة`, `سميتي ...`, `Mme Karima Bennani`, `Je m'appelle ...` |

Detection is intentionally conservative: it errs toward recall on
identifiers with real formats (cards are Luhn-checked, ICE requires a
nearby `ICE` hint) and documents its limits. It is a strong layer, not a
guarantee — pair it with your own review for regulated workloads.

## How it works

1. Your app sends a normal OpenAI-compatible request to Aman.
2. Aman scans every message and replaces each detection with a placeholder
   like `__AMAN_PII_EMAIL_1__`, keeping the mapping in memory only.
3. The redacted request goes to the upstream; the mapping never does.
4. The response (streamed or not) is scanned for placeholders, which are
   replaced with the original values before your app receives them.
5. The audit log gets one line: timestamp, endpoint, counts by type.

## Library use

```python
import aman

redactor = aman.Redactor()
r = redactor.redact("اتصل بيا فـ 0670472999")
r.clean_text          # "اتصل بيا فـ __AMAN_PII_PHONE_MA_1__"
redactor.restore(r.clean_text, r.mapping)   # original text back

# For token streams:
restorer = aman.StreamingRestorer(r.mapping)
for chunk in stream:
    safe_text = restorer.feed(chunk)
safe_text = restorer.flush()
```

## Tests

```bash
python -m unittest tests_aman -v
```

## Roadmap

- Config-file driven detector toggles and custom regex rules
- Darija name gazetteer expansion
- LiteLLM guardrail adapter
- Metrics endpoint (Prometheus)

## License

MIT © Manadger Tech SARL

---

## بالدارجة / بالعربية 🇲🇦

**أمان** هو بوابة خصوصية كتحطها بين التطبيق ديالك وأي API ديال الذكاء
الاصطناعي. قبل ما يخرج شي طلب من الجهاز ديالك، كيقلب على المعطيات الشخصية —
الإيميلات، الأرقام ديال البنوك، البطاقة الوطنية (CIN)، ICE ديال الشركات،
أرقام الهواتف المغربية، والأسماء بالعربية والفرنسية — وكيحيّدها وكيبدلها
برموز، ومن بعد كيرجعها فالجواب كأن والو ما وقع.

- كيخدم مع Ollama، OpenAI، vLLM... غير بدل `base_url`.
- السجل (audit log) كيسجل غير العدد ديال المعطيات المحجوبة، أبدا ماشي
  القيم ديالها.
- كلشي مفتوح المصدر وبلا حتى مكتبة خارجية.

```bash
python aman.py serve --upstream http://localhost:11434/v1
```
