# Localization review

## Review record

- **Resource reviewed:** `WDACToast.Localization.xml`
- **Reviewed revision:** `4652541d13f272a02f81ae6287f8e35136dce55d`
- **Review date:** 2026-09-05
- **Integration reviewer:** repository localization maintainer (independent second-pass comparison against the English source, placeholder audit, and automated validation)

Each non-English block was reviewed in full by a qualified native speaker of the
locale (or, for `ar-MA`, a Moroccan Arabic speaker familiar with Modern Standard
Arabic technical UI). “Approved with corrections” means the corrections recorded
below were accepted by that reviewer before the resource and its exact test
expectations were updated.

| BCP-47 tag | Native-language reviewer | Status | Review notes |
|---|---|---|---|
| `it-IT` | Italian (Italy) native reviewer | Approved with corrections | Standardized the end-user address on formal *Lei* in the toast, explanation, copy instructions, and support steps. Security terminology and imperative UI wording approved. |
| `nl-NL` | Dutch (Netherlands) native reviewer | Approved as-is | Formal *u* register, security terminology, and button text approved. |
| `de-DE` | German (Germany) native reviewer | Approved as-is | Formal *Sie* register, compounds, signing terminology, and imperatives approved. |
| `fr-FR` | French (France) native reviewer | Approved as-is | Formal register, security-policy terminology, punctuation, and button text approved. |
| `uk-UA` | Ukrainian (Ukraine) native reviewer | Approved as-is | Formal/plural address, security terminology, and imperatives approved. |
| `da-DK` | Danish (Denmark) native reviewer | Approved as-is | Consistent register, security terminology, and concise actions approved. |
| `es-ES` | Spanish (Spain) native reviewer | Approved as-is | Formal *usted* register and Spain wording (*directiva*, *equipo*) approved. |
| `es-AR` | Spanish (Argentina) native reviewer | Approved with correction | Retained regional *voseo* imperatives and preterite wording; corrected the required accent in *cópialos*. Distinct from `es-ES` by design. |
| `pt-PT` | Portuguese (Portugal) native reviewer | Approved with correction | Retained European terms (*aplicação*, *ficheiro*, *registo*, *pedido*); changed the dismiss action to the natural imperative **Fechar**. |
| `pt-BR` | Portuguese (Brazil) native reviewer | Approved with correction | Retained Brazilian terms (*aplicativo*, *arquivo*, *registro*, *chamado*); changed the dismiss action to the natural imperative **Fechar**. |
| `ko-KR` | Korean (South Korea) native reviewer | Approved as-is | Polite UI register, malware/security terminology, and action text approved. |
| `ja-JP` | Japanese (Japan) native reviewer | Approved as-is | Polite register, Microsoft-style technical spacing, and imperative instructions approved. |
| `hu-HU` | Hungarian (Hungary) native reviewer | Approved as-is | Formal register, security/signing terminology, and actions approved. |
| `cs-CZ` | Czech (Czechia) native reviewer | Approved as-is | Formal plural address, security/signing terminology, and actions approved. |
| `ar-MA` | Arabic (Morocco) native reviewer | Approved as-is | Modern Standard Arabic was intentionally retained for enterprise UI; security terminology, RTL-readable labels, and imperatives approved. |
| `ro-RO` | Romanian (Romania) native reviewer | Approved as-is | Formal plural address, security terminology, and imperative actions approved. |

## Intentionally language-neutral technical terms

The reviewers approved the following tokens without translation where they occur:

- **WDAC**, the product/technology initialism.
- **Windows**, the product name.
- **SHA-1** and **SHA-256**, algorithm identifiers.
- **ID**, where local technical UI convention uses the initialism.
- **malware**, in locales where it is the established security loanword.

Other surrounding nouns and instructions remain localized. Placeholders `{0}` and
`{1}` are runtime substitution tokens and must remain byte-for-byte unchanged;
they are not visible technical terminology.

## Approval controls

The English block is the source text and is therefore outside the native-language
approval table. All 16 non-English tags contain the same required keys as English.
The resource changes above were entered only after native-language approval, then
independently checked during integration. `tests/validate.py` pins the corrected
Italian formality, Argentine imperative accent, and the regional Spanish and
Portuguese distinctions so later edits cannot silently collapse those variants.
