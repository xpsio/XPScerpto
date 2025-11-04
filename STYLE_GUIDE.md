# XPScerpto Documentation Style Guide

## Tone & Voice
- Use **professional, consistent** language across all documents.
- Prefer **imperative mood** for guides and tutorials (e.g., “Run the command…”, “Use X to do Y.”).
- Prefer **neutral, third-person** language for reference, design, and security docs (e.g., “The module provides…”).
- Write **positively and explicitly**. Avoid hedging and ambiguity (e.g., prefer “Use X to do Y” over “You may want to consider using X to do Y.”).
- Avoid colloquialisms and hype (e.g., replace “battle-ready,” “blazing fast,” “super” with “production-grade,” “high-performance,” “robust,” etc.).

## Grammar & Usage
- Use **American English** spelling consistently, unless the project standard is different.
- Use the correct phrase **“whichever comes first”** (not “whichever first”).
- Prefer “**Comprehensive, well‑structured documentation**” over informal slogans like “Battle‑ready docs.”

## Acronyms & Terminology
- **Define acronyms at first use** in each document, e.g., “Authenticated Encryption with Associated Data (**AEAD**)”.
- After the first definition, use the acronym consistently.
- Use the **Glossary** (GLOSSARY.md) as the canonical reference.

## Formatting
- Use sentence case for headings unless a proper noun requires capitalization.
- Keep paragraphs short (≤ 5 lines).
- Use numbered steps for procedures; bullets for unordered lists.
- Use code fences with language hints (```bash, ```cpp).
- Link to internal docs with relative paths.

## Examples
- Configuration and code examples must be **minimal**, **buildable**, and **tested** where possible.
- Include expected output or behavior.

## File Structure Conventions
- Name primary entry pages `README.md`.
- Place topic-specific documents under `docs/<topic>/`.
- Maintain a single source of truth; avoid duplicated content.
