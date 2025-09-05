# Time Capsule (TCAP)

> **Encapsuler du temps CPU en une chaîne SHA‑256 irréversible avec checkpoints, Merkle root et manifeste vérifiable.**

`time_capsule.py` fabrique des **capsules de temps** `.tcap` : une chaîne SHA‑256 de N itérations, horodatée, avec **checkpoints réguliers**, **Merkle root** et **manifeste signé**. Vous pouvez ensuite **vérifier** une capsule (intégrité + échantillons de segments), **inspecter** son manifeste, **générer** et **vérifier** des **preuves Merkle**.

> ⚠️ **Avertissement** : ce projet n’est **pas** une VDF auditée cryptographiquement. C’est une chaîne SHA‑256 simple destinée à matérialiser du **temps CPU** et fournir des preuves pratiques (Merkle + échantillons).

---

## ✨ Caractéristiques

* **Deux modes de charge** : par **nombre d’itérations** (`--iterations`) ou par **durée cible** (`--seconds`) via **calibration** locale.
* **Checkpoints** automatiques (\~2048 par défaut) ou contrôle fin avec `--checkpoint-every`.
* **Preuves Merkle** : `prove` (seed / final / ckpt\:k) & `check` (indépendant de la capsule).
* **Intégrité forte** : hash du manifeste, Merkle root, échantillonnage de segments recalculés.
* **100% standard library** (Python ≥ 3.8) ; portable, offline‑first.

---

## 🔎 Format `.tcap`

Fichier compact avec entête + manifeste JSON UTF‑8 :

```
MAGIC 'TMC1' | uint64_be(manifest_len) | manifest_json_utf8
```

Le **manifeste** contient :

* `version`, `capsule_id`, `created_at`, `note`
* `algo` (sha256\_chain), `seed_hex`, `iterations`, `checkpoint_every`, `checkpoint_count`
* `checkpoints_index[]`, `checkpoints_hash[]`, `final_hash`, `merkle_root`
* `perf` (elapsed\_seconds, rate\_iter\_per\_sec), `system`, `integrity.manifest_sha256`

---

## 🚀 Quickstart

```bash
# 1) Construire une capsule par itérations fixes
python3 time_capsule.py make --iterations 10_000_000 --out build/demo.tcap --note "demo fixed N"

# 2) Construire une capsule sur ~5 secondes (calibration locale)
python3 time_capsule.py make --seconds 5 --out build/5s.tcap --note "demo 5s"

# 3) Vérifier une capsule (manifest, Merkle, segments aléatoires)
python3 time_capsule.py verify --caps build/5s.tcap --samples 8

# 4) Inspecter le manifeste
python3 time_capsule.py inspect --caps build/5s.tcap

# 5) Générer une preuve Merkle pour un checkpoint
python3 time_capsule.py prove --caps build/5s.tcap --which ckpt:10

# 6) Vérifier une preuve Merkle (indépendant)
python3 time_capsule.py check \
  --root <merkle_root_hex> \
  --leaf <leaf_hash_hex> \
  --index <leaf_index> \
  --proof "[[\"R\",\"abc...\"],[\"L\",\"def...\"],...]"
```

---

## 🧩 CLI

```
usage: time_capsule.py {make,verify,inspect,prove,check} [...]

make   : fabrique .tcap
  --iterations INT            nombre total d'itérations SHA‑256
  --seconds FLOAT             durée cible (calibrée) en secondes
  --target-points INT         ~nb de checkpoints (défaut 2048)
  --checkpoint-every INT      pas fixe entre checkpoints (écrase target)
  --seed-hex HEX              seed initiale (sinon aléatoire 32o)
  --note STR                  note libre dans le manifeste
  --calibrate-seconds FLOAT   durée de calibration (défaut 0.5s)
  --out PATH                  sortie .tcap

verify : vérifie .tcap (manifest, Merkle, segments)
  --caps PATH                 fichier .tcap
  --samples INT               nb de segments à tester (défaut 5)
  --seed INT                  seed PRNG pour l'échantillonnage

inspect: affiche le manifeste JSON
  --caps PATH

prove  : preuve Merkle (seed|final|ckpt:k)
  --caps PATH
  --which seed|final|ckpt:k

check  : vérifie une preuve Merkle hors‑capsule
  --root HEX --leaf HEX --index INT --proof JSON
```

---

## 🔒 Intégrité & Sécurité

* **Hash de manifeste** (`integrity.manifest_sha256`) pour détecter toute altération.
* **Merkle root** sur : feuille seed, feuilles checkpoints, feuille finale.
* **Vérification par échantillons** : recalcul local des segments (≤ `checkpoint_every`).
* Recommandations :

  * Signer les `.tcap` (ex. *minisign*, *cosign*).
  * Documenter la plateforme (CPU/flags) si vous comparez des débits.

---

## 🧪 Méthodologie de preuve

1. **Feuille canonique** : `H('LEAF'||type||be64(index)||value)` où `type∈{S,C,F}`.
2. **Preuve** : chemin de frères (L/R) jusqu’à la racine.
3. **Vérification** : recomposer la racine ; égalité ⇒ preuve valide.

---

## 📈 Performance

* `make --seconds` calibre le débit local (it/s) puis fixe `iterations` ≈ seconds × rate.
* Rapport en ligne : progression, ETA, débit moyen en fin de charge.

> Le débit dépend fortement du CPU et des flags (AVX2/sha‑ni non utilisés explicitement).

---

## 🧭 Bonnes pratiques

* Pour **capsules comparables** entre machines, fixez **N** (pas `--seconds`).
* Pour **preuves rapides**, gardez `checkpoint_every` raisonnable (par défaut calculé pour \~2048 points).
* Stockez `manifest.json` (via `inspect`) si vous devez citer la capsule dans un papier/rapport.

---

## 🗺️ Roadmap

* Encodage compact des preuves (base64url)
* Export side‑car de preuves (`.tcap.proof.json`)
* Mode « déterministe total » (seed + config → reproductible)
* Option SHA‑512/BLAKE3 (avec drapeau d’algo dans le manifeste)

Contributions bienvenues (voir **CLA**).

---

## 💼 Licence commerciale & Marque

Ce dépôt est proposé en **double licence** :

* **DECL‑C v3.1** — usage communautaire **non commercial**
* **DECL‑X v3.1** — **commercial/SaaS/OEM/Entreprise**, avec mises à jour, options SLA et guides de marque

**Toute utilisation commerciale** (produit payant, SaaS, OEM, cloud/edge, consulting facturé, monétisation directe ou indirecte) **requiert** DECL‑X.

👉 Contact : \[email\@domaine] · [https://ton‑site.exemple/licensing](https://ton-site.exemple/licensing)

Ajoutez dans vos fichiers source :

```python
# SPDX-License-Identifier: DECL-C-3.1 OR DECL-X-3.1
# Copyright (c) 2025 [Ton Entité]
```

---

## 🤝 Contribuer

En contribuant, vous acceptez la **DECL‑CLA v1.1** (voir `DECL-CLA.md`).

Workflow : fork → branche → PR ; conservez **standard‑library‑only** ;
ajoutez des exemples si vous touchez à la calibration, Merkle ou I/O.

---

## 🙌 Remerciements

Fait avec ❤️ et uniquement la **bibliothèque standard Python**.
