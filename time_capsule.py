#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
time_capsule.py — Pile de Temps Cristallisé (charge & vérif)
-------------------------------------------------------------
Concept : encapsuler du "temps CPU" sous forme d'une chaîne SHA-256 irréversible.
- make     : fabrique une capsule .tcap
  * total d'itérations fixé (--iterations), OU calibré sur une durée cible (--seconds)
  * checkpoints réguliers (par défaut ~2048 points), Merkle root, manifest signé (hash)
- verify   : vérifie la capsule (intégrité + échantillons de segments recalculés)
- inspect  : affiche le manifeste
- prove    : génère une preuve Merkle pour un checkpoint donné
- check    : vérifie une preuve Merkle (indépendamment de la capsule)

Format fichier .tcap :
  MAGIC 'TMC1' | uint64_be(manifest_len) | manifest_json_utf8
Le manifest contient tout : seed, itérations, indices & hashs des checkpoints, Merkle root, etc.

Dépendances : Python 3.8+ (standard library only)
Avertissement : ceci n'est PAS une VDF audité cryptographiquement. C'est une chaîne SHA-256 simple
destinée à matérialiser du temps CPU et fournir des preuves pratiques (Merkle + segments).
"""

import argparse, os, sys, json, time, uuid, hashlib, math, random
from datetime import datetime, timezone
from typing import List, Tuple, Dict, Any, Optional

UTC = timezone.utc
MAGIC = b"TMC1"

# --------------------------- Utils ---------------------------

def ensure_dir(path: str):
    if path:
        os.makedirs(path, exist_ok=True)

def now_iso() -> str:
    return datetime.now(UTC).isoformat()

def sha256_bytes(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def be64(n: int) -> bytes:
    return int(n).to_bytes(8, "big", signed=False)

def read_be64(b: bytes) -> int:
    return int.from_bytes(b, "big", signed=False)

def human_int(n: int) -> str:
    # 1234567 -> 1.23M
    units = ["","K","M","G","T","P"]
    x = float(n)
    i = 0
    while x >= 1000 and i < len(units)-1:
        x /= 1000.0; i += 1
    return f"{x:.2f}{units[i]}"

# ---------------------- Merkle helpers -----------------------

def merkle_leaf(seed_or_hash_bytes: bytes, index: int, leaf_type: str) -> bytes:
    """
    Construit un "feuille" canonique : H( b'LEAF' || type || be64(index) || value )
    - type: 'S' pour seed, 'C' pour checkpoint, 'F' pour final
    """
    t = b'S' if leaf_type == 'S' else (b'F' if leaf_type == 'F' else b'C')
    return sha256_bytes(b'LEAF' + t + be64(index) + seed_or_hash_bytes)

def merkle_root_from_leaves(leaves: List[bytes]) -> str:
    if not leaves:
        return sha256_hex(b"")
    level = leaves[:]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            L = level[i]
            R = level[i+1] if i+1 < len(level) else level[i]
            nxt.append(sha256_bytes(L + R))
        level = nxt
    return level[0].hex()

def merkle_proof(leaves: List[bytes], idx: int) -> List[Tuple[str, str]]:
    """
    Retourne une liste [(pos, hash_hex), ...] pour prouver le leaf d'index idx :
    pos in {'L','R'} indique si le sibling est à gauche ou à droite.
    """
    if idx < 0 or idx >= len(leaves):
        raise IndexError("index feuille hors limites")
    proof = []
    level = leaves[:]
    pos = idx
    while len(level) > 1:
        if pos % 2 == 0:
            # paire : sibling = pos+1 (ou duplication si absent)
            sib = pos+1 if pos+1 < len(level) else pos
            sibling_hash = level[sib].hex()
            proof.append(('R', sibling_hash))
        else:
            sib = pos-1
            sibling_hash = level[sib].hex()
            proof.append(('L', sibling_hash))
        # compacter niveau
        nxt = []
        for i in range(0, len(level), 2):
            L = level[i]
            R = level[i+1] if i+1 < len(level) else level[i]
            nxt.append(sha256_bytes(L + R))
        level = nxt
        pos //= 2
    return proof

def merkle_verify(leaf_hash_hex: str, idx: int, proof: List[Tuple[str, str]], root_hex: str) -> bool:
    h = bytes.fromhex(leaf_hash_hex)
    pos = idx
    for (side, sib_hex) in proof:
        sib = bytes.fromhex(sib_hex)
        if side == 'R':
            h = sha256_bytes(h + sib)
        elif side == 'L':
            h = sha256_bytes(sib + h)
        else:
            return False
        pos //= 2
    return h.hex() == root_hex

# ------------------ Calibration & chain ----------------------

def calibrate_iterations(seconds: float = 0.5) -> float:
    """Mesure approximative d'itérations SHA-256/s sur cette machine."""
    if seconds <= 0: seconds = 0.25
    h = os.urandom(32)
    cnt = 0
    t0 = time.perf_counter()
    while True:
        h = sha256_bytes(h)
        cnt += 1
        if cnt % 2000 == 0 and (time.perf_counter() - t0) >= seconds:
            break
    elapsed = time.perf_counter() - t0
    rate = cnt / max(1e-9, elapsed)
    return rate

def make_checkpoints(total_iters: int, target_points: int = 2048) -> int:
    """Choisit un intervalle de checkpoint pour obtenir ~target_points (min 1)."""
    if total_iters <= 0: return 1
    step = max(1, total_iters // max(1, target_points))
    return step

# ------------------------ Capsule I/O ------------------------

def write_capsule(path: str, manifest: Dict[str, Any]):
    ensure_dir(os.path.dirname(path) or ".")
    blob = json.dumps(manifest, ensure_ascii=False, separators=(",",":")).encode("utf-8")
    with open(path + ".tmp", "wb") as f:
        f.write(MAGIC)
        f.write(be64(len(blob)))
        f.write(blob)
    os.replace(path + ".tmp", path)

def read_capsule(path: str) -> Dict[str, Any]:
    with open(path, "rb") as f:
        magic = f.read(4)
        if magic != MAGIC:
            raise ValueError("Magic invalide (pas une capsule TMC1)")
        mlen = read_be64(f.read(8))
        mjson = f.read(mlen)
    manifest = json.loads(mjson.decode("utf-8"))
    return manifest

# ----------------------- Construction ------------------------

def build_time_capsule(out_path: str,
                       iterations: Optional[int],
                       seconds: Optional[float],
                       target_points: int,
                       checkpoint_every: Optional[int],
                       note: str,
                       seed_hex: Optional[str],
                       calibrate_s: float) -> Dict[str, Any]:
    """
    Construit la capsule en calculant une chaîne SHA-256 de longueur 'iterations'.
    Si 'seconds' est précisé et 'iterations' None, on calibre d'abord.
    """
    # Déterminer N
    if (iterations is None) == (seconds is None):
        raise SystemExit("Spécifie soit --iterations, soit --seconds (mais pas les deux).")
    if iterations is None:
        rate = calibrate_iterations(calibrate_s)
        est = int(max(1, seconds * rate))
        print(f"⏱️  Calibration ~{rate:,.0f} it/s → objectif N ≈ {est:,} itérations pour ~{seconds} s")
        iterations = est
    N = int(iterations)

    # Préparer seed
    if seed_hex:
        try:
            seed = bytes.fromhex(seed_hex)
        except Exception as e:
            raise SystemExit(f"--seed-hex invalide: {e}")
        if len(seed) == 0:
            raise SystemExit("--seed-hex vide")
    else:
        seed = os.urandom(32)

    # Choisir checkpoint_every
    if checkpoint_every is None or checkpoint_every <= 0:
        checkpoint_every = make_checkpoints(N, target_points)
    step = int(max(1, checkpoint_every))
    print(f"🧱 Checkpoints tous les {step} itérations (~{max(1,N//step)} points)")

    # Boucle de charge
    capsule_id = uuid.uuid4().hex[:12]
    created_at = now_iso()
    algo = "sha256_chain"
    checkpoints_idx: List[int] = []
    checkpoints_hash: List[str] = []

    h = seed
    t0 = time.perf_counter()
    next_report = t0 + 1.0
    for i in range(1, N+1):
        h = sha256_bytes(h)
        if (i % step == 0) or (i == N):
            checkpoints_idx.append(i)
            checkpoints_hash.append(h.hex())
        if time.perf_counter() >= next_report:
            done_ratio = i / N
            eta = (time.perf_counter() - t0) * (1.0 - done_ratio) / max(1e-9, done_ratio)
            sys.stdout.write(f"\r… {human_int(i)} / {human_int(N)} iters ({done_ratio*100:.1f}%) | ETA ~{int(eta)}s")
            sys.stdout.flush()
            next_report += 1.0
    sys.stdout.write("\n")
    elapsed = time.perf_counter() - t0
    rate = N / max(1e-9, elapsed)

    # Merkle root (seed + checkpoints + final)
    leaves: List[bytes] = []
    leaves.append(merkle_leaf(seed, 0, 'S'))
    for idx, hx in zip(checkpoints_idx, checkpoints_hash):
        leaves.append(merkle_leaf(bytes.fromhex(hx), idx, 'C'))
    # Final = dernier hash (doit être égal au dernier checkpoint si N multiple de step)
    final_hex = h.hex()
    leaves.append(merkle_leaf(bytes.fromhex(final_hex), N, 'F'))
    root_hex = merkle_root_from_leaves(leaves)

    manifest: Dict[str, Any] = {
        "version": "1.0",
        "capsule_id": capsule_id,
        "created_at": created_at,
        "note": note,
        "algo": algo,
        "seed_hex": seed.hex(),
        "iterations": N,
        "checkpoint_every": step,
        "checkpoint_count": len(checkpoints_idx),
        "checkpoints_index": checkpoints_idx,
        "checkpoints_hash": checkpoints_hash,
        "final_hash": final_hex,
        "merkle_root": root_hex,
        "perf": {
            "elapsed_seconds": elapsed,
            "rate_iter_per_sec": rate
        },
        "system": {
            "python": sys.version.split()[0],
            "platform": os.name
        },
        "integrity": {
            "manifest_sha256": None  # rempli après
        }
    }
    manifest["integrity"]["manifest_sha256"] = sha256_hex(json.dumps(
        {k: manifest[k] for k in manifest if k != "integrity"},
        ensure_ascii=False, separators=(",",":")
    ).encode("utf-8"))

    write_capsule(out_path, manifest)
    print("✅ Capsule créée")
    print(f"   Fichier       : {out_path}")
    print(f"   Itérations    : {N:,}")
    print(f"   Checkpoints   : {len(checkpoints_idx)} (tous {step})")
    print(f"   Final hash    : {final_hex[:16]}…")
    print(f"   Merkle root   : {root_hex[:16]}…")
    print(f"   Débit moyen   : {rate:,.0f} it/s | Temps ~{elapsed:.1f}s")
    return manifest

# ----------------------- Vérification ------------------------

def verify_capsule(path: str, samples: int = 5, rng_seed: Optional[int] = None) -> bool:
    """
    Vérifie :
      - intégrité du manifest (empreinte)
      - cohérence Merkle (recalcul complète à partir des feuilles manifest)
      - échantillons de segments (recalcul local entre checkpoints)
    """
    manifest = read_capsule(path)
    # Intégrité basique (hash du manifest sans le champ integrity)
    m_no_integrity = {k: manifest[k] for k in manifest if k != "integrity"}
    calc = sha256_hex(json.dumps(m_no_integrity, ensure_ascii=False, separators=(",",":")).encode("utf-8"))
    ok_int = (calc == manifest.get("integrity",{}).get("manifest_sha256"))
    print(f"🔐 Manifest hash : {'OK' if ok_int else 'FAIL'}")

    seed = bytes.fromhex(manifest["seed_hex"])
    idxs = manifest["checkpoints_index"]
    hx = manifest["checkpoints_hash"]
    N = int(manifest["iterations"])
    step = int(manifest["checkpoint_every"])
    final_hex = manifest["final_hash"]
    # Re-merkle
    leaves = [merkle_leaf(seed, 0, 'S')]
    for i, h in zip(idxs, hx):
        leaves.append(merkle_leaf(bytes.fromhex(h), i, 'C'))
    leaves.append(merkle_leaf(bytes.fromhex(final_hex), N, 'F'))
    root = merkle_root_from_leaves(leaves)
    ok_root = (root == manifest["merkle_root"])
    print(f"🌳 Merkle root   : {'OK' if ok_root else 'FAIL'}")

    # Vérification par échantillons de segments
    if rng_seed is None:
        rng_seed = int(time.time()) ^ N
    rng = random.Random(rng_seed)
    # positions : choisir des indices de checkpoints à revalider (pas le tout premier)
    total_points = len(idxs)
    if total_points == 0:
        # pas de checkpoint (cas step>=N) -> on valide uniquement final depuis seed
        print("⚠️  Zéro checkpoint enregistré : recalcul complet du N (peut être long).")
        start_hash = seed
        seg_len = N
        h = start_hash
        for _ in range(seg_len):
            h = sha256_bytes(h)
        ok_seg = (h.hex() == final_hex)
        print(f"🧪 Segment unique 0→{N} : {'OK' if ok_seg else 'FAIL'}")
        return ok_int and ok_root and ok_seg

    samples = max(1, min(samples, total_points))  # pas plus que le nb de checkpoints
    chosen = sorted(rng.sample(range(total_points), samples))
    print(f"🧪 Segments à tester : {samples} / {total_points} checkpoints")
    all_ok = True
    # On va recalculer du dernier point validé vers le point choisi (au plus 'step' itérations)
    # Pour chaque checkpoint choisi k :
    #   prev_i = 0 (seed) si k==0, sinon idxs[k-1]
    #   prev_h = seed si k==0, sinon hx[k-1]
    #   need = idxs[k] - prev_i  (<= step, sauf si k==0 -> = step)
    for k in chosen:
        prev_i = 0 if k == 0 else idxs[k-1]
        prev_h = seed if k == 0 else bytes.fromhex(hx[k-1])
        target_i = idxs[k]
        target_hx = hx[k]
        need = target_i - prev_i
        h = prev_h
        for _ in range(need):
            h = sha256_bytes(h)
        ok_seg = (h.hex() == target_hx)
        print(f"   - {prev_i:>12} → {target_i:>12}  (len {need:>8}) : {'OK' if ok_seg else 'FAIL'}")
        all_ok = all_ok and ok_seg

    # Vérifie aussi le "reste" depuis le dernier checkpoint jusqu'à N (si pas aligné)
    if idxs and idxs[-1] != N:
        prev_i = idxs[-1]
        prev_h = bytes.fromhex(hx[-1])
        need = N - prev_i
        h = prev_h
        for _ in range(need):
            h = sha256_bytes(h)
        ok_tail = (h.hex() == final_hex)
        print(f"   - {prev_i:>12} → {N:>12}  (reste {need:>6}) : {'OK' if ok_tail else 'FAIL'}")
        all_ok = all_ok and ok_tail
    else:
        # si dernier checkpoint == N, juste vérifier cohérence avec final
        if hx and hx[-1] != final_hex:
            print("   - Dernier checkpoint != final_hash : FAIL")
            all_ok = False

    overall = ok_int and ok_root and all_ok
    print(f"✅ Vérification globale : {'OK' if overall else 'FAIL'}")
    return overall

# -------------------- Inspect / Proofs -----------------------

def inspect_capsule(path: str):
    m = read_capsule(path)
    print(json.dumps(m, ensure_ascii=False, indent=2))

def prove_checkpoint(path: str, which: str):
    """
    Génère une preuve Merkle pour :
      - 'seed'            → feuille 0 (seed)
      - 'final'           → dernière feuille (final)
      - 'ckpt:<INDEX>'    → checkpoint à l'index k (0-based dans la liste)
    Imprime un JSON avec leaf_hash_hex, index_leaf, proof ([(pos,hash),...]), root.
    """
    m = read_capsule(path)
    seed = bytes.fromhex(m["seed_hex"])
    idxs = m["checkpoints_index"]
    hx = m["checkpoints_hash"]
    N = int(m["iterations"])
    final_hex = m["final_hash"]

    leaves: List[bytes] = [merkle_leaf(seed, 0, 'S')]
    for i, h in zip(idxs, hx):
        leaves.append(merkle_leaf(bytes.fromhex(h), i, 'C'))
    leaves.append(merkle_leaf(bytes.fromhex(final_hex), N, 'F'))

    if which == "seed":
        idx = 0
        leaf_hex = leaves[0].hex()
    elif which == "final":
        idx = len(leaves) - 1
        leaf_hex = leaves[idx].hex()
    elif which.startswith("ckpt:"):
        k = int(which.split(":",1)[1])
        if k < 0 or k >= len(idxs):
            raise SystemExit("Index de checkpoint invalide")
        idx = 1 + k  # seed=0, ckpts démarrent à 1
        leaf_hex = leaves[idx].hex()
    else:
        raise SystemExit("Argument 'which' invalide (seed|final|ckpt:<index>)")

    proof = merkle_proof(leaves, idx)
    out = {
        "capsule_id": m["capsule_id"],
        "which": which,
        "leaf_index": idx,
        "leaf_hash_hex": leaf_hex,
        "merkle_root": m["merkle_root"],
        "proof": proof
    }
    print(json.dumps(out, ensure_ascii=False, indent=2))

def check_proof(root_hex: str, leaf_hash_hex: str, index: int, proof: List[Tuple[str,str]]) -> bool:
    ok = merkle_verify(leaf_hash_hex, index, proof, root_hex)
    print(f"🔎 Vérif preuve : {'OK' if ok else 'FAIL'}")
    return ok

# ----------------------------- CLI ---------------------------

def build_parser():
    p = argparse.ArgumentParser(description="Pile de Temps Cristallisé (.tcap) — charge & vérification")
    sub = p.add_subparsers(dest="cmd", required=True)

    pm = sub.add_parser("make", help="Fabriquer une capsule .tcap (charge)")
    g = pm.add_mutually_exclusive_group(required=True)
    g.add_argument("--iterations", type=int, help="Nombre total d'itérations SHA-256")
    g.add_argument("--seconds", type=float, help="Durée cible (calibrée) en secondes")
    pm.add_argument("--target-points", type=int, default=2048, help="Nb visé de checkpoints (~2048 par défaut)")
    pm.add_argument("--checkpoint-every", type=int, help="Pas de checkpoint (si défini, écrase target-points)")
    pm.add_argument("--seed-hex", type=str, help="Seed initiale en hex (32+ octets recommandé). Par défaut: os.urandom(32)")
    pm.add_argument("--note", type=str, default="", help="Note libre dans le manifeste")
    pm.add_argument("--calibrate-seconds", type=float, default=0.5, help="Durée calibration (si --seconds)")
    pm.add_argument("--out", required=True, help="Chemin de sortie .tcap")
    pm.set_defaults(func=lambda a: build_time_capsule(
        out_path=a.out,
        iterations=a.iterations,
        seconds=a.seconds,
        target_points=a.target_points,
        checkpoint_every=a.checkpoint_every,
        note=a.note,
        seed_hex=a.seed_hex,
        calibrate_s=a.calibrate_seconds
    ))

    pv = sub.add_parser("verify", help="Vérifier la capsule (manifest, Merkle, segments)")
    pv.add_argument("--caps", required=True, help="Fichier .tcap")
    pv.add_argument("--samples", type=int, default=5, help="Nb de segments aléatoires à recalculer (≤ nb checkpoints)")
    pv.add_argument("--seed", type=int, help="Seed pour l'échantillonnage (défaut aléatoire)")
    def _v(a):
        ok = verify_capsule(a.caps, samples=a.samples, rng_seed=a.seed)
        if not ok: sys.exit(2)
    pv.set_defaults(func=_v)

    pi = sub.add_parser("inspect", help="Afficher le manifeste (JSON)")
    pi.add_argument("--caps", required=True)
    pi.set_defaults(func=lambda a: inspect_capsule(a.caps))

    pp = sub.add_parser("prove", help="Générer une preuve Merkle (seed|final|ckpt:<index>)")
    pp.add_argument("--caps", required=True)
    pp.add_argument("--which", required=True)
    pp.set_defaults(func=lambda a: prove_checkpoint(a.caps, a.which))

    pc = sub.add_parser("check", help="Vérifier une preuve Merkle (indépendant)")
    pc.add_argument("--root", required=True, help="Merkle root hex")
    pc.add_argument("--leaf", required=True, help="Leaf hash hex (déjà H(LEAF||...))")
    pc.add_argument("--index", type=int, required=True, help="Index de la feuille")
    pc.add_argument("--proof", required=True, help="Preuve JSON: [[\"L\"|\"R\", \"hex\"], ...]")
    def _c(a):
        proof = json.loads(a.proof)
        ok = check_proof(a.root, a.leaf, a.index, proof)
        if not ok: sys.exit(3)
    pc.set_defaults(func=_c)

    return p

def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
