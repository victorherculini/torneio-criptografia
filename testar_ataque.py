#!/usr/bin/env python3
"""Bateria de testes do ataque do simples.py.

Uso:
  python3 testar_ataque.py [TEXTOS_POR_COMBINACAO]

Testa, com textos diferentes em cada tentativa:
  - todas as cifras e combinacoes validas nas fases 1 a 4;
  - chaves XOR com bytes baixos/zero (as mais dificeis para a busca);
  - as rodadas atuais em desafios/ (se a pasta existir);
  - os exemplos em ingles do professor.

O tempo padrao e de 1 a 2 minutos. Use 1 no argumento para rodar mais rapido
ou 5 para uma bateria mais completa.
"""

from __future__ import annotations

import json
import random
import re
import statistics
import sys
import time
import unicodedata
from pathlib import Path

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE))

import simples as S  # noqa: E402

CORPUS = unicodedata.normalize(
    "NFKD", (BASE / "portugues.txt").read_text("utf-8", "ignore")
)
CORPUS = re.sub(r"[^a-z]", "", CORPUS.encode("ascii", "ignore").decode()).encode()

falhas: list[tuple[str, str]] = []
tempos: list[float] = []


def texto_aleatorio(rng: random.Random, n: int | None = None) -> bytes:
    n = n or rng.randint(200, 250)
    i = rng.randrange(0, len(CORPUS) - n)
    return CORPUS[i:i + n]


def chave_xor(rng: random.Random, n: int, zeros: bool = False) -> bytes:
    if not zeros:
        return bytes(rng.randrange(1, 256) for _ in range(n))
    return bytes(0 if rng.random() < 0.6 else rng.randrange(1, 256)
                 for _ in range(n))


def chave_vigenere(rng: random.Random, n: int) -> bytes:
    return bytes(rng.randrange(97, 123) for _ in range(n))


def combos() -> list[tuple[int, list[tuple[str, object]]]]:
    """Todas as combinacoes validas, com chaves so para saber o tamanho."""
    out = []
    for fase in (1, 2, 3, 4):
        orc = S.ORCAMENTO[fase]
        simples = [("atbash", None), ("cesar", 7)]
        simples += [("vigenere", b"a" * m)
                    for m in range(1, min(8, int(orc // 4.7)) + 1)]
        simples += [("xor", b"\x01" * n)
                    for n in range(1, min(5, orc // 8) + 1)]
        if fase == 1:
            simples += [("xor2", k) for k in range(4)]
        for c in simples:
            if S.custo([c]) <= orc:
                out.append((fase, [c]))
        if fase >= 3:
            bases = [("atbash", None), ("cesar", 7)]
            bases += [("vigenere", b"a" * m) for m in range(1, 9)]
            xs = [("xor", b"\x01" * n) for n in range(1, 6)]
            pares = [[a, x] for a in bases for x in xs]
            pares += [[a, b] for a in bases for b in bases if a[0] != b[0]]
            for p in pares:
                if len({n for n, _ in p}) == len(p) and S.custo(p) <= orc:
                    out.append((fase, p))
    return out


def chaves_reais(rng: random.Random, modelo, zeros: bool = False):
    ps = []
    for nome, ref in modelo:
        if nome == "atbash":
            k = None
        elif nome == "cesar":
            k = rng.randrange(1, 26)
        elif nome == "vigenere":
            k = chave_vigenere(rng, len(ref))
        elif nome == "xor":
            k = chave_xor(rng, len(ref), zeros)
        else:
            k = rng.randrange(4)
        ps.append((nome, k))
    return ps


def avaliar(grupo: str, nome: str, fase: int, cif: bytes, claro: bytes) -> bool:
    ini = time.time()
    try:
        res = S.atacar(cif, fase, 10)
    except Exception as e:  # noqa: BLE001
        falhas.append((grupo, f"{nome}: excecao {e!r}"))
        return False
    dt = time.time() - ini
    tempos.append(dt)
    rank = next((i for i, (_, p, _) in enumerate(res, 1)
                 if p.rstrip(b"\r\n") == claro.rstrip(b"\r\n")), None)
    if rank != 1:
        falhas.append((grupo, f"{nome}: rank {rank} em {dt:.2f}s"))
        return False
    return True


def testar(grupo: str, nome: str, fase: int, claro: bytes, ps) -> bool:
    cif = S.aplicar(claro, ps)
    if avaliar(grupo, nome, fase, cif, claro):
        return True
    detalhe = " -> ".join(
        f"{n}({k.hex() if isinstance(k, bytes) else k})" for n, k in ps
    )
    falhas[-1] = (grupo, falhas[-1][1] + f" | {detalhe}")
    return False


def grupo_sintetico(textos: int) -> tuple[int, int]:
    rng = random.Random(2024)
    cs = combos()
    ok = total = 0
    for fase, modelo in cs:
        for _ in range(textos):
            total += 1
            ps = chaves_reais(rng, modelo)
            ok += testar("sintetico", f"fase {fase}", fase, texto_aleatorio(rng), ps)
    return ok, total


def grupo_chaves_baixas(repeticoes: int) -> tuple[int, int]:
    rng = random.Random(99)
    modelos = [
        (4, [("xor", b"\x01" * 5)]),
        (4, [("cesar", 3), ("xor", b"\x01" * 4)]),
        (4, [("atbash", None), ("xor", b"\x01" * 5)]),
        (4, [("vigenere", b"aaa"), ("xor", b"\x01" * 2)]),
    ]
    ok = total = 0
    for _ in range(repeticoes):
        for fase, modelo in modelos:
            total += 1
            ps = chaves_reais(rng, modelo, zeros=True)
            ok += testar("chaves baixas", f"fase {fase}", fase,
                         texto_aleatorio(rng), ps)
    return ok, total


def grupo_rodadas() -> tuple[int, int]:
    pastas = sorted((BASE / "desafios").glob("rodada_*"))
    ok = total = 0
    for pasta in pastas:
        meta = pasta / "metadata.json"
        if not meta.exists():
            continue
        dados = json.loads(meta.read_text("utf-8"))
        claro = dados["texto_claro"].encode()
        cif = S.ler_cifrado(pasta / dados.get("texto_cifrado_arquivo",
                                               "texto_cifrado.txt"))
        total += 1
        ok += avaliar("rodadas", pasta.name, dados["fase"], cif, claro)
    return ok, total


def grupo_professor() -> tuple[int, int]:
    esperado = S.ler_claro(BASE / "data.txt")
    arquivos = ["atbash_criptografado.txt", "caesar_criptografado.txt",
                "crypt_vigenere.txt", "xor_criptografado.txt"]
    ok = total = 0
    for nome in arquivos:
        caminho = BASE / nome
        if not caminho.exists():
            continue
        total += 1
        cif = S.ler_cifrado(caminho)
        ini = time.time()
        res = S.atacar(cif, 1, 10)
        tempos.append(time.time() - ini)
        achou = any(p.rstrip(b"\r\n") == esperado.rstrip(b"\r\n")
                    for _, p, _ in res)
        if not achou:
            falhas.append(("professor", nome))
        ok += achou
    return ok, total


def main() -> int:
    textos = int(sys.argv[1]) if len(sys.argv) > 1 else 2
    inicio = time.time()
    grupos = [
        ("sintetico", lambda: grupo_sintetico(textos)),
        ("chaves baixas", lambda: grupo_chaves_baixas(4)),
        ("rodadas", grupo_rodadas),
        ("professor", grupo_professor),
    ]
    for nome, funcao in grupos:
        ok, total = funcao()
        print(f"{nome:14s} {ok:3d}/{total:3d}"
              + ("  OK" if ok == total else "  FALHAS"))
    print(f"\ntempo total {time.time() - inicio:.1f}s"
          + (f" | medio {statistics.mean(tempos):.2f}s"
             if tempos else ""))
    if falhas:
        print("\nFalhas:")
        for grupo, detalhe in falhas:
            print(f"  [{grupo}] {detalhe}")
        return 1
    print("Tudo passou.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
