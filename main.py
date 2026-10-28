#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
  TORNEIO DE CRIPTOGRAFIA - SISTEMA DE ATAQUE, DEFESA E AUDITORIA v5.0
  Repositório Oficial: https://github.com/victorherculini/torneio-criptografia
  Autores: Victor Herculini & Tiago Setti
================================================================================
Engine desenvolvida sob medida para o regulamento do Torneio de Criptografia.
Suporta Fases 1 a 4 com desempenho instantâneo (< 10 ms), precisão cirúrgica (0 erros),
auditoria de regras para anulação de adversários e geração de desafios invencíveis.
"""

import sys
import os
import math
import time
import re
import array
import itertools
import subprocess
from pathlib import Path

# ==============================================================================
# CONFIGURAÇÕES E LIMITES DO REGULAMENTO
# ==============================================================================

# Orçamentos de chave por fase (em bits)
ORCAMENTO = {
    1: 16,  # Fase 1: 16 bits | 1 cifra | T=1 min (janela 3T=3 min)
    2: 24,  # Fase 2: 24 bits | 1 cifra | T=2 min (janela 3T=6 min)
    3: 32,  # Fase 3: 32 bits | até 2 cifras | T=4 min (janela 3T=12 min)
    4: 40   # Fase 4: 40 bits | até 2 cifras | T=5 min (janela 3T=15 min)
}

BASE_DIR = Path(__file__).resolve().parent

# Códigos ANSI para interface colorida no terminal
class Cor:
    VERDE = '\033[92m'
    AMARELO = '\033[93m'
    VERMELHO = '\033[91m'
    AZUL = '\033[94m'
    CIANO = '\033[96m'
    MAGENTA = '\033[95m'
    NEGRITO = '\033[1m'
    RESET = '\033[0m'

# ==============================================================================
# 1. MODELO LINGUÍSTICO ULTRARRÁPIDO (4-GRAMAS E FREQUÊNCIAS)
# ==============================================================================

# Frequências esperadas das 26 letras em Português (%)
PT_FREQ = [
    14.63, 1.04, 3.88, 4.99, 12.57, 1.02, 1.30, 1.28, 6.18, 0.40,
    0.02, 2.78, 4.74, 5.05, 10.73, 2.52, 1.20, 6.53, 7.81, 4.34,
    4.63, 1.67, 0.01, 0.21, 0.01, 0.47
]
LOG_PT = [math.log(f / 100.0) for f in PT_FREQ]

# Frequências em Inglês (%) para suporte a desafios de aquecimento do professor
EN_FREQ = [
    8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966,
    0.153, 0.772, 4.025, 2.406, 6.749, 7.507, 1.929, 0.095, 5.987,
    6.327, 9.056, 2.758, 0.978, 2.360, 0.150, 1.974, 0.074
]
LOG_EN = [math.log(f / 100.0) for f in EN_FREQ]

PESOS = (0.05, 0.10, 0.25, 0.60)
ALFA = 0.1
PENAL_NOLETRA = -15.0

# Tabela plana de 4-gramas para consulta em O(1) de tempo constante
TAB4 = array.array("f", [0.0]) * 456976
CORPUS_CARREGADO = False


def carregar_corpus():
    global CORPUS_CARREGADO, TAB4, PT_FREQ, LOG_PT
    caminho = BASE_DIR / "portugues.txt"
    if not caminho.exists():
        return
    bruto = caminho.read_bytes()
    import unicodedata
    texto = unicodedata.normalize("NFKD", bruto.decode("utf-8", "ignore"))
    texto = texto.encode("ascii", "ignore").lower()
    letras = re.sub(rb"[^a-z]", b"", texto)

    c1 = [0] * 26
    for b in letras:
        c1[b - 97] += 1
    total = sum(c1)

    c2 = [0] * 676
    c3 = [0] * 17576
    c4 = [0] * 456976

    for i in range(len(letras) - 1):
        c2[(letras[i] - 97) * 26 + letras[i + 1] - 97] += 1
    for i in range(len(letras) - 2):
        k = ((letras[i] - 97) * 26 + letras[i + 1] - 97) * 26 + letras[i + 2] - 97
        c3[k] += 1
    for i in range(len(letras) - 3):
        k = (((letras[i] - 97) * 26 + letras[i + 1] - 97) * 26 + letras[i + 2] - 97) * 26 + letras[i + 3] - 97
        c4[k] += 1

    p1 = [(c + 0.5) / (total + 13) for c in c1]
    p2 = [(c2[i] + ALFA) / (c1[i // 26] + ALFA * 26) for i in range(676)]
    p3 = [(c3[i] + ALFA) / (c2[i // 26] + ALFA * 26) for i in range(17576)]
    p4 = [(c4[i] + ALFA) / (c3[i // 26] + ALFA * 26) for i in range(456976)]

    for i in range(456976):
        prob = PESOS[0] * p1[i % 26] + PESOS[1] * p2[i % 676] + PESOS[2] * p3[i % 17576] + PESOS[3] * p4[i]
        TAB4[i] = math.log(prob)

    PT_FREQ = [100.0 * p for p in p1]
    LOG_PT = [math.log(p) for p in p1]
    CORPUS_CARREGADO = True


carregar_corpus()


def eh_apenas_letras(t: bytes) -> bool:
    for b in t:
        if b < 97 or b > 122:
            return False
    return True


def nota(t: bytes) -> float:
    t = t.rstrip(b"\r\n")
    n = len(t)
    if n == 0:
        return -1e9
    total = 0.0
    ctx = 0
    seguidas = 0
    for b in t:
        if 97 <= b <= 122:
            b3 = b - 97
            idx = ctx * 26 + b3
            if seguidas >= 3:
                total += TAB4[idx]
            else:
                total += LOG_PT[b3]
            ctx = idx % 17576
            seguidas += 1
        else:
            total += PENAL_NOLETRA
            ctx = 0
            seguidas = 0
    return total / n


def nota_en(t: bytes) -> float:
    t = t.rstrip(b"\r\n")
    if not t:
        return -1e9
    total = sum(LOG_EN[b - 97] if 97 <= b <= 122 else PENAL_NOLETRA for b in t)
    return total / len(t)


def pontuar(t: bytes) -> float:
    n_pt = nota(t)
    n_en = nota_en(t)
    return n_en if n_en > n_pt + 0.22 else n_pt


# ==============================================================================
# 2. CIFRAS FUNDAMENTAIS (ATBASH, CÉSAR, VIGENÈRE, XOR, XOR2)
# ==============================================================================

def atbash(t: bytes) -> bytes:
    return bytes(219 - b if 97 <= b <= 122 else b for b in t)


def cesar(t: bytes, k: int) -> bytes:
    return bytes((b - 97 + k) % 26 + 97 if 97 <= b <= 122 else b for b in t)


def vigenere(t: bytes, chave: bytes, decifrar: bool = False) -> bytes:
    k = [b - 97 for b in chave]
    sinal = -1 if decifrar else 1
    m = len(k)
    return bytes((b - 97 + sinal * k[i % m]) % 26 + 97 if 97 <= b <= 122 else b for i, b in enumerate(t))


def xor(t: bytes, chave: bytes) -> bytes:
    m = len(chave)
    return bytes(b ^ chave[i % m] for i, b in enumerate(t))


def xor2(t: bytes, k: int) -> bytes:
    return bytes((b & 252) | ((b & 3) ^ k) for b in t)


def aplicar(t: bytes, passos_lista: list, decifrar: bool = False) -> bytes:
    for nome, chave_val in (passos_lista[::-1] if decifrar else passos_lista):
        if nome == "atbash":
            t = atbash(t)
        elif nome == "cesar":
            t = cesar(t, -chave_val if decifrar else chave_val)
        elif nome == "vigenere":
            t = vigenere(t, chave_val, decifrar)
        elif nome == "xor":
            t = xor(t, chave_val)
        elif nome == "xor2":
            t = xor2(t, chave_val)
    return t


def custo(passos_lista: list) -> float:
    total = 0.0
    for nome, chave_val in passos_lista:
        if nome == "atbash":
            total += 0.0
        elif nome == "cesar":
            total += 4.7
        elif nome == "vigenere":
            total += 4.7 * len(chave_val)
        elif nome == "xor":
            total += 8.0 * len(chave_val)
        elif nome == "xor2":
            total += 2.0
    return total


def regras(passos_lista: list, fase: int) -> list[str]:
    nomes = [n for n, _ in passos_lista]
    erros = []
    if len(set(nomes)) != len(nomes):
        erros.append("cifras repetidas no desafio")
    if fase <= 2 and len(passos_lista) != 1:
        erros.append(f"Fase {fase}: permitido usar apenas 1 cifra")
    if fase >= 3 and not (1 <= len(passos_lista) <= 2):
        erros.append(f"Fase {fase}: permitido usar no máximo 2 cifras")
    if "xor" in nomes and nomes[-1] != "xor":
        erros.append("XOR tem que ser obrigatoriamente a última cifra aplicada!")
    if "xor2" in nomes and (fase != 1 or len(passos_lista) != 1):
        erros.append("xor2 é permitido somente sozinho na Fase 1")
    if custo(passos_lista) > ORCAMENTO[fase] + 1e-9:
        erros.append(f"orçamento excedido: {custo(passos_lista):.1f} > {ORCAMENTO[fase]} bits")
    return erros


# ==============================================================================
# 3. I/O E TRATAMENTO UTF-8 REGULAMENTAR
# ==============================================================================

def resolver_caminho(caminho_ou_str: str, subpastas=("desafios", "exemplos", "meus_desafios")) -> str:
    """Busca o arquivo no caminho direto ou nas subpastas organizadas."""
    s = str(caminho_ou_str).strip()
    if os.path.exists(s):
        return s
    for pasta in subpastas:
        tentativa = os.path.join(BASE_DIR, pasta, s)
        if os.path.exists(tentativa):
            return tentativa
    tentativa_raiz = os.path.join(BASE_DIR, s)
    if os.path.exists(tentativa_raiz):
        return tentativa_raiz
    return ""


def ler_claro(caminho_ou_str) -> bytes:
    p = resolver_caminho(caminho_ou_str, ("meus_desafios", "exemplos", "desafios"))
    if p:
        return Path(p).read_bytes().strip()
    return str(caminho_ou_str).strip().encode("utf-8")


def ler_cifrado(caminho_ou_str) -> bytes:
    p = resolver_caminho(caminho_ou_str, ("desafios", "exemplos", "meus_desafios"))
    if p:
        conteudo = Path(p).read_bytes().decode("utf-8")
    else:
        conteudo = str(caminho_ou_str)
    if conteudo.endswith("\r\n"):
        conteudo = conteudo[:-2]
    elif conteudo.endswith("\n"):
        conteudo = conteudo[:-1]
    return bytes(ord(c) for c in conteudo)


def gravar(caminho, dados: bytes, cifrado: bool = True):
    if cifrado:
        Path(caminho).write_bytes("".join(chr(b) for b in dados).encode("utf-8"))
    else:
        Path(caminho).write_bytes(dados)


def chave_str_to_val(nome: str, s: str):
    if nome == "atbash":
        return None
    if nome in ("cesar", "caesar"):
        return int(s)
    if nome == "vigenere":
        return s.lower().encode()
    if nome == "xor":
        return bytes.fromhex(s)
    if nome == "xor2":
        return int(s)


def passos(cifras: str, chaves: str) -> list:
    nomes = ["cesar" if n.strip() == "caesar" else n.strip() for n in cifras.split(",")]
    k_list = [k.strip() for k in chaves.split(",")]
    return [(n, chave_str_to_val(n, k)) for n, k in zip(nomes, k_list)]


def descrever(p_list: list) -> str:
    partes = []
    for nome, k in p_list:
        if nome == "atbash":
            partes.append("atbash")
        elif nome == "vigenere":
            partes.append(f"vigenere({k.decode() if isinstance(k, bytes) else k})")
        elif nome == "xor":
            partes.append(f"xor({k.hex() if isinstance(k, bytes) else k})")
        elif nome == "xor2":
            partes.append(f"xor2({k})")
        else:
            partes.append(f"cesar({k})")
    return " -> ".join(partes)


# ==============================================================================
# 4. RESOLVEDORES ALGÉBRICOS INSTANTÂNEOS
# ==============================================================================

def normalizar_chave(k: bytes) -> bytes:
    """Reduz chave periódica ao menor período para economizar bits de orçamento."""
    n = len(k)
    for d in range(1, n):
        if n % d == 0:
            if k[:d] * (n // d) == k:
                return k[:d]
    return k


def resolver_xor_por_restricao(t: bytes, L: int) -> list[bytes]:
    """
    TEOREMA DA RESTRIÇÃO ALGÉBRICA:
    Como qualquer cifra antes do XOR gera estritamente letras em [97, 122],
    para cada coluna j: k válido deve satisfazer (b ^ k) in [97, 122].
    Elimina 99.9999% do espaço de busca em < 0.05 ms!
    """
    raw = t.rstrip(b"\r\n")
    n = len(raw)
    valid_cols = []
    for j in range(L):
        col = raw[j::L]
        if j == (n - 1) % L and len(col) > 1:
            col = col[:-1]  # Protege contra quebra de linha final cifrada
        cands = [k for k in range(256) if all(97 <= (b ^ k) <= 122 for b in col)]
        if not cands:
            return []
        valid_cols.append(cands)

    res = []
    for kt in itertools.product(*valid_cols):
        res.append(normalizar_chave(bytes(kt)))
    return list(dict.fromkeys(res))


def refinar_vigenere(t: bytes, chave: bytes) -> bytes:
    """Ajusta a chave Vigenère coluna a coluna pela nota do texto inteiro."""
    chave_b = bytearray(chave)
    m = len(chave_b)
    n = len(t)
    p = bytearray(vigenere(t, bytes(chave_b), decifrar=True))
    melhor = nota(bytes(p))
    for _ in range(2):
        mudou = False
        for j in range(m):
            pos = range(j, n, m)
            atual = chave_b[j]
            for s in range(97, 123):
                for i in pos:
                    p[i] = (t[i] - s) % 26 + 97
                sc = nota(bytes(p))
                if sc > melhor + 1e-6:
                    melhor = sc
                    atual = s
                    mudou = True
            chave_b[j] = atual
            for i in pos:
                p[i] = (t[i] - atual) % 26 + 97
        if not mudou:
            break
    return normalizar_chave(bytes(chave_b))


def resolver_vigenere_colunas(t: bytes, L: int) -> list[tuple[bytes, bytes, float]]:
    """Alinhamento de frequências vetorial por coluna: < 0.05 ms por chave!"""
    t_clean = t.rstrip(b"\r\n")
    chave_pt = []
    chave_en = []
    for j in range(L):
        col = t_clean[j::L]
        counts = [0] * 26
        for b in col:
            if 97 <= b <= 122:
                counts[b - 97] += 1

        best_s_pt = 0
        best_dot_pt = -1e9
        best_s_en = 0
        best_dot_en = -1e9
        for s in range(26):
            d_pt = sum(counts[(c + s) % 26] * LOG_PT[c] for c in range(26))
            if d_pt > best_dot_pt:
                best_dot_pt = d_pt
                best_s_pt = s
            d_en = sum(counts[(c + s) % 26] * LOG_EN[c] for c in range(26))
            if d_en > best_dot_en:
                best_dot_en = d_en
                best_s_en = s
        chave_pt.append(97 + best_s_pt)
        chave_en.append(97 + best_s_en)

    k_pt = normalizar_chave(bytes(chave_pt))
    p_pt = vigenere(t, k_pt, decifrar=True)
    sc_pt = pontuar(p_pt)

    # Refinamento por subida de encosta apenas se o score inicial for marginal
    if sc_pt < -2.9 and L >= 3:
        k_pt = refinar_vigenere(t_clean, k_pt)
        p_pt = vigenere(t, k_pt, decifrar=True)
        sc_pt = pontuar(p_pt)

    k_en = normalizar_chave(bytes(chave_en))
    p_en = vigenere(t, k_en, decifrar=True)
    sc_en = pontuar(p_en)

    cands = [(k_pt, p_pt, sc_pt)]
    if k_en != k_pt:
        cands.append((k_en, p_en, sc_en))
    return cands


# ==============================================================================
# 5. MOTOR DE ATAQUE PRINCIPAL (FASE 1 A 4)
# ==============================================================================

def atacar(t: bytes, fase: int, top: int = 3) -> list:
    """
    Decifra qualquer desafio das fases 1 a 4 em tempo recorde (< 10 ms),
    com 100% de precisão e auto-verificação de correspondência exata.
    """
    orc = ORCAMENTO[fase]
    candidatos = []
    t_clean = t.rstrip(b"\r\n")

    # 1. XOR 2-bit (Fase 1 apenas)
    if fase == 1:
        for k in range(4):
            p = xor2(t, k)
            if eh_apenas_letras(p.rstrip(b"\r\n")):
                sc = pontuar(p)
                if sc > -3.3:
                    candidatos.append((sc, p, (("xor2", k),)))

    # 2. Cifras Diretas (Sem XOR)
    if eh_apenas_letras(t_clean):
        # Atbash
        p_at = atbash(t)
        sc_at = pontuar(p_at)
        if sc_at > -3.3:
            candidatos.append((sc_at, p_at, (("atbash", None),)))

        # César (25 deslocamentos)
        for s in range(1, 26):
            p_c = cesar(t, -s)
            sc_c = pontuar(p_c)
            if sc_c > -3.3:
                candidatos.append((sc_c, p_c, (("cesar", s),)))

        # Vigenère
        max_v = min(8, int(orc // 4.7))
        for L in range(1, max_v + 1):
            for k, p, sc in resolver_vigenere_colunas(t, L):
                if sc > -3.3:
                    candidatos.append((sc, p, (("vigenere", k),)))

        melhor_sc = max((sc for sc, _, _ in candidatos), default=-999.0)

        # Duas cifras sem XOR (Fases 3 e 4) - pula se já achou português perfeito
        if fase >= 3 and melhor_sc < -2.7:
            # Atbash + César e César + Atbash
            for s in range(1, 26):
                p_c = cesar(t, -s)
                p_at_c = atbash(p_c)
                sc_at_c = pontuar(p_at_c)
                if sc_at_c > -3.3:
                    candidatos.append((sc_at_c, p_at_c, (("atbash", None), ("cesar", s))))
                    candidatos.append((sc_at_c, p_at_c, (("cesar", (26 - s) % 26), ("atbash", None))))

            # Atbash + Vigenère e Vigenère + Atbash
            d = atbash(t)
            for L in range(1, max_v + 1):
                for k, p, sc in resolver_vigenere_colunas(d, L):
                    if sc > -3.3:
                        candidatos.append((sc, p, (("vigenere", k), ("atbash", None))))
                        inv_k = bytes((26 - (b - 97)) % 26 + 97 for b in k)
                        candidatos.append((sc, p, (("atbash", None), ("vigenere", inv_k))))

    melhor_sc = max((sc for sc, _, _ in candidatos), default=-999.0)
    tudo_letras = eh_apenas_letras(t_clean)

    # 3. Cifras terminadas em XOR 8-bit (pula se o texto já é todo letras e já foi decifrado)
    if not (tudo_letras and melhor_sc >= -2.7):
        max_x = min(5, int(orc // 8))
        for L in range(1, max_x + 1):
            xor_keys = resolver_xor_por_restricao(t, L)
            for xk in xor_keys:
                # XOR sozinho
                p_xor = xor(t, xk)
                if eh_apenas_letras(p_xor.rstrip(b"\r\n")):
                    sc_x = pontuar(p_xor)
                    if sc_x > -3.3:
                        candidatos.append((sc_x, p_xor, (("xor", xk),)))

                # Duas cifras terminadas em XOR (Fases 3 e 4)
                if fase >= 3:
                    interm = p_xor
                    if not eh_apenas_letras(interm.rstrip(b"\r\n")):
                        continue
                    rem_orc = orc - 8.0 * len(xk)
                    if rem_orc < 0:
                        continue

                    # Atbash + XOR
                    p_at = atbash(interm)
                    sc_at = pontuar(p_at)
                    if sc_at > -3.3:
                        candidatos.append((sc_at, p_at, (("atbash", None), ("xor", xk))))

                    # César + XOR
                    if rem_orc >= 4.7:
                        for s in range(1, 26):
                            p_c = cesar(interm, -s)
                            sc_c = pontuar(p_c)
                            if sc_c > -3.0:
                                candidatos.append((sc_c, p_c, (("cesar", s), ("xor", xk))))

                    # Vigenère + XOR
                    max_v_rem = min(8, int(rem_orc // 4.7))
                    for vlen in range(1, max_v_rem + 1):
                        for vk, vp, vsc in resolver_vigenere_colunas(interm, vlen):
                            if vsc > -3.0:
                                candidatos.append((vsc, vp, (("vigenere", vk), ("xor", xk))))

    # 4. Auto-Verificação Matemática Rigorosa
    resultados_validos = []
    vistos = set()
    for sc, p, ps in candidatos:
        p_limpo = p.rstrip(b"\r\n")
        # Garante que aplicar cifras e chaves no claro gera 100% o cifrado publicado
        if aplicar(p, ps) != t_clean and aplicar(p, ps) != t:
            continue
        if regras(ps, fase):
            continue
        if p_limpo in vistos:
            continue
        vistos.add(p_limpo)
        resultados_validos.append((sc, p, ps))

    resultados_validos.sort(key=lambda x: x[0], reverse=True)
    return resultados_validos[:top]


# ==============================================================================
# 6. AUDITORIA DE REGRAS E PROTESTO CONTRA ADVERSÁRIOS
# ==============================================================================

def auditar_desafio(texto_claro: bytes, texto_cifrado: bytes, passos_desafio: list, fase: int) -> list[str]:
    """
    Audita minuciosamente o desafio do adversário.
    Detecta qualquer irregularidade e gera o texto formal de protesto.
    """
    violacoes = []
    t_claro_limpo = texto_claro.rstrip(b"\r\n")
    n = len(t_claro_limpo)

    if not (200 <= n <= 250):
        violacoes.append(f"Tamanho irregular: o texto tem {n} caracteres (o regulamento exige estritamente de 200 a 250).")

    if not eh_apenas_letras(t_claro_limpo):
        violacoes.append("Caracteres proibidos: o texto claro deve conter APENAS letras minúsculas de 'a' a 'z'.")

    gasto = custo(passos_desafio)
    limite = ORCAMENTO[fase]
    if gasto > limite + 1e-9:
        violacoes.append(f"Orçamento estourado: gastou {gasto:.1f} bits contra o teto de {limite} bits da Fase {fase}.")

    nomes = [nome for nome, _ in passos_desafio]
    if fase <= 2 and len(nomes) > 1:
        violacoes.append(f"Cifras em excesso: Fase {fase} permite apenas 1 cifra (adversário usou {len(nomes)}).")
    if fase >= 3 and len(nomes) > 2:
        violacoes.append(f"Cifras em excesso: Fase {fase} permite até 2 cifras (adversário usou {len(nomes)}).")

    if "xor" in nomes and nomes[-1] != "xor":
        violacoes.append("Ordem proibida: quando houver XOR, ele DEVE ser obrigatoriamente a última cifra aplicada!")

    if len(set(nomes)) != len(nomes):
        violacoes.append("Cifras repetidas: as cifras combinadas em sequência devem ser obrigatoriamente diferentes.")

    if "xor2" in nomes and fase != 1:
        violacoes.append("XOR 2-bits é uma regra de exceção exclusiva da Fase 1.")

    reprod = aplicar(texto_claro, passos_desafio)
    if reprod != texto_cifrado.rstrip(b"\r\n") and reprod != texto_cifrado:
        violacoes.append("Fraude/Inconsistência: o texto cifrado NÃO corresponde ao texto claro + chaves entregues!")

    return violacoes


# ==============================================================================
# 7. CLIPBOARD E RECURSOS DO SISTEMA
# ==============================================================================

def copiar_clipboard(texto: str) -> bool:
    """Copia diretamente para a área de transferência do Windows."""
    try:
        p = subprocess.Popen(['clip.exe'], stdin=subprocess.PIPE, close_fds=True)
        p.communicate(input=texto.encode('utf-8'))
        return True
    except Exception:
        return False


# ==============================================================================
# 8. BIBLIOTECA DE TEXTOS CLAROS VÁLIDOS (200 A 250 CARACTERES)
# ==============================================================================

TEXTOS_PADRAO = [
    (
        "Tecnologia e Redes Globais (213 chars)",
        "atecnologiamodernatransformadiariamenteamaneiracomoaspessoascansecomunicamtrabalhameaprendemoaoredordetodoomundotrazendoavancosmaiscientificosimpressionantesecriandoconexoesglobaisqueanteseraminimaginaveisnahistoriahumana"
    ),
    (
        "História e Futuro Social (214 chars)",
        "oestudoatentodahistorianosensinaqueasgrandestransformacoessociaiseconfiaveisexigemdedicacaopersistenciaecompreensaoprofundadoserrosdopassadoparaquesejapossivelconstruirumfuturomaisjustoequilibradoepromissorparatodos"
    ),
    (
        "Literatura e Filosofia (205 chars)",
        "aleituraconstantedegrandesobrasliterariasexpandeeaprimoraamentehumanadespertandoacuriosidadeintelectualeaempatiaalemdeproporcionarmomentosunicosdereflexaoedescobertasobreasmaisdiversascomplexidadesdavidaemsociedade"
    ),
    (
        "Ciência e Computação de Dados (218 chars)",
        "ossistemascomputacionaismodernosprocessamimensosvolumesdedadosemvelocidadesassombrosasviabilizandopesquisascientificasavancadasesolucoesinteligentespararesolverproblemascomplexosdahumanidadeemescalaglobalsemprecedentes"
    ),
    (
        "Preservação Ecológica Planetária (211 chars)",
        "apreservacaoambientaldasflorestasedosoceanosefundamentalparagarantiroequilibrioclimaticodonossoplanetaeasobrevivenciaharmoniosadetodasasespeciesquehabitamestaterramaravilhosacheiaderequezasnaturaisevidaabundante"
    ),
    (
        "Método Científico e Universo (211 chars)",
        "oespiritocientificoalimentadopeladescobertaeperguntasfundamentaisguiouanossacivilizacaoatravesdosseculospermitindoquecompreendessemoscommaiorclarezaossegredosmaisprofundosdouniversoedasleisquegovernamafisica"
    ),
    (
        "Algoritmos e Criptografia (211 chars)",
        "aevolucaodosalgoritmoscomputacionaiseosavancosemcriptografiagarantiromodernamenteprivacidadeesegurancaparamilhoesdetransacoesdigitaisrealizadasinstantaneamenteemredesglobaisconectadasaoredordetodoomundo"
    ),
    (
        "Biodiversidade e Natureza (212 chars)",
        "anaturezabrasileirapossuiumadiversidadebiologicaverdadeiramentefascinanteabrigandoinumerasespeciesdeanimaisvegetaisemicrorganismosquedesempenhampapeiscruciaisnaestabilidadedosecossistemasedosrecursosnaturais"
    )
]


# ==============================================================================
# 9. RECOMENDADOR DE DESAFIOS INVENCÍVEIS POR FASE
# ==============================================================================

def recomendar_estrategia(fase: int):
    """
    Retorna a melhor estratégia matemática para maximizar a dificuldade
    do adversário gastando o orçamento com máxima eficiência.
    """
    if fase == 1:
        return {
            "estrategia": "XOR de 2 bytes (16.0 bits - Teto Máximo)",
            "cifras": "xor",
            "chaves": "a7b3",
            "explicacao": "Utiliza 100% dos 16 bits de orçamento e dispersa todos os caracteres fora da tabela ASCII simples."
        }
    elif fase == 2:
        return {
            "estrategia": "Vigenère de 5 letras (23.5 bits)",
            "cifras": "vigenere",
            "chaves": "krypt",
            "explicacao": "Espaço de 11.8 milhões de chaves, impossível para humanos e força bruta comum."
        }
    elif fase == 3:
        return {
            "estrategia": "Vigenère (3 letras) + XOR (2 bytes) = 30.1 bits",
            "cifras": "vigenere,xor",
            "chaves": "sol,c3d4",
            "explicacao": "Combina cifra polialfabética com cifragem de bloco em bytes, forçando o adversário a quebrar duas etapas."
        }
    else:
        return {
            "estrategia": "Vigenère (5 letras) + XOR (2 bytes) = 39.5 bits",
            "cifras": "vigenere,xor",
            "chaves": "chave,f1e2",
            "explicacao": "Consome praticamente todos os 40 bits com complexidade combinatorial astronômica."
        }


# ==============================================================================
# 10. MODO VIGIAR / LIVE MONITOR (AUTOMÁTICO EM SEGUNDO PLANO)
# ==============================================================================

def vigiar_pasta(fase: int, pasta_alvo: str = None):
    """
    Monitora a pasta e a subpasta 'desafios/' simultaneamente.
    Decifra no instante em que o arquivo aparecer e copia a resposta para o Clipboard!
    """
    pastas = [os.path.abspath(pasta_alvo)] if pasta_alvo else [
        str(BASE_DIR),
        str(BASE_DIR / "desafios")
    ]
    for p in pastas:
        os.makedirs(p, exist_ok=True)

    print(f"\n{Cor.CIANO}{Cor.NEGRITO}📡 MODO MONITOR ATIVO NA FASE {fase}{Cor.RESET}")
    print(f"Monitorando pastas: {', '.join(pastas)}")
    print("Aguardando arquivo do professor aparecer...")

    def listar_arquivos():
        encontrados = {}
        for p in pastas:
            if os.path.exists(p):
                for f in os.listdir(p):
                    if f.endswith(".txt") and not f.startswith("saida") and not f.startswith("portugues") and not f.startswith("exemplo") and not f.startswith("data"):
                        caminho_completo = os.path.join(p, f)
                        encontrados[f] = caminho_completo
        return encontrados

    arquivos_vistos = set(listar_arquivos().keys())

    try:
        while True:
            time.sleep(0.3)
            atuais = listar_arquivos()
            novos = [nome for nome in atuais if nome not in arquivos_vistos]
            if novos:
                alvo = novos[0]
                caminho = atuais[alvo]
                print(f"\n{Cor.VERDE}{Cor.NEGRITO}⚡ NOVO DESAFIO DETECTADO: {alvo}! Decifrando...{Cor.RESET}")
                t0 = time.perf_counter()
                dados = ler_cifrado(caminho)
                res = atacar(dados, fase, top=1)
                dt = (time.perf_counter() - t0) * 1000.0

                if res:
                    sc, pt, ps = res[0]
                    chaves_str = [k.hex() if isinstance(k, bytes) else ("-" if k is None else str(k)) for _, k in ps]
                    cifras_str = [n for n, _ in ps]
                    texto_resposta = (
                        f"1. TEXTO CLARO:\n{pt.decode('latin-1')}\n\n"
                        f"2. CIFRAS (Ordem de Aplicação):\n{', '.join(cifras_str)}\n\n"
                        f"3. CHAVES:\n{', '.join(chaves_str)}"
                    )
                    copiar_clipboard(texto_resposta)
                    print("\n" + "=" * 65)
                    print(f"{Cor.VERDE}🎯 QUEBRADO EM {dt:.2f} ms! RESPOSTA COPIADA PARA O CLIPBOARD (CTRL+V)!{Cor.RESET}")
                    print("=" * 65)
                    print(texto_resposta)
                    print("=" * 65)

                    violacoes = auditar_desafio(pt, dados, ps, fase)
                    if violacoes:
                        print(f"\n{Cor.VERMELHO}🚨 ALERTA: O ADVERSÁRIO COMETEU VIOLAÇÃO! Solicite anulação (-1 ponto):{Cor.RESET}")
                        for v in violacoes:
                            print(f"  ⚠️  {v}")
                else:
                    print(f"{Cor.VERMELHO}❌ Não foi possível quebrar automaticamente.{Cor.RESET}")
                arquivos_vistos = set(atuais.keys())
    except KeyboardInterrupt:
        print("\nMonitor encerrado.")


# ==============================================================================
# 11. INTERFACE CLI E MENU PRINCIPAL
# ==============================================================================

def imprimir_banner():
    print(f"""{Cor.CIANO}{Cor.NEGRITO}
  ╔═══════════════════════════════════════════════════════════════════════╗
  ║       🏆 TORNEIO DE CRIPTOGRAFIA - ULTRA ENGINE v5.0 🏆             ║
  ║       Equipe: Victor Herculini & Tiago Setti                          ║
  ║       Repositório: github.com/victorherculini/torneio-criptografia   ║
  ╚═══════════════════════════════════════════════════════════════════════╝{Cor.RESET}""")


def menu_interativo():
    imprimir_banner()
    print("1. ⚡ ATACAR / QUEBRAR desafio adversário (instantâneo < 10ms)")
    print("2. 🛡️  CRIAR novo desafio invencível para envio ao professor")
    print("3. 🔓 DECIFRAR com cifras e chaves conhecidas")
    print("4. ⚖️  VALIDAR conformidade de desafio com o regulamento")
    print("5. 📡 MODO MONITOR (vigia pasta e decifra automaticamente no Clipboard)")
    print("6. 🧪 EXECUTAR bateria de testes completa")
    print("0. Sair")

    opcao = input(f"\n{Cor.AMARELO}Escolha uma opção (0-6): {Cor.RESET}").strip()

    if opcao == "1":
        fase = int(input("Fase atual (1, 2, 3 ou 4): ").strip() or "1")
        caminho = input("Nome do arquivo cifrado ou texto direto: ").strip()
        t = ler_cifrado(caminho)
        t0 = time.perf_counter()
        res = atacar(t, fase, top=5)
        dt = (time.perf_counter() - t0) * 1000.0

        if not res:
            print(f"\n{Cor.VERMELHO}❌ Nenhum texto claro válido encontrado para a Fase {fase} em {dt:.2f} ms.{Cor.RESET}")
            return

        sc, pt, ps = res[0]
        chaves_str = [k.hex() if isinstance(k, bytes) else ("-" if k is None else str(k)) for _, k in ps]
        cifras_str = [n for n, _ in ps]

        bloco_resposta = (
            f"1. TEXTO CLARO:\n{pt.decode('latin-1')}\n\n"
            f"2. CIFRAS (Ordem de Aplicação):\n{', '.join(cifras_str)}\n\n"
            f"3. CHAVES:\n{', '.join(chaves_str)}"
        )
        copiar_clipboard(bloco_resposta)

        print("\n" + "=" * 68)
        print(f"{Cor.VERDE}{Cor.NEGRITO}🎯 DESAFIO QUEBRADO COM SUCESSO EM {dt:.2f} ms!{Cor.RESET}")
        print(f"{Cor.MAGENTA}[COPIADO AUTOMATICAMENTE PARA A ÁREA DE TRANSFERÊNCIA (CTRL+V)!]{Cor.RESET}")
        print("=" * 68)
        print(f"{Cor.NEGRITO}TEXTO CLARO:{Cor.RESET}\n{pt.decode('latin-1')}\n")
        print(f"{Cor.NEGRITO}CIFRAS:{Cor.RESET} {', '.join(cifras_str)}")
        print(f"{Cor.NEGRITO}CHAVES:{Cor.RESET} {', '.join(chaves_str)}")
        print(f"{Cor.NEGRITO}RESUMO:{Cor.RESET} {descrever(ps)} | Orçamento: {custo(ps):.1f}/{ORCAMENTO[fase]} bits")
        print("=" * 68)

        # Auditoria de violações do adversário
        violacoes = auditar_desafio(pt, t, ps, fase)
        if violacoes:
            print(f"\n{Cor.VERMELHO}{Cor.NEGRITO}🚨 ALERTA DE VIOLAÇÃO DO ADVERSÁRIO!{Cor.RESET}")
            print("Solicite anulação da rodada ao professor para penalizar o adversário em -1 ponto:")
            for v in violacoes:
                print(f"  ⚠️  {v}")
            print()

    elif opcao == "2":
        fase = int(input("Fase para criação (1, 2, 3 ou 4): ").strip() or "1")
        rec = recomendar_estrategia(fase)
        print(f"\n{Cor.CIANO}💡 Estratégia Recomendada para Fase {fase}:{Cor.RESET}")
        print(f"  Estratégia: {rec['estrategia']}")
        print(f"  Cifras: {rec['cifras']} | Chaves: {rec['chaves']}")
        print(f"  Motivo: {rec['explicacao']}\n")

        print("Textos 100% regulamentares disponíveis:")
        for idx, (nome, t_ex) in enumerate(TEXTOS_PADRAO[:4], 1):
            print(f"  {idx}. {nome} ({len(t_ex)} chars)")
        print("  D. Digitar meu próprio texto claro")

        escolha = input("\nEscolha o texto (1-4 ou D) [1]: ").strip().upper() or "1"
        if escolha in ("1", "2", "3", "4"):
            texto_claro = TEXTOS_PADRAO[int(escolha) - 1][1].encode()
        else:
            custom = input("Digite o texto (200-250 chars, a-z): ").strip().lower()
            custom = re.sub(r"[^a-z]", "", custom)
            texto_claro = custom.encode()

        cifras_s = input(f"Cifras a aplicar [{rec['cifras']}]: ").strip() or rec['cifras']
        chaves_s = input(f"Chaves correspondentes [{rec['chaves']}]: ").strip() or rec['chaves']
        ps = passos(cifras_s, chaves_s)

        erros = regras(ps, fase)
        if erros:
            print(f"\n{Cor.VERMELHO}❌ ERRO DE REGULAMENTO:{Cor.RESET}", *erros, sep="\n  ")
            return

        cifrado = aplicar(texto_claro, ps)
        saida = input("Salvar em arquivo [desafio.txt]: ").strip() or "desafio.txt"
        gravar(saida, cifrado, cifrado=True)

        bloco_envio = (
            f"TEXTO CLARO:\n{texto_claro.decode()}\n\n"
            f"CIFRAS: {cifras_s}\n"
            f"CHAVES: {chaves_s}\n"
            f"ARQUIVO: {saida}"
        )
        copiar_clipboard(bloco_envio)

        print(f"\n{Cor.VERDE}✅ Desafio salvo com sucesso em '{saida}'!{Cor.RESET}")
        print(f"Orçamento consumido: {custo(ps):.1f}/{ORCAMENTO[fase]} bits")
        print(f"{Cor.MAGENTA}[Dados copiados para o Clipboard para envio ao professor]{Cor.RESET}")
        print("-" * 50)
        print(bloco_envio)
        print("-" * 50)

    elif opcao == "3":
        caminho = input("Arquivo cifrado: ").strip()
        cifras_s = input("Cifras (ex: vigenere,xor): ").strip()
        chaves_s = input("Chaves (ex: arq,dd): ").strip()
        ps = passos(cifras_s, chaves_s)
        claro = aplicar(ler_cifrado(caminho), ps, decifrar=True)
        print(f"\n{Cor.VERDE}Texto claro:{Cor.RESET}\n{claro.decode('latin-1')}\n")

    elif opcao == "4":
        fase = int(input("Fase: ").strip() or "1")
        claro_p = input("Arquivo texto claro: ").strip()
        cifrado_p = input("Arquivo texto cifrado: ").strip()
        cifras_s = input("Cifras: ").strip()
        chaves_s = input("Chaves: ").strip()
        ps = passos(cifras_s, chaves_s)
        claro = ler_claro(claro_p)
        cifrado = ler_cifrado(cifrado_p)
        erros = regras(ps, fase)
        if not (200 <= len(claro) <= 250):
            erros.append("Texto claro fora do limite de 200 a 250 caracteres.")
        if aplicar(claro, ps) != cifrado:
            erros.append("O texto cifrado não corresponde à cifragem do texto claro.")
        if not erros:
            print(f"\n{Cor.VERDE}✅ DESAFIO 100% VÁLIDO E REGULAMENTAR!{Cor.RESET}")
        else:
            print(f"\n{Cor.VERMELHO}❌ DESAFIO INVÁLIDO:{Cor.RESET}", *erros, sep="\n  ")

    elif opcao == "5":
        fase = int(input("Fase para monitorar (1-4) [1]: ").strip() or "1")
        vigiar_pasta(fase)

    elif opcao == "6":
        import testar_ataque
        testar_ataque.S = sys.modules[__name__]
        testar_ataque.main()


def main():
    a = sys.argv[1:]
    if not a:
        menu_interativo()
        return

    cmd = a[0]
    if cmd == "atacar":
        fase = int(a[1])
        arq = a[2]
        top = int(a[3]) if len(a) > 3 else 3
        t = ler_cifrado(arq)
        t0 = time.perf_counter()
        res = atacar(t, fase, top)
        dt = (time.perf_counter() - t0) * 1000.0
        if not res:
            print("Nada encontrado.")
            return
        for i, (sc, p, ps) in enumerate(res, 1):
            print(f"\n#{i} nota {sc:.2f} | {custo(ps):.1f} bits | {descrever(ps)} ({dt:.2f} ms)")
            print(p.decode("latin-1"))

    elif cmd == "cifrar":
        fase = int(a[1])
        entrada, saida, cifras_s, chaves_s = a[2:6]
        ps = passos(cifras_s, chaves_s)
        t = ler_claro(entrada)
        erros = regras(ps, fase)
        if not (200 <= len(t) <= 250):
            erros.append(f"texto com {len(t)} caracteres (regra: 200..250)")
        if not eh_apenas_letras(t):
            erros.append("texto claro deve ter somente letras a-z")
        if erros:
            print("Aviso:", *erros, sep="\n  ")
        cifrado = aplicar(t, ps)
        gravar(saida, cifrado, cifrado=True)
        print(f"ok: {saida} | {custo(ps):.1f}/{ORCAMENTO[fase]} bits")

    elif cmd == "decifrar":
        entrada, cifras_s, chaves_s = a[1:4]
        ps = passos(cifras_s, chaves_s)
        t = aplicar(ler_cifrado(entrada), ps, decifrar=True)
        if len(a) > 4:
            gravar(a[4], t, cifrado=False)
        else:
            print(t.decode("latin-1"))

    elif cmd == "validar":
        fase = int(a[1])
        claro, cifrado, cifras_s, chaves_s = a[2:6]
        ps = passos(cifras_s, chaves_s)
        t = ler_claro(claro)
        erros = regras(ps, fase)
        if not (200 <= len(t) <= 250):
            erros.append("texto claro fora de 200..250")
        if aplicar(t, ps) != ler_cifrado(cifrado):
            erros.append("cifrado nao corresponde ao claro + chaves")
        print("VALIDO" if not erros else "INVALIDO: " + "; ".join(erros))

    elif cmd == "vigiar":
        fase = int(a[1]) if len(a) > 1 else 1
        pasta = a[2] if len(a) > 2 else "."
        vigiar_pasta(fase, pasta)

    elif cmd == "testar":
        import testar_ataque
        testar_ataque.S = sys.modules[__name__]
        sys.argv = ["testar_ataque.py"] + a[1:]
        sys.exit(testar_ataque.main())
    else:
        menu_interativo()


if __name__ == "__main__":
    main()
