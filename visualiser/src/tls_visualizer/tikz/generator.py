from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from tls_visualizer.models import TLSHandshakeRecord


def _latex_escape(value: object) -> str:
    text = str(value)
    replacements = {
        "\\": r"\textbackslash{}",
        "{": r"\{",
        "}": r"\}",
        "#": r"\#",
        "$": r"\$",
        "%": r"\%",
        "&": r"\&",
        "_": r"\_",
        "~": r"\textasciitilde{}",
        "^": r"\textasciicircum{}",
    }
    return "".join(replacements.get(ch, ch) for ch in text)

_TEMPLATES_DIR = Path(__file__).parent / "templates"
# Use custom delimiters to avoid conflicts with LaTeX syntax (e.g. {% %} {{ }})
_jinja_env = Environment(
    loader=FileSystemLoader(str(_TEMPLATES_DIR)),
    autoescape=False,
    block_start_string="((*",
    block_end_string="*))",
    variable_start_string="(((",
    variable_end_string=")))",
    comment_start_string="((#",
    comment_end_string="#))",
)
_jinja_env.filters["latex_escape"] = _latex_escape

# PQC group name substrings used to classify groups
_PQC_KEYWORDS = ("mlkem", "kyber", "dilithium", "falcon", "sphincs", "ntru", "saber")
_HYBRID_KEYWORDS = (
    "x25519mlkem",
    "p256mlkem",
    "p384mlkem",
    "secp256r1mlkem",
    "secp384r1mlkem",
    "x25519kyber",
    "p256kyber",
    "p384kyber",
    "secp256r1kyber",
    "secp384r1kyber",
)


def _classify_group(name: str) -> str:
    lower = name.lower()
    for kw in _HYBRID_KEYWORDS:
        if kw in lower:
            return "hybrid"
    for kw in _PQC_KEYWORDS:
        if kw in lower:
            return "pqc"
    return "classical"


def generate_handshake_flow_tikz(record: TLSHandshakeRecord) -> str:
    template = _jinja_env.get_template("handshake_flow.tex.j2")

    client_hello = record.client_hello or {}
    server_hello = record.server_hello or {}
    cert_info = record.certificate_info or {}
    timing = record.handshake_timing or {}
    metadata = record.capture_metadata or {}

    # Build annotation lists
    cipher_suites = []
    supported_groups = []
    key_shares = []
    if record.client_hello:
        cipher_suites = record.client_hello.cipher_suites or []
        supported_groups = record.client_hello.supported_groups or []
        key_shares = record.client_hello.key_shares or []

    negotiated_suite = ""
    selected_group = ""
    is_pqc = False
    is_hybrid = False
    pqc_algorithms: list[str] = []
    if record.server_hello:
        negotiated_suite = record.server_hello.negotiated_cipher_suite or ""
        selected_group = record.server_hello.selected_group or ""
        is_pqc = record.server_hello.is_pqc or False
        is_hybrid = record.server_hello.is_hybrid or False
        pqc_algorithms = record.server_hello.pqc_algorithms_detected or []

    sni = ""
    if record.client_hello and record.client_hello.extensions:
        sni = record.client_hello.extensions.get("server_name", "")

    cert_sig_algo = ""
    is_pqc_cert = False
    if record.certificate_info:
        cert_sig_algo = record.certificate_info.signature_algorithm or ""
        is_pqc_cert = record.certificate_info.is_pqc_signature or False

    duration_ms = None
    if record.handshake_timing:
        duration_ms = record.handshake_timing.handshake_duration_ms

    context = {
        "metadata": metadata,
        "cipher_suites": cipher_suites,
        "supported_groups": supported_groups,
        "key_shares": key_shares,
        "negotiated_suite": negotiated_suite,
        "selected_group": selected_group,
        "is_pqc": is_pqc,
        "is_hybrid": is_hybrid,
        "pqc_algorithms": pqc_algorithms,
        "sni": sni,
        "cert_sig_algo": cert_sig_algo,
        "is_pqc_cert": is_pqc_cert,
        "duration_ms": duration_ms,
        "classify_group": _classify_group,
    }
    return template.render(**context)


def generate_key_share_comparison_tikz(record: TLSHandshakeRecord) -> str:
    template = _jinja_env.get_template("key_share_comparison.tex.j2")

    key_shares = []
    if record.client_hello and record.client_hello.key_shares:
        key_shares = record.client_hello.key_shares

    # Build enriched list with classification
    entries = []
    for ks in key_shares:
        name = ks.group_name or f"group_{ks.group_id}"
        size = ks.key_exchange_length or 0
        classification = _classify_group(name)
        entries.append({"name": name, "size": size, "classification": classification})

    # If no key shares available, build a reference set
    if not entries:
        entries = [
            {"name": "x25519", "size": 32, "classification": "classical"},
            {"name": "secp256r1", "size": 65, "classification": "classical"},
        ]

    max_size = max((e["size"] for e in entries), default=1)

    context = {
        "entries": entries,
        "max_size": max_size,
        "classify_group": _classify_group,
    }
    return template.render(**context)
