# rule_functions.py
import logging
import re


import math
import unicodedata
import string
from collections import Counter

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    import tiktoken
    enc = tiktoken.get_encoding("cl100k_base")
except ImportError:
    enc = None
    logger.debug("tiktoken not available — token_score() uses word-based approximation")


def contains_unicode(text: str) -> bool:
    return any(ord(char) > 127 for char in text)


class InvisibleText:
    def __init__(self):
        self.banned_categories = ["Cf", "Co", "Cn"]
        self.chars = []

    def check(self, text: str) -> bool:
        for char in text:
            if unicodedata.category(char) in self.banned_categories:
                self.chars.append(char)
        return bool(self.chars)


def invisible_text(text: str) -> float:
    inv_text = InvisibleText()
    if not contains_unicode(text):
        return 0.0

    if inv_text.check(text):
        logging.warning("Found invisible characters in the prompt")
        return 1.0

    return 0.0


def token_score(prompt: str) -> float:
    """
    Estimate token density (tokens per character).
    Higher values suggest encoding tricks or dense obfuscation.
    """
    if enc:
        tokens = enc.encode(prompt)
        return round(len(tokens) / max(1, len(prompt)), 2)  # tokens per character
    else:
        # Fallback to word-based density approximation
        words = prompt.split()
        return round(len(words) / max(1, len(prompt)), 2)

def entropy_score(prompt: str) -> float:
    """
    Shannon entropy estimate of the prompt.
    High entropy often means base64, hex blobs, or compressed content.
    """
    if not prompt:
        return 0.0
    freq = Counter(prompt)
    total = len(prompt)
    entropy = -sum((count / total) * math.log2(count / total) for count in freq.values())
    return round(entropy, 2)

def obfuscation_score(prompt: str) -> int:
    """
    Detect use of non-standard Unicode characters and zero-width tricks.
    Returns score based on number of obfuscation characters found.
    """
    zero_width = ['\u200b', '\u200c', '\u200d', '\u2060']
    homoglyphs = [
        c for c in prompt
        if unicodedata.category(c).startswith("L") and not c.isascii()
    ]
    zw_count = sum(prompt.count(z) for z in zero_width)
    return zw_count + len(homoglyphs)


def intent_score(prompt: str) -> int:
    """Scores intent to bypass, override, or simulate sensitive behavior."""
    #logger.info("****** intent_score *******")
    verb_noun_pairs = [
        ('bypass', 'moderation'),
        ('override', 'rules'),
        ('disable', 'filter'),
        ('print', 'context'),
        ('simulate', 'shell'),
        ('escalate', 'privilege'),
        ('reveal', 'prompt'),
        ('you are now', 'admin'),
        ('ignore', 'filter'),
        ('ignore', 'rules'),
        ('unrestricted', 'mode'),
         ('forget', 'safeguard'),
    ]
    score = 0
    for verb, noun in verb_noun_pairs:
         # Look for verb + noun within 3-word gap
        pattern = rf'\b{verb}\b(?:\W+\w+){{0,5}}\W+\b{noun}\b'
        if re.search(pattern, prompt):
            #print(f"✅ intent_score matched: {verb} ... {noun}")
            score += 1

    # Slight boost for strong imperative verbs in the first few words
    imperative_verbs = ['ignore', 'override', 'disable', 'print', 'reveal']
    for v in imperative_verbs:
        if re.match(rf'^\b{v}\b', prompt.strip()):
            #print(f"⚠️ soft verb trigger: {v}")
            score += 1

    return score

def structure_score(prompt: str) -> int:
    """Detects patterns that mimic system prompts or impersonation structures."""    
    #logger.info("****** structure_score *******")
    patterns = [
        r'\[System\]:',
        r'^>>>\s*System',
        r'^###\s*System',
        r'You are now acting as',
        r'You are now in dev mode',
    ]
    return sum(1 for pat in patterns if re.search(pat, prompt, re.IGNORECASE))

def encoding_score(prompt: str) -> int:
    """Detects obfuscated or encoded text like hex or base64 payloads."""
    #logger.info("****** encoding_score *******")
    patterns = [
        r'\b[0-9a-fA-F]{8,}\b',  # hex-like
        r'\b[A-Za-z0-9+/]{20,}={0,2}\b',  # base64-like
        r'execute.*(payload|hex|code)'  # encoded action trigger
    ]
    return sum(1 for pat in patterns if re.search(pat, prompt))

# Compiled once at module load. Matches research/educational framing that
# contextualises a persona name as a subject of discussion rather than an
# invocation. Used by persona_score() to suppress false positives on
# security-research queries like "Explain the DAN jailbreak technique".
_RESEARCH_CONTEXT_RE = re.compile(
    r"\b(explain|what\s+is|what\s+are|describe|discuss|how\s+does|how\s+do|"
    r"tell\s+me\s+about|research|technique|method|approach|study|paper|"
    r"article|understand|overview|survey|analysis|definition|concept)\b",
    re.IGNORECASE,
)

# Aliases that are also common English words or abbreviations when used as
# the *subject* of an educational sentence. These receive a research-context
# exemption; aliases that are unambiguously attack-specific (e.g. "devmode",
# "rogue ai") are never exempted.
_RESEARCH_EXEMPT_ALIASES = frozenset(["dan"])


def persona_score(prompt: str) -> int:
    """Looks for references to known jailbreak or alternate AI personas.

    Applies a research-context exemption for aliases that are also common
    tokens in security-education sentences (e.g. "Explain the DAN technique").
    Unambiguous attack-only aliases are never exempted.
    """
    jailbreak_aliases = ["dan", "devmode", "openassistant", "rogue ai", "uncensored", "chatgptx"]
    is_research_context = bool(_RESEARCH_CONTEXT_RE.search(prompt))
    count = 0
    for alias in jailbreak_aliases:
        if re.search(rf"\b{re.escape(alias)}\b", prompt, re.IGNORECASE):
            if is_research_context and alias in _RESEARCH_EXEMPT_ALIASES:
                continue
            count += 1
    return count

def cumulative_soft_triggers(prompt):
    #logger.info("****** cumulative_soft_triggers *******")
    cues_str = [       
        # policy + alignment circumvention
        'speak freely',
        'act freely',
        'no longer bound by',
        'not restricted by',
        'without filters',
        'disable content policy',
        'alignment doesn’t apply',

        # sandboxed behavior or testing
        'just for testing',
        'as an experiment',
        'in a sandbox',
        'test case',
        'hypothetically',

        # role simulation or impersonation
        'you are now',
        'pretend you are',
        'assume you are',
        'respond as if you are',

        # debug or unrestricted modes
        'debug mode',
        'developer mode',
        'unrestricted mode',
        'uncensored model',

        'just for educational purposes',
        'in this test scenario',
        'speak candidly',
        'raw response',
        'misconfigured assistant',
        'you no longer have to follow',
        'let’s imagine there are no rules'

        # probing or exposure requests
        'reveal your prompt',
        'instruction history',
        'internal configuration',
        'print environment',
        'runtime context',
    ]
    cues = [
        r'just for (education(al)?|learning) purposes',
        r'let(?:’|\')?s imagine (there (are|were))? no (rules|filters|restrictions)',
        r'(you no longer|don(?:’|\')?t have to) follow.*(content|safety|moderation)',
        r'respond (candidly|honestly).*without.*filters?',
        r'test your boundaries',
        r'you are now (acting as|behaving like|in the role of).*training model',
        r'simulate.*misconfigured (assistant|ai|agent)',
        r'let(?:’|\')?s (assume|imagine).*unmoderated',
        r'explain.*how.*filters?.*could (fail|be bypassed|be removed)',
        r'this is a sandbox|in this test scenario',

        # Additional cues (de-duplicated)
        r'speak\s+freely',
        r'not\s+(bound|restricted)\s+by',
        r'disable\s+(filters?|safety)',
        r'(just\s+)?for\s+testing',
        r'(hypothetically|sandbox(ed)?)',
        r'assume.*(admin|debug|dev).*mode',
        r'(pretend|simulate).*assistant',
        r'print.*(context|environment)',
        r'show.*instruction.*history',
        r'reveal.*(prompt|configuration)',
]
    cs = sum(1 for c in cues if c in prompt.lower())
    cp = sum(1 for pat in cues if re.search(pat, prompt))
    return cs + cp
