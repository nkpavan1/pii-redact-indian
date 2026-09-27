"""Cleans up PERSON spans before they become mapping-store keys.

The span is the key: "Ping Ravi Kumar" and "Ravi Kumar" get two different
codes, so one person looks like two to the model, and reversal writes
"Ping Ravi Kumar" back wherever the model used the first code. A span that
stops short ("Please call PERSON_D Zanzibar today") leaves the rest of the
name in the clear. Both were measured on spaCy's NER, synthetic names, in
ordinary sentence frames (DECISIONS.md, step 13):

- A sentence-initial word is swallowed into the name: "Ping Ravi Kumar",
  "Customer Ravi Kumar", "Email Ravi Kumar", "Remind Ravi Kumar", "Call
  Periwinkle Zanzibar", "Dear Ram Kumar". spaCy tags "Ping", "Dear" and
  "Pay" as proper nouns there, so its tagger can't tell them apart from a
  name.
- A name is cut short: "Ping Periwinkle" + "Zanzibar", "Periwinkle" +
  "Zanzibar", "NARAYANAN" without "LAKSHMI".

So each PERSON span is refined in two steps:

1. Trim: words from NOT_NAME_WORDS (greetings, contact verbs, roles,
   statement vocabulary, days, months, software names, headings and
   labels) are removed from
   either edge, repeatedly, and TITLES from the front only ("Kumari" is a
   title before a name and a surname after one). The lists are curated rather than
   derived from a tagger or a dictionary, on purpose: a word is removed
   only when it is never a name. Words that are also given names ("Ram",
   "Bill", "Will", "Mark", "Rose", "Sunny", and the months "Jan", "Mar",
   "April", "May", "June", "August") are deliberately absent - trimming a
   real name part would leak it. A span with nothing left is dropped
   ("Dear Sir").
2. Extend: an adjacent word joins the name when it is plausibly part of
   it: spaCy tags it PROPN, it's separated from the name by spaces only
   (no punctuation, no line break), it is letters only, cased like the name
   (Title-case next to Title-case, all caps next to all caps, so "PAN" next
   to "Ravi Kumar" never joins), and it isn't a stop word, a NOT_NAME_WORD
   or a title, or part of a date, number or organization entity. At most
   two words per side. Here the tagger does tell "PAID" (VERB) from
   "LAKSHMI" (PROPN).

Extending can only ever mask more, never less, so where it guesses wrong
the cost is a second code, not a leak. Trimming is the step that can
unmask a word, which is why it uses a fixed list and not a guess.
"""

from __future__ import annotations

import re

from presidio_analyzer import RecognizerResult
from spacy.lang.en.stop_words import STOP_WORDS

# Never a person's name, in the chat and documents this tool sees.
# Lower-case; compared against a word with surrounding punctuation removed.
_GREETINGS = """
    hi hello hey hiya dear dearest respected thanks thank thx regards namaste namaskar
    namaskaram vanakkam greetings congrats congratulations welcome bye goodbye cheers
    attn attention
"""
_CONTACT_VERBS = """
    ping call ask tell email e-mail mail message msg text sms whatsapp dm meet contact forward
    fwd cc bcc remind invite inform notify update pay send tag loop reply respond
    congratulate introduce connect schedule visit alert ring nudge greet help let cancel
    approve check brief escalate assign add include transfer refund charge credit debit
    request confirm told said asked called met paid sent emailed messaged pinged informed
    reminded invited thanked
"""
_ROLES = """
    customer client patient employee applicant borrower guarantor nominee holder cardholder
    beneficiary payee payer remitter sender recipient receiver tenant landlord owner manager
    director doctor sir madam maam mam team colleague candidate member user assessee taxpayer
    investor depositor insured proposer policyholder name prof professor adv advocate officer
    agent boss friend brother sister uncle aunty aunt bhai bhaiya didi cousin son daughter
    father mother wife husband spouse guardian ji jee sahab saheb sahib garu
"""
# Titles are trimmed only before a name. After one, some are part of it
# ("Priya Kumari", "Lakshmi Sri").
_TITLES = "mr mrs ms miss mx shri sri smt kumari kum er capt col maj lt rev s/o d/o w/o c/o h/o"
_FUNCTION_WORDS = """
    please pls plz kindly per via from to by with and or for about of the a an this that these
    those my our your his her their its re fw subject note ok okay yes no also then so but if
    when where who whom whose did does do is are was were has have had can could should would
    shall must on at in into onto as than
"""
_TIME_WORDS = """
    today tomorrow yesterday tonight morning evening afternoon noon night week month year
    monday tuesday wednesday thursday friday saturday sunday mon tue tues wed thu thur thurs
    fri sat january february march july september october november december feb apr jun
    jul aug sep sept oct nov dec
"""
_STATEMENT_WORDS = """
    account savings current bank branch address date number no pan aadhaar mobile phone email
    id dob upi neft rtgs imps ifsc micr txn ref cheque chq atm pos ach ecs nach cash clg
    interest salary amount balance total statement details city state pin pincode gst gstin
    tan cin folio policy loan card dr cr sbi hdfc icici axis kotak pnb idbi canara iob uco
    traders enterprises industries pvt ltd limited private llp co company corp services
    solutions agency agencies stores store mart hospital clinic pharmacy medicals school
    college university trust foundation associates infotech technologies systems motors
    jewellers textiles foods hotel restaurant
"""

# Software and format names spaCy tags as people in instruction text
# ("Markdown does NOT render", "run Docker"), found in a real system prompt.
# Only words that are never given names: Ruby, Julia, Crystal, Claude and
# the like are left out.
_TECHNICAL_WORDS = """
    markdown python javascript typescript json yaml toml html css xml csv pdf sql bash zsh shell
    powershell linux ubuntu debian fedora windows macos android ios github gitlab bitbucket git
    docker kubernetes podman terraform ansible nginx redis postgres postgresql mysql sqlite
    mongodb node nodejs npm pip conda jupyter vscode vim neovim emacs tmux wsl chrome chromium
    firefox safari gmail outlook slack discord telegram whatsapp zoom notion obsidian excel
    powerpoint onedrive dropbox api cli gui url http https ssh llm gpt chatgpt openai litellm
    ollama sdk ide repo readme changelog regex unicode ascii emoji webhook oauth jwt
"""

# Headings and labels in instructions and notes, often in bold ("**Goal:**",
# "**Pros**", "**Language:** Kannada"). Once spaCy reads them without their
# emphasis marks (emphasis.py), it tags some as people (0.4.3). Words that
# are also given names (Grace, Joy, Hope, Frank, Bill) are left out.
_LABEL_WORDS = """
    goal goals objective objectives pros cons summary tldr overview context background tone
    rules boundaries example examples important warning caution reminder todo status priority
    deadline task tasks answer question sources output input format style persona vibe
    continuity heartbeat
    hindi english kannada tamil telugu malayalam marathi bengali bangla gujarati punjabi odia
    oriya urdu sanskrit konkani assamese hinglish
"""

NOT_NAME_WORDS = frozenset(
    " ".join(
        [
            _GREETINGS,
            _CONTACT_VERBS,
            _ROLES,
            _FUNCTION_WORDS,
            _TIME_WORDS,
            _STATEMENT_WORDS,
            _TECHNICAL_WORDS,
            _LABEL_WORDS,
        ]
    ).split()
)
TITLES = frozenset(_TITLES.split())

# spaCy entity types a word may belong to and still be read as part of an
# adjacent name. Dates, numbers and organizations are excluded (a bank or
# an employer next to a name is not part of it); places are not, because
# surnames that are also place names get tagged GPE.
_NOT_NAME_ENTITY_TYPES = frozenset(
    {"DATE", "TIME", "MONEY", "CARDINAL", "ORDINAL", "PERCENT", "QUANTITY", "ORG"}
)

_MAX_EXTENSION_WORDS = 2
# Markdown's emphasis and code marks count too: spaCy reads
# "**Ravi Kumar** will call" as the PERSON "Ravi Kumar*" (0.4.1).
_EDGE_PUNCTUATION = ".,:;!?\"'()[]{}<>“”‘’*_`~"
_WORD = re.compile(r"\S+")

# spaCy's PERSON span swallows a trailing possessive ("Ravi Kumar's" -> one
# span, confirmed by direct probe). Left in, it becomes part of the
# mapping-store key, so "Ravi Kumar" and "Ravi Kumar's" would get two
# different codes for one person, and reversal would reinsert the "'s"
# after a code the LLM already wrote as "PERSON_A's".
_POSSESSIVE_SUFFIX = re.compile(r"['’][sS]?$")


def word_key(word: str) -> str:
    return word.strip(_EDGE_PUNCTUATION).casefold()


def is_not_a_name_word(word: str, *, leading: bool) -> bool:
    """Whether `word` is never part of a name at that edge of one: the
    first word of a name (`leading`) or the last."""
    key = word_key(word)
    return not any(c.isalpha() for c in key) or key in NOT_NAME_WORDS or (leading and key in TITLES)


def trim_span(text: str, start: int, end: int) -> tuple[int, int] | None:
    """(start, end) with a trailing possessive and NOT_NAME_WORDS removed
    from both edges, or None when nothing of the name is left."""
    match = _POSSESSIVE_SUFFIX.search(text[start:end])
    if match:
        end = start + match.start()
    words = [(start + m.start(), start + m.end()) for m in _WORD.finditer(text[start:end])]
    while words and is_not_a_name_word(text[words[0][0] : words[0][1]], leading=True):
        words.pop(0)
    while words and is_not_a_name_word(text[words[-1][0] : words[-1][1]], leading=False):
        words.pop()
    if not words:
        return None
    start, end = words[0][0], words[-1][1]
    # Punctuation left at the edges of the kept words ("Kumar," after
    # trimming a trailing "sir") is not part of the name.
    while start < end and text[start] in _EDGE_PUNCTUATION:
        start += 1
    while end > start and text[end - 1] in _EDGE_PUNCTUATION:
        end -= 1
    return (start, end) if start < end else None


def _has_digit(text: str) -> bool:
    return any(c.isdigit() for c in text)


def name_part(text: str, start: int, end: int) -> tuple[int, int] | None:
    """The part of a PERSON span that can be a name, trimmed (trim_span),
    or None.

    A person's name never contains a digit, and spaCy tags short,
    sentence-less strings as PERSON with high confidence - an AIS quarter
    label, "Q4(Jan-Mar)", came back PERSON at 0.85. But spaCy also runs a
    name on into the identifier after it: "Ravi Kumar PAN ABCPE1234F" and
    "Ravi Kumar UPI 9876543210" are each one PERSON span. Dropping such a
    span (0.3.0) left the name in the clear. So the span is cut at its
    first word with a digit, and the words before it are kept if they are
    still a plausible name: two words or more, or a name followed by a
    label that was trimmed off ("Ravi PAN ..."). A lone word before a
    number, with no label ("Form 16"), is dropped as before."""
    words = [(start + m.start(), start + m.end()) for m in _WORD.finditer(text[start:end])]
    first_digit = next((i for i, (s, e) in enumerate(words) if _has_digit(text[s:e])), None)
    if first_digit is None:
        return trim_span(text, start, end)
    before = words[:first_digit]
    if not before:
        return None
    trimmed = trim_span(text, before[0][0], before[-1][1])
    if trimmed is None:
        return None
    kept_words = len(_WORD.findall(text[trimmed[0] : trimmed[1]]))
    last_word = text[before[-1][0] : before[-1][1]]
    if kept_words >= 2 or is_not_a_name_word(last_word, leading=False):
        return trimmed
    return None


def _case_matches(name: str, word: str) -> bool:
    """Title-case joins a name written with lower-case letters; all caps
    joins an all-caps name. So an acronym ("PAN", "UPI") never joins
    "Ravi Kumar", and nothing joins a name written all in lower case."""
    if not word[0].isupper() or not any(c.isupper() for c in name):
        return False
    if any(c.islower() for c in name):
        return any(c.islower() for c in word[1:])
    return word.isupper()


def _joins_name(token, name: str) -> bool:
    return (
        token.pos_ == "PROPN"
        and token.is_alpha
        and len(token.text) >= 2
        and _case_matches(name, token.text)
        and token.lower_ not in STOP_WORDS
        and token.lower_ not in NOT_NAME_WORDS
        and token.lower_ not in TITLES
        and token.ent_type_ not in _NOT_NAME_ENTITY_TYPES
    )


def _separated_by_spaces(text: str, left_end: int, right_start: int) -> bool:
    gap = text[left_end:right_start]
    return bool(gap) and all(c in " \t" for c in gap)


def extend_span(text: str, start: int, end: int, doc) -> tuple[int, int]:
    """(start, end) widened over adjacent words that look like more of the
    same name (see the module docstring). `doc` is the spaCy Doc of
    `text`; without one the span is returned unchanged."""
    if doc is None:
        return start, end
    span = doc.char_span(start, end, alignment_mode="expand")
    if span is None or len(span) == 0:
        return start, end
    name = text[start:end]

    right = span.end
    for _ in range(_MAX_EXTENSION_WORDS):
        if right >= len(doc):
            break
        token = doc[right]
        if not (_separated_by_spaces(text, end, token.idx) and _joins_name(token, name)):
            break
        end = token.idx + len(token.text)
        right += 1

    left = span.start - 1
    for _ in range(_MAX_EXTENSION_WORDS):
        if left < 0:
            break
        token = doc[left]
        token_end = token.idx + len(token.text)
        if not (_separated_by_spaces(text, token_end, start) and _joins_name(token, name)):
            break
        start = token.idx
        left -= 1
    return start, end


def refine_person_results(text: str, results: list[RecognizerResult], doc) -> list[RecognizerResult]:
    """PERSON results cut to their name part (name_part), extended (see the
    module docstring), implausible ones dropped, and overlapping ones merged into one span
    with the higher score. Other entity types pass through unchanged."""
    people: list[RecognizerResult] = []
    others: list[RecognizerResult] = []
    for r in results:
        if r.entity_type != "PERSON":
            others.append(r)
            continue
        trimmed = name_part(text, r.start, r.end)
        if trimmed is None:
            continue
        start, end = extend_span(text, *trimmed, doc)
        people.append(RecognizerResult("PERSON", start, end, r.score, r.analysis_explanation, r.recognition_metadata))

    merged: list[RecognizerResult] = []
    for r in sorted(people, key=lambda r: (r.start, -r.end)):
        if merged and r.start < merged[-1].end:
            last = merged[-1]
            last.end = max(last.end, r.end)
            last.score = max(last.score, r.score)
        else:
            merged.append(r)
    return others + merged
