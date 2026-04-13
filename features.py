import math
from collections import Counter

HIGH_RISK_TLDS = {
    'tk':0.95,'ml':0.95,'cf':0.95,'ga':0.95,'gq':0.95,
    'xyz':0.85,'top':0.85,'click':0.80,'loan':0.90,'work':0.75,
    'online':0.70,'site':0.70,'live':0.65,'club':0.60,'info':0.50,
    'ink':0.60,'cc':0.65,'pw':0.70,'su':0.65,'biz':0.50
}

BRANDS = [
    'google','paypal','amazon','apple','microsoft','facebook',
    'instagram','twitter','netflix','hdfc','sbi','icici','paytm',
    'flipkart','whatsapp','youtube','linkedin','dropbox','adobe',
    'chase','bankofamerica','wellsfargo','citibank','yahoo',
    'outlook','office365','icloud','ebay','walmart','coinbase','binance'
]

PHISH_KEYWORDS = [
    'login','secure','account','update','verify','confirm','bank',
    'payment','invoice','alert','suspended','unusual','access',
    'recover','support','helpdesk','auth','signin','password','reset',
    'validate','unlock','limited','urgent','immediate','click','free'
]

IMPOSSIBLE_BIGRAMS = {
    'qx','qz','qj','zx','zj','vx','vq','wx','wq',
    'bx','cx','dx','fx','gx','hx','jx','kx','lx',
    'mx','nx','px','rx','sx','tx'
}

COMMON_BIGRAMS = {
    'th','he','in','er','an','re','on','en','at','es',
    'st','or','te','of','ed','is','it','al','ar','to'
}

def levenshtein(a, b):
    if a == b: return 0
    if len(a) < len(b): a, b = b, a
    prev = list(range(len(b)+1))
    for i, ca in enumerate(a):
        curr = [i+1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j+1]+1, curr[j]+1, prev[j]+(ca!=cb)))
        prev = curr
    return prev[-1]

def jaro_winkler(s1, s2):
    if s1 == s2: return 1.0
    l1, l2 = len(s1), len(s2)
    if l1 == 0 or l2 == 0: return 0.0
    match_dist = max(l1, l2) // 2 - 1
    if match_dist < 0: match_dist = 0
    s1m = [False]*l1
    s2m = [False]*l2
    matches = 0
    for i in range(l1):
        start = max(0, i-match_dist)
        end = min(i+match_dist+1, l2)
        for j in range(start, end):
            if s2m[j] or s1[i] != s2[j]: continue
            s1m[i] = s2m[j] = True
            matches += 1
            break
    if matches == 0: return 0.0
    k = 0
    trans = 0
    for i in range(l1):
        if not s1m[i]: continue
        while not s2m[k]: k += 1
        if s1[i] != s2[k]: trans += 1
        k += 1
    jaro = (matches/l1 + matches/l2 + (matches-trans/2)/matches) / 3
    prefix = sum(1 for i in range(min(4,l1,l2)) if s1[i]==s2[i])
    return jaro + prefix * 0.1 * (1 - jaro)

def extract_features(domain: str) -> list:
    domain = domain.lower().strip()
    # remove protocol if present
    if '://' in domain:
        domain = domain.split('://')[1]
    domain = domain.split('/')[0]
    
    parts = domain.split('.')
    tld = parts[-1] if len(parts) > 1 else ''
    sld = parts[0] if parts else domain
    vowels = set('aeiou')
    hex_chars = set('0123456789abcdef')

    # entropy
    freq = Counter(sld)
    p = [v/len(sld) for v in freq.values()] if sld else [1]
    entropy = -sum(x*math.log2(x) for x in p if x > 0)

    # ngram randomness
    bigrams = [sld[i:i+2] for i in range(len(sld)-1)]
    ngram_rand = 1-(sum(1 for b in bigrams if b in COMMON_BIGRAMS)/max(len(bigrams),1))

    # impossible bigrams
    impossible = sum(1 for b in bigrams if b in IMPOSSIBLE_BIGRAMS)
    char_continuity = impossible / max(len(bigrams),1)

    # repeated chars
    repeated = sum(1 for i in range(1,len(sld)) if sld[i]==sld[i-1])
    repeated_score = repeated / max(len(sld),1)

    # max consecutive consonants
    max_cons, curr = 0, 0
    for c in sld:
        if c.isalpha() and c not in vowels:
            curr += 1; max_cons = max(max_cons, curr)
        else: curr = 0

    # tld risk
    tld_risk = HIGH_RISK_TLDS.get(tld, 0.1)

    # keywords
    kw_score = sum(1 for kw in PHISH_KEYWORDS if kw in domain)/len(PHISH_KEYWORDS)

    # lookalike levenshtein
    min_lev = min((levenshtein(sld, b) for b in BRANDS), default=99)
    lookalike = 1.0 if 0 < min_lev <= 2 else (0.5 if min_lev <= 4 else 0.0)

    # jaro winkler
    jw = max((jaro_winkler(sld, b) for b in BRANDS), default=0.0)
    jw_score = jw if (jw > 0.85 and sld not in BRANDS) else 0.0

    return [
        min(len(domain)/63, 1.0),                                              # length
        min((len(parts)-1)/5, 1.0),                                            # num_subdomains
        sum(c in vowels for c in sld)/max(len(sld),1),                         # vowel_ratio
        sum(c.isalpha() and c not in vowels for c in sld)/max(len(sld),1),     # consonant_ratio
        sum(c.isdigit() for c in sld)/max(len(sld),1),                         # digit_ratio
        min(sum(not c.isalnum() for c in sld)/10, 1.0),                        # special_char_count
        min(entropy/4, 1.0),                                                    # entropy
        ngram_rand,                                                             # ngram_randomness
        repeated_score,                                                         # repeated_char_score
        tld_risk,                                                               # tld_risk
        kw_score,                                                               # suspicious_keyword_score
        lookalike,                                                              # lookalike_score
        min(max_cons/8, 1.0),                                                   # max_consecutive_consonants
        len(set(sld))/max(len(sld),1),                                          # unique_char_ratio
        sum(1 for c in sld if c in hex_chars)/max(len(sld),1),                 # hex_char_ratio
        jw_score,                                                               # jaro_winkler_score
        char_continuity,                                                        # char_continuity_score
    ]
