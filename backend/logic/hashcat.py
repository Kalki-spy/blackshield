#!/usr/bin/env python3
"""
Hashcat-style Password Cracker Backend
Pure Python — no external dependencies

Endpoints:
    GET  /health   — health check
    POST /crack    — crack a hash
        body: { hash, hash_type, wordlist?, mode? }
"""

import json
import hashlib
import itertools
import string
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

import os
PORT = int(os.environ.get("PORT", 8771))

# ── Wordlist (rockyou-inspired top 500+) ─────────────────────────────────────
WORDLIST = [
    # Top rockyou passwords
    "password","123456","12345678","1234","12345","dragon","qwerty","abc123",
    "mustang","michael","shadow","baseball","iloveyou","master","jennifer",
    "monkey","696969","letmein","trustno1","superman","batman","jordan",
    "harley","1234567","hunter","buster","soccer","thomas","ranger","tigger",
    "robert","access","snoopy","joshua","midnight","vanilla","cheese","hello",
    "charlie","donald","diamond","maverick","samsung","andrea","smokey",
    "joseph","mercedes","dakota","arsenal","eagles","simba","apples","mother",
    "badboy","pass","666666","purple","jessica","zxcvbn","ginger","hammer",
    "summer","corvette","dave","matrix","secret","falcon","taylor","111111",
    "131313","123123","222222","1q2w3e","qazwsx","monkey1","whatever",
    "golden","password1","loveme","sunshine","princess","welcome","money",
    "freedom","coffee","turtle","angel","lucky","chocolate","cookie","hello1",
    "scorpion","computer","internet","chicken","tennis","ferrari","yankees",
    "guitar","boston","tiger","killer","silver","blazer","please","abcdef",
    "trouble","simple","destiny","sebastian","yankee","power","cool","cowboy",
    "camaro","dallas","pepper","alexis","christian","thomas1","soccer1",
    "hockey","football","baseball1","basketball","tigger1","compaq","hacker",
    "wizard","super","ninja","gaming","pokemon","pikachu","naruto","vegeta",
    "admin","root","toor","test","demo","guest","user","login","pass123",
    "pass1234","admin123","root123","alpine","ubuntu","linux","windows",
    "letmein1","welcome1","password!","Password1","P@ssw0rd","Admin@123",
    "winter2023","summer2023","spring2023","fall2023","winter2024","summer2024",
    "january","february","march","april","may","june","july","august",
    "september","october","november","december",
    "1234567890","0987654321","987654321","00000000","11111111","12341234",
    "qwerty123","azerty","zxcvbn1","1q2w3e4r","qwertyuiop","asdfghjkl",
    "sunshine1","shadow1","master1","dragon1","batman1","superman1",
    "password123","password12","iloveyou1","iloveyou2","princess1",
    "passw0rd","p@ssword","p@$$word","p455w0rd","pa$$w0rd",
    "letmein123","welcome123","admin@123","user@123","guest@123",
    "blackshield","cybersec","pentest","hacking","exploit","payload",
    "meterpreter","mimikatz","nmap","metasploit","kali","burpsuite",
    "changeme","default","system","service","manager","network","security",
    "secret123","secret1","mysecret","topsecret","classified",
    "abc1234","abc12345","abcd1234","zxcvbnm","asdfjkl","qwerasdf",
    "superman123","batman123","spiderman","ironman","hulksmash","avengers",
    "starwars","r2d2","c3po","jediknight","darkside","vader","luke",
    "gandalf","frodo","hobbit","mordor","rivendell",
    "google","facebook","twitter","linkedin","instagram","snapchat","tiktok",
    "apple","amazon","netflix","spotify","discord","reddit","github",
    "football1","soccer12","hockey12","baseball2","basketball1",
    "chelsea","arsenal1","liverpool","barcelona","madrid","juventus",
    "1password","2password","3password","mypassword","yourpassword",
    "newpassword","oldpassword","temppass","testpass","devpass",
    "monday","tuesday","wednesday","thursday","friday","saturday","sunday",
    "spring","summer","autumn","winter","season","holiday","vacation",
    "love123","love1234","iloveyou123","loveyou","mylove","sweetheart",
    "family","friends","home","house","school","college","university",
    "dog","cat","fish","bird","horse","rabbit","hamster","puppy","kitty",
    "blue","red","green","yellow","black","white","purple","orange","pink",
    "happy","sad","angry","excited","bored","tired","sleepy",
    "123qwe","qwe123","asd123","zxc123","1qaz2wsx","1qazxsw2",
    "password2","password3","password4","password5","password9","password0",
    "abc","abcd","abcde","abcdef","abcdefg","aaaaaaaa","bbbbbbbb",
    "1111","2222","3333","4444","5555","6666","7777","8888","9999","0000",
    "11111","22222","33333","44444","55555","66666","77777","88888","99999",
    "112233","123321","654321","321654","147258","258369","369258","159753",
    "admin1","admin12","admin1234","admin12345","administrator",
    "root1","root12","root1234","superuser","sysadmin","webmaster",
    "tomcat","apache","nginx","mysql","postgres","oracle","mongodb","redis",
    "cisco","juniper","router","switch","firewall","gateway","proxy",
    "morning","evening","night","afternoon","today","tomorrow","yesterday",
    "pass@123","pass#123","pass$123","password@1","Password@1","Password#1",
    "test123","test1234","testing","tester","testuser","testpass",
    "india","china","russia","america","england","france","germany","japan",
    "london","paris","tokyo","berlin","moscow","beijing","mumbai","delhi",
]

# ── Hash Detection ────────────────────────────────────────────────────────────

HASH_SIGNATURES = {
    32:  ["md5"],
    40:  ["sha1"],
    56:  ["sha224"],
    64:  ["sha256"],
    96:  ["sha384"],
    128: ["sha512"],
}

HASH_ALGORITHMS = {
    "md5":    hashlib.md5,
    "sha1":   hashlib.sha1,
    "sha224": hashlib.sha224,
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
}

def detect_hash_type(hash_str: str) -> list:
    h = hash_str.strip().lower()
    length = len(h)
    if not all(c in "0123456789abcdef" for c in h):
        return ["unknown"]
    return HASH_SIGNATURES.get(length, ["unknown"])

def compute_hash(algo: str, plaintext: str) -> str:
    fn = HASH_ALGORITHMS.get(algo)
    if not fn:
        return ""
    return fn(plaintext.encode()).hexdigest()

# ── Cracking Modes ────────────────────────────────────────────────────────────

MUTATIONS = [
    lambda w: w,
    lambda w: w.capitalize(),
    lambda w: w.upper(),
    lambda w: w + "1",
    lambda w: w + "12",
    lambda w: w + "123",
    lambda w: w + "1234",
    lambda w: w + "12345",
    lambda w: w + "!",
    lambda w: w + "@",
    lambda w: w + "#",
    lambda w: w + "2023",
    lambda w: w + "2024",
    lambda w: "1" + w,
    lambda w: w + "0",
    lambda w: w + "00",
    lambda w: w.capitalize() + "1",
    lambda w: w.capitalize() + "!",
    lambda w: w.capitalize() + "123",
    lambda w: w.replace("a","@").replace("e","3").replace("i","1").replace("o","0"),
    lambda w: w.upper() + "1",
    lambda w: w.upper() + "!",
    lambda w: w + w,
]

def crack_wordlist(hash_str: str, algo: str, custom_words: list = None) -> dict:
    words = custom_words if custom_words else WORDLIST
    hash_str = hash_str.strip().lower()
    attempts = 0
    start = time.time()

    for word in words:
        for mutate in MUTATIONS:
            attempts += 1
            variant = mutate(word)
            if compute_hash(algo, variant) == hash_str:
                return {"cracked": True, "plaintext": variant, "attempts": attempts,
                        "time": round(time.time() - start, 4), "method": "wordlist+mutation"}

    return {"cracked": False, "attempts": attempts,
            "time": round(time.time() - start, 4), "method": "wordlist"}


def crack_bruteforce(hash_str: str, algo: str, max_len: int = 5) -> dict:
    charset = string.digits + string.ascii_lowercase
    hash_str = hash_str.strip().lower()
    attempts = 0
    start = time.time()
    MAX_TIME = 10

    for length in range(1, max_len + 1):
        for combo in itertools.product(charset, repeat=length):
            if time.time() - start > MAX_TIME:
                return {"cracked": False, "attempts": attempts,
                        "time": round(time.time() - start, 4), "method": "bruteforce",
                        "note": f"Time limit reached — password not found in {max_len}-char brute-force range"}
            attempts += 1
            word = "".join(combo)
            if compute_hash(algo, word) == hash_str:
                return {"cracked": True, "plaintext": word, "attempts": attempts,
                        "time": round(time.time() - start, 4), "method": "bruteforce"}

    return {"cracked": False, "attempts": attempts,
            "time": round(time.time() - start, 4), "method": "bruteforce"}


def crack_hash(hash_str: str, hash_type: str = "auto", mode: str = "both",
               custom_words: list = None) -> dict:
    hash_str = hash_str.strip()
    if not hash_str:
        return {"error": "No hash provided"}

    if hash_type == "auto" or not hash_type:
        detected = detect_hash_type(hash_str)
        if detected == ["unknown"]:
            return {"error": "Cannot detect hash type — make sure it is a valid hex hash"}
        algos = detected
    else:
        algos = [hash_type.lower()]
        if algos[0] not in HASH_ALGORITHMS:
            return {"error": f"Unsupported hash type: {hash_type}"}

    detected_types = detect_hash_type(hash_str)
    total_attempts = 0
    total_time = 0.0

    for algo in algos:
        if mode == "bruteforce":
            res = crack_bruteforce(hash_str, algo)
        elif mode == "wordlist":
            res = crack_wordlist(hash_str, algo, custom_words)
        else:  # both
            res = crack_wordlist(hash_str, algo, custom_words)
            total_attempts += res.get("attempts", 0)
            total_time += res.get("time", 0)
            if not res["cracked"]:
                res2 = crack_bruteforce(hash_str, algo)
                total_attempts += res2.get("attempts", 0)
                total_time += res2.get("time", 0)
                if res2["cracked"]:
                    res = res2
                    res["attempts"] = total_attempts
                    res["time"] = round(total_time, 4)
            else:
                res["attempts"] = total_attempts
                res["time"] = round(total_time, 4)

        if res.get("cracked"):
            break

    if mode != "both":
        total_attempts = res.get("attempts", 0)
        total_time = res.get("time", 0)

    return {
        "hash":           hash_str,
        "hash_type":      algos[0],
        "detected_types": detected_types,
        "mode":           mode,
        "cracked":        res.get("cracked", False),
        "plaintext":      res.get("plaintext"),
        "attempts":       total_attempts,
        "time_seconds":   round(total_time, 4),
        "method":         res.get("method", ""),
        "note":           res.get("note"),
    }


# ── HTTP Handler ──────────────────────────────────────────────────────────────

