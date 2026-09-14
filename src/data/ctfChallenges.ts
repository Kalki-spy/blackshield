// Real, solvable CTF challenges. Each one has a genuine flag you can only
// get by actually working through the puzzle (decoding, cipher-breaking,
// log-hunting, steganography, etc.) — nothing here is a fake placeholder.
// There's no backend for multiplayer leaderboards yet, so this is
// single-player: completion and points are tracked locally per account,
// and there's no fabricated "solves" counter since that would imply a
// live competitive backend that doesn't exist.
//
// Four challenges (needle-in-the-log, view-source, hidden-in-plain-sight,
// jwt-peek) ship with a downloadable asset instead of an inline brief.
// Those files live in /public/ctf/ — copy them into the app's public
// folder so `assetUrl` resolves:
//   public/ctf/access.log
//   public/ctf/portal.html
//   public/ctf/hidden-in-plain-sight.png

export interface CTFChallenge {
  id: string;
  title: string;
  category: string;
  difficulty: "Beginner" | "Intermediate" | "Advanced";
  points: number;
  brief: string;
  hint: string;
  flag: string; // checked case-sensitively, trimmed
  assetUrl?: string; // optional downloadable/openable file under /ctf/
  assetLabel?: string; // link text for the asset (defaults to "Download asset")
}

export const ctfChallenges: CTFChallenge[] = [
  {
    id: "encoded-message",
    title: "Encoded Message",
    category: "Web Exploitation",
    difficulty: "Beginner",
    points: 100,
    brief: "An API response was intercepted mid-transit. The payload below was Base64-encoded before transmission — decode it to recover the flag.\n\nQkxBQ0tTSElFTER7YjQ1ZTY0X2lzX25vdF9lbmNyeXB0aW9ufQ==",
    hint: "Base64 decodes to plain text — try an online decoder or `atob()` in a browser console.",
    flag: "BLACKSHIELD{b45e64_is_not_encryption}",
  },
  {
    id: "open-door",
    title: "Open Door",
    category: "Network",
    difficulty: "Beginner",
    points: 100,
    brief: "A misconfigured service left this response header block world-readable. Somewhere in it is a flag hiding in plain sight.\n\nHTTP/1.1 200 OK\nServer: nginx/1.18.0\nX-Powered-By: Express\nX-Debug-Flag: BLACKSHIELD{h34d3rs_l34k_m0r3_th4n_y0u_th1nk}\nContent-Type: application/json",
    hint: "Read every header line carefully — not just the ones that look important.",
    flag: "BLACKSHIELD{h34d3rs_l34k_m0r3_th4n_y0u_th1nk}",
  },
  {
    id: "weak-cipher",
    title: "Weak Cipher",
    category: "Cryptography",
    difficulty: "Intermediate",
    points: 250,
    brief: "A legacy system encrypts its secrets with a Caesar cipher, shift unknown. Recover the plaintext flag from this ciphertext:\n\nOYNPXFUVRYQ{pnrfne_fyvqrf_naq_qbqtrf}",
    hint: "There are only 25 possible shifts to try — or notice this one's shift 13, better known as ROT13.",
    flag: "BLACKSHIELD{caesar_slides_and_dodges}",
  },
  {
    id: "packet-trail",
    title: "Packet Trail",
    category: "Forensics",
    difficulty: "Intermediate",
    points: 250,
    brief: "A captured request had its flag URL-encoded before logging. Decode it to recover the flag:\n\nBLACKSHIELD%7Bpercent_encoding_hides_in_plain_sight%7D",
    hint: "URL/percent-decode the string — %7B is '{' and %7D is '}'.",
    flag: "BLACKSHIELD{percent_encoding_hides_in_plain_sight}",
  },
  {
    id: "blind-extraction",
    title: "Blind Extraction",
    category: "Web Exploitation",
    difficulty: "Advanced",
    points: 400,
    brief: "A backup script wrote this flag to disk backwards to 'obfuscate' it. Reverse it to recover the original:\n\n}gnidaer_esrever_ta_doog_eb_dluohs_uoy{DLEIHSKCALB",
    hint: "Reverse the entire string character by character.",
    flag: "BLACKSHIELD{you_should_be_good_at_reverse_reading}",
  },
  {
    id: "silent-service",
    title: "Silent Service",
    category: "Network",
    difficulty: "Advanced",
    points: 400,
    brief: "A service on a non-standard port responds only in hex. Decode this hex dump to recover the flag:\n\n424c41434b534849454c447b6865785f69735f6a7573745f6279746573217d",
    hint: "Each pair of hex digits is one ASCII character.",
    flag: "BLACKSHIELD{hex_is_just_bytes!}",
  },
  {
    id: "view-source",
    title: "View Source",
    category: "Web Exploitation",
    difficulty: "Beginner",
    points: 150,
    brief: "A staging build of an internal portal shipped to the wrong place. The rendered page looks empty — but rendered isn't the same as sent. Open the page and look at what the browser actually downloaded.",
    hint: "Right-click → View Page Source (or Ctrl+U). Read every line, including comments.",
    flag: "blackshield{h1dd3n_1n_html}",
    assetUrl: "/ctf/portal.html",
    assetLabel: "Open staging portal",
  },
  {
    id: "needle-in-the-log",
    title: "Needle in the Log",
    category: "Forensics",
    difficulty: "Intermediate",
    points: 300,
    brief: "A production access log was pulled for a routine audit. Buried among ~180 completely ordinary requests is one anomalous line carrying an encoded flag. Find it, then decode what it's hiding.",
    hint: "grep is your friend. Look for a request that doesn't fit the pattern of the rest — an unusual client, an unusual path, or a suspiciously long query string — then Base64-decode its payload.",
    flag: "blackshield{gr3p_1s_y0ur_fr13nd}",
    assetUrl: "/ctf/access.log",
    assetLabel: "Download access.log",
  },
  {
    id: "hidden-in-plain-sight",
    title: "Hidden in Plain Sight",
    category: "Steganography",
    difficulty: "Advanced",
    points: 450,
    brief: "This 64×64 image looks like pure random noise — and visually, it is. But the noise was generated around a message hidden in the least-significant bits of one color channel. Extract it to recover the flag.",
    hint: "Pull the least significant bit of every red channel value, in pixel order, and pack each group of 8 bits into a byte. A short Python + Pillow script (or any LSB-stego tool) will do it.",
    flag: "blackshield{pix3ls_d0nt_l13}",
    assetUrl: "/ctf/hidden-in-plain-sight.png",
    assetLabel: "Download image",
  },
  {
    id: "jwt-peek",
    title: "JWT Peek",
    category: "Web Exploitation",
    difficulty: "Intermediate",
    points: 250,
    brief: "A session token was sniffed off an unencrypted debug endpoint. JWTs aren't encrypted — only signed — so the payload is there for anyone who looks.\n\neyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJndWVzdCIsInJvbGUiOiJ2aWV3ZXIiLCJmbGFnIjoiYmxhY2tzaGllbGR7and0X3BheTEwYWRzX2FyZW50X3MzY3JldH0ifQ.fake_sig_not_needed_for_this_challenge",
    hint: "A JWT is header.payload.signature — each of the first two parts is separately Base64URL-encoded JSON. Decode the middle part.",
    flag: "blackshield{jwt_pay10ads_arent_s3cret}",
  },
];

export const totalPoints = ctfChallenges.reduce((sum, c) => sum + c.points, 0);