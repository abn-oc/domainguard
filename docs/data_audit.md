# Data audit

Audit performed 2026-11-24. URLs and terms were checked by web search and by
actually downloading the files; hashes, sizes and row counts come from
`data/manifest.json`, which is written by `domainguard.data.download`.

## Tranco (benign)

- Metadata URL: <https://tranco-list.eu/api/lists/date/latest>
- Download URL: <https://tranco-list.eu/download/8PW6V/1000000>
- Pinned list ID: **8PW6V**, created 2026-11-22T22:00:01 UTC.
- Size: 22,689,419 bytes; 1,000,000 rows; SHA-256 begins `e809da9d6763`.
- Format verified: `rank,domain` CSV, no header, bare registrable domains.
- Terms: the site is a research service; it states no single licence for the
  combined list and credits upstream providers (CrUX CC BY 4.0/CC BY-SA 4.0
  depending on source, Majestic CC BY 3.0, Cloudflare Radar CC BY-NC 4.0,
  Cisco Umbrella free of charge, Farsight default list only). We use the list
  for academic research only, do not redistribute the raw list, and cite the
  list ID. <https://tranco-list.eu/>
- API note: the `download` field already contains the full 1M prefix; appending
  `/1000000` again gives 404. This differs from the handout's assumed URL form.

## Phishing.Database (main phishing source)

- Links URL: <https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE.txt>
  - 65,823,890 bytes; 789,054 rows; SHA-256 begins `be4a179b3ac9`.
  - Last commit touching this file: **2025-12-22T20:39:14Z** (about 11 months
    stale at audit time).
- Domains URL: <https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt>
  - 11,023,128 bytes; 392,178 rows; SHA-256 begins `70c6c2e24e6b`.
  - Last commit touching this file: **2026-10-02T15:30:28Z**.
- License: MIT. <https://github.com/Phishing-Database/Phishing.Database/blob/master/LICENSE>
- Blocked check: the larger historical `ALL-phishing-links.lst` is not present
  in the GitHub repository; the official mirror
  `https://phish.co.za/latest/ALL-phishing-links.lst` returned HTTP 503.
  Per the handout we did not substitute another source; the two ACTIVE files
  are used instead and the shortfall is recorded in `docs/results.md`.
- Known label noise: some entries are phishing pages on compromised or free
  hosts. Free-host rows are flagged in the data and reported separately.

## OpenPhish community feed (optional phishing source)

- Feed URL: <https://openphish.com/feed.txt> (verified reachable).
- Size: 14,762 bytes; 300 rows (a rolling ~12-hour window, not a sample of all
  phishing). SHA-256 begins `5711deadfde6`.
- Terms read: <https://www.openphish.com/terms.html>. Free services are for
  personal, academic or independent research that does not support business
  operations. Redistribution and commercial use are prohibited without written
  consent. <https://www.openphish.com/phishing_feeds.html>
- Decision: download allowed for this student research project. The raw feed
  stays in gitignored `data/raw/` and is never committed or redistributed.

## ExtraHop DGA dataset (external test only)

- Repository: <https://github.com/ExtraHop/DGA-Detection-Training-Dataset>, MIT
  license: <https://github.com/ExtraHop/DGA-Detection-Training-Dataset/blob/main/LICENSE>
- Actual file in the repository: **`dga-training-data-encoded.json.gz`**
  (the README calls it `dga-training-data-encoded-v3.json.gz`; that name does
  not exist in the repository). It is a Git LFS object, resolved via GitHub's
  LFS batch API. Downloaded size: 170,860,023 bytes; 16,246,011 newline
  characters including a 6-line copyright header; SHA-256 begins
  `05014290af5d`.
- Verified by inspecting decompressed lines: `domain` values are plain text
  lowercase strings with no TLD, e.g. `{"domain": "hkhqursjnuux", "threat": "dga"}`.
  The "encoded" in the filename is misleading.
- No family labels. Used only as a fixed external test sample; never for
  training. Not committed.

## Word list (DGA dictionary shapes)

- URL: <https://raw.githubusercontent.com/dwyl/english-words/master/words_alpha.txt>
- License: **The Unlicense**, <https://github.com/dwyl/english-words/blob/master/LICENSE.md>.
  Redistribution is permitted, so `domainguard/dga/wordlist.txt` is committed.
- Size: 4,234,910 bytes.

## Offline suffix list

- `tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)` is used
  everywhere. A unit test confirms the bundled snapshot resolves `co.uk`
  without a network request. Version: see `docs/results.md`.

## Free-hosting list

`domainguard/config.py` lists documented platform domains from providers' own
product pages: Google Blogger/Sites, Wix, Weebly, WordPress.com, GitHub Pages,
Netlify, Vercel, Squarespace, Webflow and 000webhost. It is a curated,
incomplete list, not an authoritative feed; results with and without these
rows are reported separately.

## Sources deliberately not used

TI-16, DGArchive, HYDRAS and CTU captures were not downloaded: access and terms
were not verified in this build. The CTU conversion remains a stretch goal.
