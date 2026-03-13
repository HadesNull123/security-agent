---
name: katana
category: recon
binary_name: katana
---

# Katana — Web Crawler & Spidering Framework

## When to Use
Run after httpx to crawl target websites, discover URLs, JavaScript endpoints, forms, and hidden paths.

## How to Use
```
katana [flags]
```

## CLI Flags
```
INPUT:
   -u, -list string[]   target URL / list to crawl

CONFIGURATION:
   -d, -depth int              max crawl depth (default 3)
   -jc, -js-crawl              parse/crawl JavaScript files
   -jsl, -jsluice              enable jsluice JS parsing (memory intensive)
   -ct, -crawl-duration value  max crawl duration (s, m, h, d)
   -kf, -known-files string    crawl known files (all,robotstxt,sitemapxml)
   -mrs, -max-response-size int  max response size to read
   -timeout int                request timeout seconds (default 10)
   -aff, -automatic-form-fill  auto form filling (experimental)
   -fx, -form-extraction       extract form/input/textarea elements in jsonl
   -retry int                  request retries (default 1)
   -proxy string               http/socks5 proxy
   -H, -headers string[]       custom headers (header:value format)
   -s, -strategy string        depth-first or breadth-first (default "depth-first")
   -iqp, -ignore-query-params  ignore same path with different query params

HEADLESS:
   -hl, -headless              enable headless hybrid crawling
   -sc, -system-chrome         use local Chrome
   -sb, -show-browser          show browser with headless mode
   -nos, -no-sandbox           Chrome --no-sandbox mode
   -xhr, -xhr-extraction       extract XHR request url/method

SCOPE:
   -cs, -crawl-scope string[]      in-scope URL regex
   -cos, -crawl-out-scope string[] out-of-scope URL regex
   -fs, -field-scope string        scope field (dn,rdn,fqdn) (default "rdn")
   -ns, -no-scope                  disable host-based scope
   -do, -display-out-scope         display external endpoints

FILTER:
   -mr, -match-regex string[]    match regex on output URL
   -fr, -filter-regex string[]   filter regex on output URL
   -f, -field string             field to display (url,path,fqdn,rdn,file,key,value,dir)
   -sf, -store-field string      field to store per host
   -em, -extension-match string[] match extensions (eg -em php,html,js)
   -ef, -extension-filter string[] filter extensions (eg -ef png,css)

RATE-LIMIT:
   -c, -concurrency int     concurrent fetchers (default 10)
   -p, -parallelism int     concurrent inputs (default 10)
   -rd, -delay int          delay between requests (seconds)
   -rl, -rate-limit int     max requests/second (default 150)

OUTPUT:
   -o, -output string       output file
   -sr, -store-response     store HTTP responses
   -j, -jsonl               JSONL output
   -silent                  display output only
   -v, -verbose             verbose output
```

## Example Commands
```bash
# Basic crawl with JS parsing
katana -u https://example.com -jc -silent

# Deep crawl with JSONL output
katana -u https://example.com -d 5 -jc -jsonl -o crawl.json

# Crawl known files (robots.txt, sitemap.xml)
katana -u https://example.com -kf all -silent

# Extract forms
katana -u https://example.com -fx -jsonl

# JavaScript-focused crawl (find API endpoints)
katana -u https://example.com -jc -jsl -f url -silent

# Headless crawl (SPA support)
katana -u https://example.com -hl -no-sandbox -silent
```

## Output Interpretation
- Each line = discovered URL
- Use `-f path` to show just paths
- JavaScript crawling (`-jc`) reveals API endpoints
- Form extraction (`-fx`) reveals input points for fuzzing

## Best Practices
- Use `-jc` to parse JavaScript files for hidden endpoints
- Use `-d 3` for quick, `-d 5` for deep
- Filter output: `-em php,html,js,json` to focus on interesting extensions
- Pipe discovered URLs to nuclei for vulnerability scanning
