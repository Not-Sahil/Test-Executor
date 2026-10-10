#### ***TC01 Banner Grabbing :-***



What the code does:

It sends requests to the target website and examines HTTP response headers and other server information to identify the web server, framework, runtime, or software and its version when disclosed.



Why it is necessary:

Exposed technology and version information helps an attacker fingerprint the application's infrastructure and potentially identify known vulnerabilities or outdated components.



What it is used for:

It is used for technology and server fingerprinting / information disclosure assessment, identifying whether the website unnecessarily reveals detailed server or software version information.



In one line:



TC01 checks whether the website reveals server/software identity and version information that could help an attacker fingerprint the underlying infrastructure.









#### ***TC02 Known Components :-***



What the code does:

It analyzes the website's publicly accessible content, headers, scripts, and resources to identify technologies/components being used, such as web frameworks, libraries, runtimes, CMS platforms, frontend frameworks, or other detectable software.



Why it is necessary:

Knowing which technologies and versions a website uses helps determine its technology attack surface. An attacker can use that **information** to research known weaknesses or outdated components.



What it is used for:

It is used for technology fingerprinting and component discovery during reconnaissance.



Important:

TC02 identifying a component does not automatically mean that component is vulnerable. Vulnerability verification is a separate step.



In one line:



TC02 identifies the technologies and components exposed by the website so the application's technology attack surface can be understood and reviewed for potential weaknesses.









#### ***TC03 Helpful Error Messages :-***



What the code does:

It deliberately sends controlled invalid or malformed requests to the website and examines the resulting error responses for technical information, such as stack traces, filesystem paths, database errors, framework details, internal IPs, or other diagnostic information.



Why it is necessary:

Detailed error messages can reveal how the application is built and expose internal implementation details that attackers can use for reconnaissance and further attacks.



What it is used for:

It is used to detect information leakage through overly detailed error messages and improper error handling.



In one line:



TC03 triggers safe error conditions and checks whether the application reveals sensitive technical or internal information in its error responses.











#### ***TC04 robots.txt :-***



What the code does



When you give it something like:



https://example.com



it checks:



https://example.com/robots.txt



Then it:



Checks whether robots.txt exists

Handles 200, 404, redirects, errors, etc.

Reads its directives

User-agent

Disallow

Allow

Sitemap

Looks for suspicious/sensitive paths, for example:

/admin/

/backup/

/config/

/database/

/debug/

/private/

/.git/

/.env

/uploads/

Checks some explicitly disclosed sensitive paths

For example, if robots.txt says:

Disallow: /admin/

Disallow: /backup/



the scanner can make a limited request to those paths.



Determines what actually happens

404/410 → probably not exposed

401/403 → access-controlled

200 → resource is reachable and needs further review

confirmed sensitive content → potentially UNSAFE

Why is this necessary?



Because developers sometimes use robots.txt like:



User-agent: \*

Disallow: /admin/

Disallow: /backup/

Disallow: /internal/

Disallow: /staging/



This does not protect those directories.



It merely tells search engines/crawlers not to index them. OWASP specifically treats robots.txt review as an information-gathering test because it can disclose hidden or interesting application paths.



So an attacker may learn:



/admin

/internal

/backup

/test



without having to discover those paths themselves.



What is it actually used for?



Think of TC04 as an information-disclosure/reconnaissance testcase.



Its purpose is:



robots.txt

&#x20;    ↓

find interesting paths

&#x20;    ↓

check whether those paths are actually reachable

&#x20;    ↓

determine whether useful/sensitive information is exposed



So the scanner is not saying "having /admin/ in robots.txt is automatically a vulnerability."



Instead:



robots.txt contains /admin/

&#x20;       ↓

REVIEW



/admin/ returns 403

&#x20;       ↓

likely SAFE



/admin/ returns a real admin page

&#x20;       ↓

REVIEW / potentially UNSAFE depending on exposure



/backup/ exposes credentials/configuration

&#x20;       ↓

UNSAFE



That's the important distinction that makes the testcase useful in a production scanner.



In one sentence



TC04 finds sensitive application paths voluntarily revealed through robots.txt and checks whether those disclosed resources are actually exposed.







#### ***TC05 Default Server Page :-***



What it does:

The scanner requests the website's root page and checks whether it is showing a generic/default web-server installation page instead of the actual application.



It looks at things like the page content, title, server-specific default-page signatures, headers, redirects, and response status.



Why is it necessary:

A default page can indicate that the server has been installed but the intended application has not been deployed/configured correctly. It can also reveal unnecessary server information and indicate poor deployment hygiene.



What is it used for:

It helps answer:



“Is this website actually serving its application, or is the web server still exposing its default installation page?”



For example:



Server: nginx

<title>Welcome to nginx!</title>



→ UNSAFE



Whereas:



Server: nginx

<title>My Company's Portal</title>

Login / Dashboard / Products



→ SAFE



And an ambiguous result gets:



REVIEW REQUIRED





&#x20;                Target /

&#x20;                   │

&#x20;                   ▼

&#x20;            Make normal GET

&#x20;                   │

&#x20;       ┌───────────┴───────────┐

&#x20;       │                       │

&#x20;  Redirects?                No redirect

&#x20;       │                       │

&#x20;       ▼                       ▼

&#x20;follow safely           Analyze response

&#x20;       │                       │

&#x20;       └───────────┬───────────┘

&#x20;                   ▼

&#x20;         Is this actually a

&#x20;         generic server page?

&#x20;                   │

&#x20;         ┌─────────┴─────────┐

&#x20;         │                   │

&#x20;        YES                  NO

&#x20;         │                   │

&#x20;      UNSAFE                SAFE







The important part is that the presence of Apache/nginx/IIS alone is not a vulnerability. TC05 is specifically looking for the default landing page, not merely identifying the server.







#### ***TC06 ETag Header :-***



What it does:

The scanner checks whether the website sends an ETag HTTP header, verifies that its format and behavior are normal, tests repeated requests and If-None-Match, and looks for suspicious ETag patterns that could indicate unintended information disclosure.



Why is it necessary:

ETags are normally legitimate and are used for HTTP caching and resource version validation. The problem is when an ETag implementation accidentally exposes useful server/resource metadata or behaves abnormally.



What is it used for:

It answers:



“Is this website's ETag implementation behaving normally, or could its ETag values reveal unnecessary information?”



For example:



ETag: "abc123"

→ SAFE



A stable ETag by itself is normal.



ETag: "5f2a-1700000000-2048"

→ REVIEW REQUIRED



because the structured value may warrant investigation, although the scanner cannot automatically prove what it represents.



And:



If-None-Match: "abc123"

→ HTTP 304



is generally normal expected behavior, not a vulnerability.



So, in one line:



TC06 is an ETag-behavior and potential information-disclosure check, not simply an “ETag exists” check.







#### ***TC07 Weak TLS Cipher / Protocol:-***







&#x20;                HTTPS target

&#x20;                    │

&#x20;                    ▼

&#x20;             Parse hostname

&#x20;                    │

&#x20;                    ▼

&#x20;             TLS baseline

&#x20;                    │

&#x20;       ┌────────────┼────────────┐

&#x20;       ▼            ▼            ▼

&#x20;    protocol      cipher       cert

&#x20;     probes       probes      metadata

&#x20;       │            │            │

&#x20;       └────────────┼────────────┘

&#x20;                    ▼

&#x20;            policy evaluation

&#x20;                    │

&#x20;       ┌────────────┼────────────┐

&#x20;       ▼            ▼            ▼

&#x20;     UNSAFE       REVIEW        SAFE



What it does:

It checks the HTTPS server for old TLS versions and weak cipher configurations, rather than only checking which modern cipher the server prefers. It also records related TLS details such as compression and certificate cryptographic information.



Why it is necessary:

A server can support a strong modern configuration while still accepting weak/deprecated protocols or ciphers for older clients. That creates unnecessary security risk. TLS 1.0 and 1.1, for example, are deprecated.



What it is used for:

It answers:



“Does this website allow outdated or weak HTTPS/TLS configurations?”



Example:



TLS 1.3 + AES-256-GCM

→ SAFE

TLS 1.0 accepted

→ UNSAFE

RC4 / NULL / EXPORT cipher accepted

→ UNSAFE

Some legacy options couldn't be tested

→ REVIEW REQUIRED



The key point is that a normal modern TLS handshake does not prove that weak options are disabled. TC07 actively probes what the server accepts.







#### ***TC08 Wildcard Certificate:-***



What it does:

The scanner checks the website’s TLS certificate to see whether it contains a wildcard certificate, such as:



\*.example.com



It then verifies whether the wildcard correctly matches the target hostname, checks the wildcard’s scope and syntax, and performs a small bounded check of related hosts to see whether potentially sensitive services are using the same certificate.



Why is it necessary:

Wildcard certificates are not inherently vulnerable. They are commonly used and legitimate. The security concern is when the wildcard has an unexpectedly broad scope or is shared across sensitive services, which can increase the impact of certificate/private-key compromise or indicate poor certificate boundary management.



What is it used for:

It answers:



“Is the wildcard certificate correctly scoped and being used across appropriate hosts?”



For example:



\*.example.com

www.example.com

&#x20;       ↓

correct match

→ SAFE



But:



\*.example.com

admin.example.com

&#x20;       ↓

same certificate is actively used by a sensitive-looking service

→ REVIEW REQUIRED



And:



\*.example.com

api.dev.example.com

&#x20;       ↓

wildcard doesn't match this hostname

→ UNSAFE



So, in one line:



TC08 checks the scope and correct use of wildcard TLS certificates; simply having a wildcard certificate is not itself a vulnerability.









#### ***TC09 Certificate Expiry :-***



What it does:

The scanner connects to the website’s HTTPS service and checks the TLS certificate’s validity dates:



notBefore — when the certificate becomes valid

notAfter — when it expires

how many days are remaining

whether the certificate or observable chain certificate is already expired or not yet valid



It also handles cases where normal certificate verification fails so it can still determine whether expiry is actually the reason.



Why is it necessary:

An expired or not-yet-valid TLS certificate can cause browsers and clients to reject HTTPS connections, creating a security and availability problem. Certificates that are close to expiration also need attention before they cause an outage.



What is it used for:

It answers:



“Is the HTTPS certificate currently valid, and will it remain valid long enough?”



For example:



Certificate expired

→ UNSAFE

Certificate becomes valid in the future

→ UNSAFE

Certificate expires in 20 days

→ REVIEW REQUIRED

Certificate valid for 150 days

→ SAFE



The important improvement is that TC09 focuses specifically on certificate validity/expiry. It does not duplicate TC07's weak-cipher testing or TC08's wildcard-certificate testing.







#### ***TC10 Directory Listing :-***



&#x20;                    Target

&#x20;                       │

&#x20;                       ▼

&#x20;            Establish baseline root

&#x20;                       │

&#x20;                       ▼

&#x20;         Build bounded directory list

&#x20;            /       |        \\

&#x20;           /        |         \\

&#x20;      configured   robots    sitemap

&#x20;        paths      paths       paths

&#x20;            \\        |         /

&#x20;             \\       |        /

&#x20;                 deduplicate

&#x20;                      │

&#x20;                      ▼

&#x20;               request directory

&#x20;                      │

&#x20;              ┌───────┴────────┐

&#x20;              │                │

&#x20;         redirect?          direct

&#x20;              │                │

&#x20;              ▼                ▼

&#x20;       follow bounded      inspect

&#x20;              │                │

&#x20;              └───────┬────────┘

&#x20;                      ▼

&#x20;             Is this a genuine

&#x20;            directory listing?

&#x20;                      │

&#x20;         ┌────────────┼────────────┐

&#x20;         ▼            ▼            ▼

&#x20;       strong      moderate       no

&#x20;       evidence     evidence

&#x20;         │            │             │

&#x20;      UNSAFE        REVIEW        SAFE





What it does:

The scanner checks whether publicly accessible website directories are exposing a directory index/listing that lets a visitor browse files and folders.



It tests common directories plus a small number of paths discovered from places such as robots.txt, sitemap.xml, and links on the application's page, then analyzes the responses for Apache/nginx-style or other directory-listing patterns.



Why is it necessary:

A directory listing can reveal files that the application never linked publicly, such as:



/backup/

/uploads/

/documents/



backup.zip

old-config.php

database.sql



This gives an attacker useful information about the application's structure and potentially exposes sensitive files. Directory indexing is therefore a server configuration/deployment weakness.



What is it used for:

It answers:



“Can an unauthenticated visitor browse the contents of any web-accessible directory?”



For example:



/uploads/

→ 403 Forbidden

→ SAFE

/uploads/

→ 200

→ Apache "Index of /uploads/"

→ UNSAFE

/random/

→ 200

→ normal React/website page

→ SAFE

/files/

→ page resembles a directory index but cannot be confirmed

→ REVIEW REQUIRED



So, in one line:



TC10 detects publicly browseable server-generated directory indexes; it is not a general-purpose directory or file brute-forcing test.







#### ***TC11 HTTP Arbitrary Methods :-***



What it does:

The scanner checks which HTTP methods the website advertises and actually accepts. It safely tests methods such as OPTIONS, HEAD, TRACE, TRACK, and an unknown method, and checks whether diagnostic request data is reflected.



Why it is necessary:

A web server may expose HTTP methods that are unnecessary or improperly configured. For example, TRACE being enabled can indicate unnecessary server functionality, while unexpected method handling can indicate routing or security-control issues. However, methods like PUT, PATCH, and DELETE can be legitimate for APIs, so their presence alone does not mean the application is vulnerable.



What it is used for:

It answers:



“Is this endpoint exposing or handling HTTP methods in an unexpected or unnecessarily permissive way?”



Examples:



TRACE → 405

Unknown method → 501

Allow: GET, HEAD, OPTIONS

→ SAFE

TRACE → 200

→ REVIEW REQUIRED

TRACE → 200

controlled marker reflected

→ REVIEW REQUIRED

Allow: GET, POST, PUT, PATCH, DELETE

→ REVIEW REQUIRED



The last case is not automatically a vulnerability because those methods may be intentionally required by a REST API.



In one line:

TC11 checks whether HTTP methods are unnecessarily exposed or handled incorrectly, while avoiding dangerous/destructive requests against live resources.









#### ***TC12 Host Header Injection :-***



&#x20;                        TC12

&#x20;                         │

&#x20;                establish baseline

&#x20;                         │

&#x20;             ┌───────────┴───────────┐

&#x20;             │                       │

&#x20;        Host injection       X-Forwarded-Host

&#x20;             │                       │

&#x20;             └───────────┬───────────┘

&#x20;                         ↓

&#x20;                analyze influence

&#x20;                         │

&#x20;       ┌─────────┬───────┼────────┬────────┐

&#x20;       ↓         ↓       ↓        ↓        ↓

&#x20;     redirect  URLs    cookies  body    routing

&#x20;       │         │       │        │        │

&#x20;       └─────────┴───────┴────────┴────────┘

&#x20;                         ↓

&#x20;                   risk classification





What it does:

The scanner sends the website a normal request and then sends controlled requests with a fake Host value and related forwarded-host headers. It checks whether that attacker-controlled value influences:



redirects

generated URLs

canonical/OpenGraph URLs

response content

cookies

virtual-host routing



Why is it necessary:

Some applications incorrectly trust the Host header when generating URLs or deciding which host/service should handle a request. This can lead to issues such as malicious redirects, password-reset URL manipulation, cache poisoning, or unintended virtual-host access.



What is it used for:

It answers:



“Does the application improperly trust a user-controlled Host value?”



For example:



Host: test.invalid

Location: https://test.invalid/login

→ UNSAFE

Host: test.invalid

value only reflected in page text

→ REVIEW REQUIRED

Host: test.invalid

no security-sensitive influence detected

→ SAFE



So, in one line:



TC12 detects whether manipulated Host/forwarded-host values can influence security-sensitive application behavior, rather than simply checking whether the fake hostname appears somewhere in the response.









#### ***TC13 Sensitive File Exposure :-***



&#x20;                      TC13

&#x20;                        │

&#x20;            Build bounded probe list

&#x20;                        │

&#x20;       ┌────────────────┼────────────────┐

&#x20;       │                │                │

&#x20;  configured       discovered       backup variants

&#x20;   sensitive         paths

&#x20;    paths

&#x20;       │                │                │

&#x20;       └────────────────┼────────────────┘

&#x20;                        ▼

&#x20;                 Deduplicate probes

&#x20;                        │

&#x20;                        ▼

&#x20;                   Safe GET

&#x20;                        │

&#x20;       ┌────────────────┼────────────────┐

&#x20;       ▼                ▼                ▼

&#x20;     2xx              3xx/4xx           5xx

&#x20;       │                │                │

&#x20;       ▼                ▼                ▼

&#x20; content analysis    classify          review

&#x20;       │

&#x20;  ┌────┼─────┐

&#x20;  ▼    ▼     ▼

&#x20;secret source archive

&#x20;  │    │     │

&#x20;  └────┼─────┘

&#x20;       ▼

&#x20;  risk classification





What it does:

The scanner checks a bounded set of commonly exposed sensitive resources such as:



/.env

/.git/HEAD

/config.php

/application.properties

/backup.zip

/phpinfo.php



It then checks whether they are actually publicly accessible and analyzes their content for things like:



credentials/secrets

database connection strings

private keys

source code

Git metadata

configuration

debug information

backup/archive files



It also handles 401/403, 404, redirects, binary files, and fake 200 responses from SPA/application fallbacks.



Why is it necessary:

Developers sometimes accidentally leave configuration files, backups, source code, logs, Git metadata, or diagnostic pages inside the web-accessible directory. These can reveal sensitive information or provide attackers with valuable knowledge about the application. OWASP specifically recommends checking old, backup, and unreferenced files for sensitive information.



What is it used for:

It answers:



“Can an unauthenticated visitor directly retrieve a sensitive file or resource that should not be publicly exposed?”



For example:



/.env → 404

→ SAFE

/.env → 200

DB\_PASSWORD=...

→ UNSAFE

/config.php → 200

normal application HTML

→ SAFE

/.git/HEAD → 200

ref: refs/heads/main

→ UNSAFE



So, in one line:



TC13 detects publicly accessible sensitive configuration, source code, credentials, version-control data, diagnostics, and backup resources—while distinguishing real exposure from harmless 200/SPA responses.









#### ***TC14 Google Dorking / Search Engine Reconnaissance :-***



&#x20;                        TC14

&#x20;                          │

&#x20;                      target

&#x20;                          │

&#x20;                ┌─────────┴─────────┐

&#x20;                │                   │

&#x20;            hostname            base domain

&#x20;                │                   │

&#x20;                └─────────┬─────────┘

&#x20;                          ▼

&#x20;                  categorized dorks

&#x20;                          │

&#x20;     ┌────────┬────────┬──┼──┬─────────┬─────────┐

&#x20;     ▼        ▼        ▼  ▼  ▼         ▼         ▼

&#x20;  admin    staging   creds git       backup     logs

&#x20;     │        │        │   │           │         │

&#x20;     └────────┴────────┴───┴───────────┴─────────┘

&#x20;                          │

&#x20;                          ▼

&#x20;               Google / Bing / DDG links

&#x20;                          │

&#x20;                          ▼

&#x20;                   manual analysis

&#x20;                          │

&#x20;                          ▼

&#x20;                 REVIEW REQUIRED





What it does:

The scanner generates a set of domain-specific search queries for Google, Bing, and DuckDuckGo to look for information about the target that may already be publicly indexed.



It searches for things such as:



admin / dashboard

staging / dev / test

backup files

configuration files

.env / .git

credentials / private keys

logs

internal information

error messages

API documentation

sensitive documents



It does not automatically search the engines; it generates links and guidance for manual review.



Why is it necessary:

A website may unintentionally have sensitive pages or documents indexed by search engines even though those resources aren't obvious from normal navigation. OWASP specifically recommends search-engine reconnaissance for discovering information leakage, including credentials, configuration information, error details, and non-production environments.



What is it used for:

It answers:



“What information about this target is already publicly discoverable through search engines?”



For example:



site:example.com "index of /"

→ may reveal indexed directory listings

site:example.com (staging OR dev OR uat)

→ may reveal non-production environments

site:example.com (".env" OR "password" OR "private key")

→ may reveal potentially sensitive indexed content



The search result itself is not automatically a vulnerability. A human needs to verify whether the discovered information is actually sensitive and unintentionally exposed.



In one line:

TC14 uses search-engine reconnaissance to discover publicly indexed information that could reveal sensitive files, internal environments, credentials, or application details that the website owner may not realize are exposed.









#### ***TC15 Internal IP Disclosure :-***



&#x20;                      TC15

&#x20;                        │

&#x20;                Fetch bounded sources

&#x20;                        │

&#x20;      ┌────────┬────────┼────────┬──────────┐

&#x20;      ▼        ▼        ▼        ▼          ▼

&#x20;     HTML    headers  redirects   JS       metadata

&#x20;      │        │        │        │          │

&#x20;      └────────┴────────┴────────┴──────────┘

&#x20;                        │

&#x20;                        ▼

&#x20;                   Extract IPs

&#x20;                        │

&#x20;                 classify address

&#x20;                        │

&#x20;      ┌─────────────────┼─────────────────┐

&#x20;      ▼                 ▼                 ▼

&#x20;   private          loopback/link      public

&#x20;      │                 │                 

&#x20;      └──────────┬──────┘                 

&#x20;                 ▼                        

&#x20;            analyze context              

&#x20;                 │                        

&#x20;        ┌────────┴────────┐              

&#x20;        ▼                 ▼              

&#x20;      strong            weak             

&#x20;        │                 │              

&#x20;      UNSAFE            REVIEW   





What it does:

The scanner checks publicly accessible responses for private/internal IP addresses, including IPv4 and IPv6, in places such as:



page content

HTTP headers

redirects

robots.txt

sitemap.xml

same-origin JavaScript



It then examines the surrounding context to determine whether the IP appears to represent real internal infrastructure or is merely an example/placeholder.



Why is it necessary:

Internal IPs can reveal information about a site's backend servers, databases, APIs, proxies, internal services, or network structure. OWASP specifically considers internal IP disclosure through webpage content, JavaScript, metadata, and redirects an information-leakage issue.



What is it used for:

It answers:



“Is the website unintentionally revealing non-public infrastructure IP addresses to unauthenticated users?”



For example:



10.42.5.17

"backend-api"

→ UNSAFE

192.168.1.1

"Example router configuration"

→ SAFE

10.20.30.40

appears without enough context

→ REVIEW REQUIRED



So, in one line:



TC15 detects and evaluates publicly disclosed internal/private IP addresses to determine whether the website is leaking useful information about its internal infrastructure.









#### ***TC16 Clickjacking :-***



&#x20;                   TC16

&#x20;                     │

&#x20;              baseline request

&#x20;                     │

&#x20;         ┌───────────┴────────────┐

&#x20;         │                        │

&#x20;      headers                 redirects

&#x20;         │                        │

&#x20;    ┌────┴────┐                │

&#x20;    ▼         ▼                  │

&#x20;   CSP       XFO                  │

&#x20;    │         │                  │

&#x20;frame-ancestors │                │

&#x20;    │         │                  │

&#x20;    └────┬────┘                │

&#x20;         ▼                        │

&#x20;   effective policy ◄──────────┘

&#x20;         │

&#x20;         ▼

&#x20;  optional browser test

&#x20;         │

&#x20;         ▼

&#x20;SAFE / REVIEW / UNSAFE





What it does:

The scanner checks whether the website has effective protection against being loaded inside another website's <iframe>. It examines:



Content-Security-Policy: frame-ancestors

X-Frame-Options

duplicate/conflicting policies

report-only CSP

redirects

and optionally verifies the behavior with a real browser.



Why is it necessary:

Without proper framing protection, an attacker may be able to place the website inside a malicious page and trick a victim into interacting with the hidden/overlaid application. frame-ancestors and X-Frame-Options are the main HTTP controls used to restrict this.



What is it used for:

It answers:



“Can another website embed this application in a frame, and has the application properly restricted who can do so?”



Examples:



CSP: frame-ancestors 'none'

→ SAFE

X-Frame-Options: DENY

→ SAFE

No effective CSP frame-ancestors

No effective X-Frame-Options

→ UNSAFE

CSP: frame-ancestors \*

→ UNSAFE

Only CSP-Report-Only provides protection

→ UNSAFE



So, in one line:



TC16 determines whether the website is adequately protected against unauthorized framing/clickjacking, rather than merely checking whether a security header exists.









#### ***TC17 Website Accessible Over IP :-***



&#x20;                   example.com

&#x20;                        │

&#x20;                  resolve DNS

&#x20;                        │

&#x20;             ┌──────────┴──────────┐

&#x20;             ▼                     ▼

&#x20;           IPv4                   IPv6

&#x20;             │                     │

&#x20;             └──────────┬──────────┘

&#x20;                        ▼

&#x20;                hostname baseline

&#x20;                        │

&#x20;               for each IP address

&#x20;                        │

&#x20;              ┌─────────┴─────────┐

&#x20;              ▼                   ▼

&#x20;         raw IP access      forced-IP access

&#x20;                             Host = example.com

&#x20;                             SNI  = example.com

&#x20;                                 │

&#x20;                                 ▼

&#x20;                          response comparison

&#x20;                                 │

&#x20;                        ┌────────┼─────────┐

&#x20;                        ▼        ▼         ▼

&#x20;                     redirect  unrelated   same app

&#x20;                        │        │           │

&#x20;                      SAFE     REVIEW      REVIEW





What it does:

The scanner resolves the website's hostname to its IP addresses and checks whether the application can also be reached directly through those IP addresses. It compares the normal hostname response with the IP-based response and also tests the IP while preserving the original hostname through Host/TLS SNI.



Why is it necessary:

A website may normally sit behind a CDN, WAF, reverse proxy, or other security layer, while its origin server remains directly reachable by IP. That can create an alternate path that potentially bypasses those protections. Direct IP access itself is not automatically a vulnerability.



What is it used for:

It answers:



“Can the actual application be reached directly through its server IP, potentially bypassing the intended hostname/security architecture?”



Examples:



example.com

→ CDN/WAF

203.0.113.10 directly

→ blocked

→ SAFE

example.com

→ application



203.0.113.10 + Host: example.com

→ same application

→ REVIEW REQUIRED

203.0.113.10

→ nginx default page

→ not the target application

→ SAFE



So, in one line:



TC17 detects whether the target application has an unintended direct-IP access path and whether that path could bypass the site's expected security boundary.









#### ***TC18 Missing Security Headers :-***





What the code does:

It sends a request to the website, reads the HTTP response headers, and checks whether five security-related headers are present and configured according to its defined baseline:



Content-Security-Policy

Strict-Transport-Security

X-Content-Type-Options

X-Frame-Options

Referrer-Policy



It then marks each header as SAFE or UNSAFE and produces an overall result based on whether any of those checks fail.



Why it is necessary:

Security headers tell browsers how they should handle the website and can reduce risks such as XSS, clickjacking, MIME-type confusion, insecure transport, and unnecessary referrer information leakage.



What it is used for:

It is used to identify missing or improperly configured browser security protections in an application's HTTP responses.



In one line:



TC18 checks whether the website is sending important HTTP security headers and whether their configurations meet the scanner's security baseline.









#### ***TC19 Hardcoded Credentials :-***



&#x20;            TC19

&#x20;              │

&#x20;              ▼

&#x20;       Fetch public HTML

&#x20;              │

&#x20;      ┌───────┴────────┐

&#x20;      ▼                ▼

&#x20;Inline scripts      External JS

&#x20;      │                │

&#x20;      └───────┬────────┘

&#x20;              ▼

&#x20;       Source-map check

&#x20;              │

&#x20;              ▼

&#x20;     Config / JSON blobs

&#x20;              │

&#x20;              ▼

&#x20;      Secret detectors

&#x20;              │

&#x20;      ┌───────┼────────┐

&#x20;      ▼       ▼        ▼

&#x20;   Known    Generic   Encoded

&#x20;   secrets  secrets   secrets

&#x20;      │       │        │

&#x20;      └───────┼────────┘

&#x20;              ▼

&#x20;      Context analysis

&#x20;              ▼

&#x20;      Placeholder filter

&#x20;              ▼

&#x20;      Confidence scoring

&#x20;              ▼

&#x20;     Secret redaction

&#x20;              ▼

&#x20;    SAFE / REVIEW / UNSAFE





What the code does:

It scans publicly accessible website content—HTML, inline JavaScript, external JavaScript, and related client-side configuration—for hardcoded credentials or secret-like values such as passwords, API keys, access tokens, private keys, authentication values, and connection strings.



Why it is necessary:

Developers can accidentally put sensitive credentials directly into frontend code. Since that code is delivered to the browser, an attacker can retrieve and inspect it.



What it is used for:

It is used to detect credential/secret exposure in unauthenticated client-accessible content before authentication.



In one line:



TC19 checks whether the website accidentally exposes hardcoded credentials or other sensitive secrets in its publicly delivered frontend code and configuration.









#### ***TC20 Sitemap XML :-***



What the code does:

It checks whether the website exposes a sitemap.xml, parses the sitemap, extracts the URLs listed in it, and looks for paths that appear sensitive, such as admin, internal, debug, backup, staging, configuration, or private areas.



Why it is necessary:

A sitemap is intentionally public, but it can reveal application paths that attackers would otherwise have to discover themselves. Sensitive-looking entries can expose information about the application's structure and attack surface.



What it is used for:

It is used for information gathering and attack-surface discovery, specifically to identify potentially sensitive application paths publicly disclosed through sitemap files.



In one line:



TC20 checks what application URLs the site's sitemap publicly reveals and flags potentially sensitive paths that deserve security review.









#### *TC21 Crossdomain XML :-*





What the code does:

It checks whether the website exposes crossdomain.xml or clientaccesspolicy.xml, parses the policy, and analyzes who is allowed to access the application's resources across domains. It checks for overly broad permissions such as wildcard domains, insecure HTTP access, unrestricted headers, broad socket ports, permissive policy-file settings, and malformed or unusual policy configurations.



Why it is necessary:

An overly permissive cross-domain policy can allow other websites/origins to interact with resources that should be restricted. This can unnecessarily expand the application's attack surface.



What it is used for:

It is used to identify misconfigured legacy cross-domain access policies and determine whether the application grants broader cross-origin permissions than intended.



In one line:



TC21 checks whether legacy cross-domain policy files grant overly broad or insecure access to other domains.









#### ***TC22 Application Running on HTTP :-***



What the code does:

It checks whether the website can be accessed through unencrypted HTTP and whether HTTP properly redirects/enforces HTTPS. It also examines redirect chains, application content, cookies, HTTP forms/resources, and the HTTPS counterpart.



Why it is necessary:

HTTP traffic is unencrypted and can expose sensitive information or allow attackers to tamper with traffic. Simply having HTTPS available is not enough if the application can still be served directly over HTTP.



What it is used for:

It is used to detect improper HTTPS enforcement and accidental application exposure over HTTP, including cases where sensitive cookies or application functionality are transmitted through HTTP.



In one line:



TC22 checks whether the application is actually accessible over insecure HTTP instead of consistently enforcing HTTPS.









#### ***TC23 Internal Path Disclosure :-***



What the code does:

It sends controlled malformed and nonexistent requests to the website and analyzes the resulting error responses for leaked internal information such as:



Windows/Unix filesystem paths

Source-code file locations and line numbers

Stack traces

Database errors

Framework/debug information

Internal URLs or host information



Why it is necessary:

Detailed error messages can reveal how the application is built and where its source files, servers, frameworks, or databases are located. Attackers can use this information to better understand and target the application.



What it is used for:

It is used to detect information leakage through error handling, particularly unintended disclosure of internal filesystem paths and application implementation details.



In one line:



TC23 deliberately triggers safe error conditions and checks whether the application's error responses reveal internal paths, source locations, stack traces, or other sensitive implementation details.

