# CIP-B103 Lab 7 – DNS Introduction and Traffic Analysis

**Student:** Fuseini Imoru Kantuogaa
**Course:** CIP-B103 – Network Forensics Fundamentals
**Lab:** Lab 7 – DNS Introduction and Traffic Analysis

## Overview

This lab establishes a **normal DNS traffic baseline** for incident
response, in preparation for analyzing DNS spoofing in Lab 8. It covers
identifying the configured DNS resolver, issuing controlled `dig`
queries against multiple record types, capturing live DNS traffic with
`tshark`, extracting and correlating query/response packet fields, and
tying DNS resolution to subsequent browser/TCP connections.

## Lab Scenario

Documenting normal DNS behavior as an incident-response baseline:
identifying the configured resolver, capturing controlled `dig` queries,
analyzing transaction IDs, query names, record types, response codes,
answers and TTL values, and correlating DNS resolution with subsequent
web or email connections.

## Learning Outcomes

- Explain recursive and iterative DNS resolution at a foundational level
- Use `dig` to query A, AAAA, MX, and NS records
- Capture and analyze DNS queries/responses with `tshark`/Wireshark
- Identify transaction ID, query name, record type, response code,
  answer, and TTL
- Correlate DNS responses with later IP connections
- Recognize normal variations: multiple answers, CNAMEs, cache
  responses, IPv6 queries

## Required Tools

| Item | Tool | Purpose |
|---|---|---|
| OS | Kali Linux / Ubuntu VM | Generate and analyze DNS traffic |
| DNS utility | `dig` (`dnsutils`) | Controlled DNS queries |
| Capture tools | `tshark`, Wireshark | Capture DNS traffic |
| Evidence | `dig_dns.pcap` or new PCAPNG | Analysis source |
| Resolver config | `/etc/resolv.conf`, `resolvectl` | Identify configured DNS service |
| Optional | Firefox/Chrome | Generate multiple real-world DNS lookups |

## 1. Lab Folder Structure & Evidence Preparation

```bash
mkdir -p ~/CIP-B103-Lab7/{evidence,working,exported,reports,screenshots,scripts}
cd ~/CIP-B103-Lab7
pwd
find . -maxdepth 1 -type d -print
```

```bash
sudo apt update
sudo apt install -y dnsutils tshark wireshark
```

Documented the configured DNS resolver before any capture:

```bash
cat /etc/resolv.conf | tee reports/resolv_conf.txt
resolvectl status 2>/dev/null | tee reports/resolvectl_status.txt || true
```

Downloaded baseline evidence, made a working copy, and hashed both to
establish chain of custody:

```bash
wget -O evidence/dig_dns.pcap \
  '<sample_dig_dns_pcap_url>'
cp --preserve=timestamps evidence/dig_dns.pcap working/dig_dns_working.pcap
sha256sum evidence/dig_dns.pcap working/dig_dns_working.pcap | tee reports/dns_capture_hashes.txt
```

## 2. Chain-of-Custody Worksheet

| Field | Entry |
|---|---|
| Case/lab identifier | CIP-B103-Lab7-Fuseini-Imoru-Kantuogaa |
| Trainee name | Fuseini Imoru Kantuogaa |
| Evidence file name(s) | `dig_dns.pcap`, `fresh_dig_dns.pcapng`, `browser_dns.pcapng` |
| Source/generation method | Downloaded sample + locally generated via `tshark`/`dig` |
| Analysis workstation | Kali Linux VM |

## 3. Part A – Query DNS Records with `dig`

```bash
dig example.com A    | tee reports/dig_example_A.txt
dig example.com AAAA | tee reports/dig_example_AAAA.txt
dig example.com MX   | tee reports/dig_example_MX.txt
dig example.com NS   | tee reports/dig_example_NS.txt
dig +short example.com A | tee reports/dig_example_short.txt
```

Documented for each query: the resolver (`SERVER` line), status/response
code, flags, question/answer counts, query time, and at least one TTL
value (recorded as a **cache lifetime**, not a record creation date).

## 4. Part B – Capture a Fresh DNS Query

```bash
IFACE=eth0
sudo tshark -i "$IFACE" -f 'port 53' -a duration:25 -w evidence/fresh_dig_dns.pcapng &
sleep 3
dig +noedns example.com A >/dev/null
wait
sha256sum evidence/fresh_dig_dns.pcapng | tee reports/fresh_dns_sha256.txt
```

> **Note:** On systems using a local stub resolver, packets may appear
> first on `lo` and then on a physical interface. Used `tshark -D` to
> confirm the correct interface capturing the actual query.

## 5. Part C – Extract DNS Query and Response Fields

```bash
PCAP=evidence/fresh_dig_dns.pcapng

# Queries
tshark -r "$PCAP" -Y 'dns.flags.response==0' -T fields \
  -e frame.number -e frame.time -e ip.src -e udp.srcport \
  -e ip.dst -e udp.dstport -e dns.id -e dns.qry.name -e dns.qry.type \
  | tee reports/dns_queries.tsv

# Responses
tshark -r "$PCAP" -Y 'dns.flags.response==1' -T fields \
  -e frame.number -e frame.time -e ip.src -e udp.srcport \
  -e ip.dst -e udp.dstport -e dns.id -e dns.flags.rcode \
  -e dns.count.answers -e dns.a -e dns.aaaa -e dns.resp.ttl \
  | tee reports/dns_responses.tsv
```

## 6. Part D – Match Queries to Responses

Matched query and response packets using **transaction ID** plus the
endpoint tuple (source/destination IP and port), confirmed the response
source matched the queried resolver, calculated response time from
frame timestamps, and documented any CNAME chains or multiple A/AAAA
answers observed.

| Transaction ID | Query Name | Type | Client/Resolver | Response Code | Answer(s) | TTL | Time Delta |
|---|---|---|---|---|---|---|---|

## 7. Part E – Analyze DNS Generated by a Browser

Captured DNS traffic generated by visiting an instructor-approved site
in a private browser window, then inventoried every domain queried
(page, images, fonts, telemetry, cached services):

```bash
sudo tshark -i "$IFACE" -f 'port 53' -a duration:40 -w evidence/browser_dns.pcapng &
sleep 3
# Visited the approved site in a private browser window, then waited
wait

tshark -r evidence/browser_dns.pcapng -Y 'dns.flags.response==0' -T fields \
  -e dns.qry.name -e dns.qry.type \
  | sort | uniq -c | sort -nr | tee reports/browser_dns_inventory.txt
```

## 8. Part F – Correlate DNS with Subsequent Connections

```bash
# Extract DNS A answers
tshark -r evidence/browser_dns.pcapng -Y 'dns.a' -T fields \
  -e frame.time_epoch -e dns.qry.name -e dns.a \
  | tee reports/dns_A_answers.tsv

# Extract later outbound TCP connection attempts (SYN only)
tshark -r evidence/browser_dns.pcapng -Y 'tcp.flags.syn==1 && tcp.flags.ack==0' -T fields \
  -e frame.time_epoch -e ip.dst -e tcp.dstport \
  | tee reports/subsequent_tcp_destinations.tsv
```

Selected one DNS answer and confirmed whether the client subsequently
connected to that resolved IP, with an explanation of any mismatches
(multiple answers, CDNs/proxies, IPv6, caching, or capture window
duration).

## 9. Part G – DNS Analysis Within SMTP Evidence (Optional)

Correlated DNS queries with the mail server lookup used in the Lab 4
SMTP capture:

```bash
tshark -r ../CIP-B103-Lab4/working/smtp_working.pcap -Y 'dns' -T fields \
  -e frame.number -e frame.time -e dns.qry.name -e dns.qry.type \
  -e dns.a -e dns.resp.name -e dns.resp.ttl \
  | tee reports/smtp_dns_correlation.tsv
```

## Required Findings Worksheet

| Field | Finding |
|---|---|
| Configured resolver IP | |
| Client source port | |
| Resolver destination port (53) | |
| Transaction ID | |
| Query name and type | |
| Response code | |
| Answer IP(s) | |
| TTL | |
| Query-response time delta | |
| Subsequent connection correlation | |
| Normal variations observed | |

## Key Tools & Filters Used

| Command / Filter | Purpose |
|---|---|
| `dig NAME TYPE` | Query a DNS record |
| `dns.qry.name` | Queried domain name |
| `dns.qry.type` | Requested record type |
| `dns.id` | DNS transaction identifier |
| `dns.flags.response` (0/1) | Distinguish query vs. response |
| `dns.flags.rcode` | Response code |
| `dns.resp.ttl` | Answer TTL |
| `dns.a` / `dns.aaaa` | IPv4/IPv6 answer records |
| `tcp.flags.syn==1 && tcp.flags.ack==0` | Outbound connection attempts (for correlation) |

## Report Files Generated

| File | Contents |
|---|---|
| `resolv_conf.txt`, `resolvectl_status.txt` | Configured DNS resolver |
| `dns_capture_hashes.txt`, `fresh_dns_sha256.txt` | Evidence integrity hashes |
| `dig_example_A/AAAA/MX/NS.txt`, `dig_example_short.txt` | `dig` query outputs |
| `dns_queries.tsv`, `dns_responses.tsv` | Extracted DNS packet fields |
| `browser_dns_inventory.txt` | Unique domains queried by the browser |
| `dns_A_answers.tsv`, `subsequent_tcp_destinations.tsv` | DNS-to-connection correlation |
| `smtp_dns_correlation.tsv` | DNS lookups tied to Lab 4 SMTP evidence |

## Legal, Ethical & Safety Notes

- Used only authorized training evidence and isolated (NAT/host-only)
  virtual networking — no production, campus, or public network traffic.
- No real credentials, personal messages, or confidential traffic were
  collected or disclosed.
- Original capture files were preserved unmodified; all analysis was
  performed on verified working copies with recorded SHA-256 hashes.
- All traffic-generation/capture processes were stopped immediately
  after the required evidence was collected, and network/firewall/ARP
  settings were restored before closing the lab.
