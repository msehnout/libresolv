# Messages

* All of them starts with header

TEN PROBLEM S KOMPRESI: proste si uloz ty cisla ukazatelu a pak to naparsuj znova input[pointer..] a je to!
nebo na parsovani cele te zpravy nepouzivat makro, ale vlastni funkci a jen z ni volat parsery tech jednotlivych casti

# Resource record formats

## A type RR


# About nom
* ref docs are quite concise
* lets write some, once I understand it! :-D
* Found awesome tool: cargo expand (https://github.com/dtolnay/cargo-expand) ... and it's even more awesome with pygments

# Ostatni:
 * Precti si nejaky doporuceni na psani knihoven, jesli mam pouzivat radeji vec nebo slice
 * Coz takle vracet z tech parseru dvojici RR, Vec<NameUnit> at to nemusim mit 2x definovane?
 * u tech builderu naimplementovat default metodu a setry na vsechno
 * https://pascalhertleif.de/artikel/good-practices-for-writing-rust-libraries/
 * Pouzit: https://crates.io/crates/byteorder

# Automated tests:
1. Capture dns traffic:
tcpdump port 53 -w test-dns.pcap (https://danielmiessler.com/study/#gs.gHMJwGc)
2. Convert to json:
tshark -T json -r test-dns.pcap
3. Filter dns dictionary only:
cat test-dns.json | python3 -c "import sys, json, pprint as pp; inner = [x['_source']['layers'] for x in json.load(sys.stdin)]; pp.pprint([x['dns'] for x in inner if 'dns' in x])" > test-dns-filtered.json
4. Use it somehow :-)
