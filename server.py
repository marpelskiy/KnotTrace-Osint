#!/usr/bin/env python3
"""
KnotTrace — локальный сервер разведки.

Запуск: python3 server.py
Затем открыть index.html в браузере.
"""

import http.server, json, re, socket, subprocess, xml.etree.ElementTree as ET
import urllib.request, urllib.parse
from urllib.parse import urlparse, parse_qs

PORT = 5050

# ──────────────────────────────────────────────
# УТИЛИТЫ
# ──────────────────────────────────────────────

def run_cmd(cmd, timeout=120):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except FileNotFoundError:
        return None, f"Команда не найдена: {cmd[0]}", 1
    except subprocess.TimeoutExpired:
        return None, "Превышен лимит времени", 1

def safe_id(*parts):
    return re.sub(r'[^a-zA-Z0-9_]', '_', '_'.join(str(p) for p in parts))[:80]

def node(id_, label, type_="Text", color="#4B5563"):
    return {"data": {"id": id_, "label": label, "type": type_, "color": color}}

def edge(src, tgt, label="", style="solid"):
    return {"data": {"id": safe_id("e", src, tgt), "source": src, "target": tgt, "edgeLabel": label, "lineStyle": style}}

def err(msg):
    return {"error": msg}

def fetch_url(url, timeout=15):
    req = urllib.request.Request(url, headers={"User-Agent": "KnotTrace/2.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8")

# ──────────────────────────────────────────────
# SCAN — NMAP
# ──────────────────────────────────────────────

def run_nmap(target, mode="quick"):
    mode_flags = {
        "quick": ["-F", "--open"],
        "full":  ["-sV", "--open"],
        "os":    ["-O", "--open"],
        "vuln":  ["--script", "vuln", "--open"],
    }
    flags = mode_flags.get(mode, ["-F", "--open"])
    out, er, rc = run_cmd(["nmap"] + flags + ["-oX", "-", target])
    if out is None:
        return err(f"nmap не найден. Установите: sudo pacman -S nmap")
    if not out:
        return err(f"nmap ошибка: {er}")
    return parse_nmap_xml(out, target)

def parse_nmap_xml(xml_data, scan_target):
    nodes, edges = [], []
    try:
        root = ET.fromstring(xml_data)
    except ET.ParseError as e:
        return err(f"XML ошибка: {e}")

    rid = safe_id("scan", scan_target)
    nodes.append(node(rid, f"Скан: {scan_target}", "Text", "#4B5563"))

    for host in root.findall("host"):
        st = host.find("status")
        if st is not None and st.get("state") != "up":
            continue
        
        addr_el = host.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host.find("address[@addrtype='ipv6']")
            
        if addr_el is None:
            continue
            
        ip = addr_el.get("addr", "?")
        mac_el = host.find("address[@addrtype='mac']")
        hn_el = host.find("hostnames/hostname")
        hostname = hn_el.get("name") if hn_el is not None else None

        ip_id = safe_id("ip", ip)
        label = ip + (f"\n{hostname}" if hostname else "")
        nodes.append(node(ip_id, label, "IP", "#8B5CF6"))
        edges.append(edge(rid, ip_id))

        if mac_el is not None:
            mac = mac_el.get("addr", "")
            vendor = mac_el.get("vendor", "")
            mid = safe_id("mac", mac)
            nodes.append(node(mid, mac + (f"\n{vendor}" if vendor else ""), "Text", "#374151"))
            edges.append(edge(ip_id, mid, "MAC", "dashed"))

        ports_el = host.find("ports")
        if ports_el:
            for port in ports_el.findall("port"):
                if port.find("state") is None or port.find("state").get("state") != "open":
                    continue
                pid = port.get("portid", "?")
                proto = port.get("protocol", "tcp")
                svc = port.find("service")
                sname = svc.get("name", "") if svc is not None else ""
                sprod = svc.get("product", "") if svc is not None else ""
                sver  = svc.get("version", "") if svc is not None else ""
                lbl = f"{proto}/{pid}"
                if sname: lbl += f"\n{sname}"
                if sprod: lbl += f" {sprod}"
                if sver:  lbl += f" {sver}"
                pnid = safe_id("port", ip_id, proto, pid)
                nodes.append(node(pnid, lbl, "Text", "#1D4ED8"))
                edges.append(edge(ip_id, pnid, "открыт"))

    if len(nodes) == 1:
        return err(f"Нет доступных хостов: «{scan_target}»")
    return {"nodes": nodes, "edges": edges}

# ──────────────────────────────────────────────
# SCAN — MASSCAN
# ──────────────────────────────────────────────

def run_masscan(target):
    parts = target.split()
    base = parts[0]
    extra = parts[1:] if len(parts) > 1 else ["-p1-1024"]
    out, er, rc = run_cmd(["masscan"] + [base] + extra + ["--rate=1000", "-oX", "-"], timeout=180)
    if out is None:
        return err("masscan не найден. Установите: sudo pacman -S masscan")
    if not out.strip() or "<nmaprun" not in out:
        return err(f"masscan: нет результатов. {er[:200] if er else ''}")
    return parse_nmap_xml(out, base)

# ──────────────────────────────────────────────
# SCAN — NAABU
# ──────────────────────────────────────────────

def run_naabu(target):
    out, er, rc = run_cmd(["naabu", "-host", target, "-json"], timeout=120)
    if out is None:
        return err("naabu не найден. Установите: go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest")
    nodes, edges = [], []
    rid = safe_id("naabu", target)
    nodes.append(node(rid, f"Naabu: {target}", "IP", "#8B5CF6"))
    for line in out.splitlines():
        try:
            d = json.loads(line)
            ip = d.get("ip",""); port = d.get("port",""); proto = d.get("protocol","tcp")
            lbl = f"{ip}\n{proto}/{port}"
            nid = safe_id("naabu", ip, port)
            nodes.append(node(nid, lbl, "IP", "#6366F1"))
            edges.append(edge(rid, nid, f"{proto}/{port}"))
        except: pass
    if len(nodes) == 1:
        return err(f"naabu: нет открытых портов для «{target}»")
    return {"nodes": nodes, "edges": edges}

# ──────────────────────────────────────────────
# SUBDOMAINS — SUBFINDER
# ──────────────────────────────────────────────

def run_subfinder(target):
    out, er, rc = run_cmd(["subfinder", "-d", target, "-silent"], timeout=120)
    if out is None:
        return err("subfinder не найден. Установите: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
    return subdomains_to_graph(out, target, "Subfinder", "#EC4899")

# ──────────────────────────────────────────────
# SUBDOMAINS — AMASS
# ──────────────────────────────────────────────

def run_amass(target):
    out, er, rc = run_cmd(["amass", "enum", "-passive", "-d", target], timeout=180)
    if out is None:
        return err("amass не найден. Установите: sudo pacman -S amass  или  go install github.com/owasp-amass/amass/v4/...@master")
    return subdomains_to_graph(out, target, "Amass", "#EC4899")

# ──────────────────────────────────────────────
# SUBDOMAINS — FINDOMAIN
# ──────────────────────────────────────────────

def run_findomain(target):
    out, er, rc = run_cmd(["findomain", "-t", target, "-q"], timeout=120)
    if out is None:
        return err("findomain не найден. Установите: sudo pacman -S findomain  или  yay -S findomain-bin")
    return subdomains_to_graph(out, target, "Findomain", "#EC4899")

def subdomains_to_graph(out, target, tool, color):
    nodes, edges = [], []
    rid = safe_id(tool.lower(), target)
    nodes.append(node(rid, f"{tool}: {target}", "Domain", "#4B5563"))
    seen = set()
    for line in out.splitlines():
        sub = line.strip().lower()
        if not sub or sub in seen or target not in sub: continue
        seen.add(sub)
        nid = safe_id("sub", sub)
        nodes.append(node(nid, sub, "Domain", color))
        edges.append(edge(rid, nid, "subdomain"))
    if len(nodes) == 1:
        return err(f"{tool}: поддомены не найдены для «{target}»")
    return {"nodes": nodes, "edges": edges}

# ──────────────────────────────────────────────
# DNS
# ──────────────────────────────────────────────

def run_dns(target):
    try:
        import dns.resolver
        return dns_full(target)
    except ImportError:
        return dns_socket(target)

def dns_full(target):
    import dns.resolver
    nodes, edges = [], []
    rid = safe_id("dns", target)
    nodes.append(node(rid, f"DNS: {target}", "Domain", "#EC4899"))
    types = {"A": ("#8B5CF6","IP"), "AAAA": ("#8B5CF6","IP"), "MX": ("#10B981","Domain"),
             "NS": ("#6366F1","Domain"), "TXT": ("#4B5563","Text"), "CNAME": ("#F59E0B","Domain")}
    for rt, (col, nt) in types.items():
        try:
            for rd in dns.resolver.resolve(target, rt, lifetime=5):
                val = str(rd).strip().rstrip(".")
                nid = safe_id("dns", rt, val)
                nodes.append(node(nid, f"{rt}:\n{val}", nt, col))
                edges.append(edge(rid, nid, rt))
        except: pass
    if len(nodes) == 1:
        return err(f"DNS: записи не найдены для «{target}»")
    return {"nodes": nodes, "edges": edges}

def dns_socket(target):
    nodes, edges = [], []
    rid = safe_id("dns", target)
    nodes.append(node(rid, f"DNS: {target}", "Domain", "#EC4899"))
    try:
        seen = set()
        for info in socket.getaddrinfo(target, None):
            ip = info[4][0]
            if ip in seen: continue
            seen.add(ip)
            rt = "AAAA" if ":" in ip else "A"
            nid = safe_id("dns_a", ip)
            nodes.append(node(nid, f"{rt}:\n{ip}", "IP", "#8B5CF6"))
            edges.append(edge(rid, nid, rt))
    except socket.gaierror:
        return err(f"DNS: не удалось разрешить «{target}»")
    hint = safe_id("dns_hint", target)
    nodes.append(node(hint, "pip install dnspython\nдля полных записей", "Text", "#374151"))
    edges.append(edge(rid, hint, "совет", "dashed"))
    return {"nodes": nodes, "edges": edges}

# ──────────────────────────────────────────────
# WHOIS
# ──────────────────────────────────────────────

def run_whois(target):
    out, er, rc = run_cmd(["whois", target], timeout=30)
    if out is None:
        return err("whois не найден. Установите: sudo pacman -S whois")
    if not out:
        return err(f"whois: нет данных для «{target}»")
    return parse_whois(out, target)

def parse_whois(raw, target):
    nodes, edges = [], []
    ts = safe_id("whois", target)
    nodes.append(node(ts, f"Whois: {target}", "Domain", "#EC4899"))
    fields = {
        "registrar": ("Registrar", "#6366F1"), "registrant name": ("Владелец", "#3B82F6"),
        "registrant email": ("Email", "#10B981"), "registrant country": ("Страна", "#EF4444"),
        "registrant org": ("Организация", "#F59E0B"), "name server": ("NS", "#8B5CF6"),
        "creation date": ("Создан", "#4B5563"), "updated date": ("Обновлён", "#4B5563"),
        "registry expiry date": ("Истекает", "#EF4444"), "expiry date": ("Истекает", "#EF4444"),
        "orgname": ("Организация", "#F59E0B"), "country": ("Страна", "#EF4444"),
        "cidr": ("CIDR", "#8B5CF6"), "netrange": ("NetRange", "#8B5CF6"),
        "admin email": ("Admin Email", "#10B981"),
    }
    seen = set()
    for line in raw.splitlines():
        if ":" not in line: continue
        k, _, v = line.partition(":")
        k = k.strip().lower(); v = v.strip()
        if not v or v.startswith("http"): continue
        for fk, (flabel, fcolor) in fields.items():
            if k == fk:
                nid = safe_id("wi", fk, v)
                if nid in seen: break
                seen.add(nid)
                nodes.append(node(nid, f"{flabel}:\n{v}", "Text", fcolor))
                edges.append(edge(ts, nid, flabel))
                break
    if len(nodes) == 1:
        nid = safe_id("wi_raw", target)
        nodes.append(node(nid, "\n".join(raw.splitlines()[:15]), "Text", "#374151"))
        edges.append(edge(ts, nid, "raw", "dashed"))
    return {"nodes": nodes, "edges": edges}

# ──────────────────────────────────────────────
# REVERSE IP
# ──────────────────────────────────────────────

def run_reverseip(ip):
    try:
        body = fetch_url(f"https://api.hackertarget.com/reverseiplookup/?q={ip}")
        if not body or "error" in body.lower():
            return err(f"Reverse IP: нет доменов для «{ip}»")
        return parse_reverse_ip(body, ip)
    except Exception as e:
        return err(f"Reverse IP ошибка: {e}")

def parse_reverse_ip(raw, ip):
    nodes, edges = [], []
    rid = safe_id("revip", ip)
    nodes.append(node(rid, ip, "IP", "#8B5CF6"))
    for domain in [d.strip() for d in raw.splitlines() if d.strip()][:50]:
        nid = safe_id("revip_d", domain)
        nodes.append(node(nid, domain, "Domain", "#EC4899"))
        edges.append(edge(rid, nid, "домен"))
    if len(nodes) == 1:
        return err(f"Домены для «{ip}» не найдены")
    return {"nodes": nodes, "edges": edges}

# ──────────────────────────────────────────────
# FIERCE
# ──────────────────────────────────────────────

def run_fierce(target):
    out, er, rc = run_cmd(["fierce", "--domain", target], timeout=120)
    if out is None:
        return err("fierce не найден. Установите: sudo pacman -S fierce  или  pip install fierce")
    nodes, edges = [], []
    rid = safe_id("fierce", target)
    nodes.append(node(rid, f"Fierce: {target}", "Domain", "#EC4899"))
    seen = set()
    for line in out.splitlines():
        m = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', line)
        dm = re.search(r'([\w\-]+\.' + re.escape(target) + r')', line)
        if m:
            ip = m.group(1)
            if ip not in seen:
                seen.add(ip)
                nid = safe_id("fierce_ip", ip)
                nodes.append(node(nid, ip, "IP", "#8B5CF6"))
                edges.append(edge(rid, nid, "IP"))
        if dm:
            sub = dm.group(1)
            if sub not in seen:
                seen.add(sub)
                nid = safe_id("fierce_sub", sub)
                nodes.append(node(nid, sub, "Domain", "#F59E0B"))
                edges.append(edge(rid, nid, "subdomain", "dashed"))
    if len(nodes) == 1:
        return err(f"Fierce: ничего не найдено для «{target}»")
    return {"nodes": nodes, "edges": edges}

# ──────────────────────────────────────────────
# WEB — WHATWEB
# ──────────────────────────────────────────────

def run_whatweb(target):
    out, er, rc = run_cmd(["whatweb", "--log-json=-", target], timeout=60)
    if out is None:
        return err("whatweb не найден. Установите: sudo pacman -S whatweb")
    nodes, edges = [], []
    rid = safe_id("ww", target)
    nodes.append(node(rid, target, "Domain", "#EC4899"))
    try:
        entries = json.loads(out) if out.startswith("[") else [json.loads(l) for l in out.splitlines() if l.strip().startswith("{")]
        for entry in entries:
            plugins = entry.get("plugins", {})
            for pname, pdata in plugins.items():
                versions = pdata.get("version", [])
                strings = pdata.get("string", [])
                val = pname
                if versions: val += f"\n{versions[0]}"
                elif strings: val += f"\n{strings[0][:40]}"
                nid = safe_id("ww_p", pname)
                clr = "#10B981" if "cms" in pname.lower() or "wordpress" in pname.lower() else "#1D4ED8"
                nodes.append(node(nid, val, "Text", clr))
                edges.append(edge(rid, nid, "обнаружен"))
    except Exception as e:
        # Fallback: plain text
        for line in out.splitlines()[:20]:
            if line.strip():
                nid = safe_id("ww_ln", line[:30])
                nodes.append(node(nid, line.strip()[:80], "Text", "#374151"))
                edges.append(edge(rid, nid))
    if len(nodes) == 1:
        return err(f"WhatWeb: нет данных для «{target}»")
    return {"nodes": nodes, "edges": edges}

# ──────────────────────────────────────────────
# WEB — HTTPX
# ──────────────────────────────────────────────

def run_httpx(target):
    out, er, rc = run_cmd(["httpx", "-u", target, "-json", "-title", "-tech-detect", "-status-code", "-silent"], timeout=60)
    if out is None:
        return err("httpx не найден. Установите: go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest")
    nodes, edges = [], []
    rid = safe_id("httpx", target)
    nodes.append(node(rid, target, "Domain", "#EC4899"))
    for line in out.splitlines():
        try:
            d = json.loads(line)
            url = d.get("url", target)
            status = d.get("status_code", "")
            title = d.get("title", "")
            techs = d.get("tech", [])

            url_id = safe_id("httpx_url", url)
            url_label = url
            if status: url_label += f"\nHTTP {status}"
            if title: url_label += f"\n{title[:40]}"
            nodes.append(node(url_id, url_label, "Domain", "#6366F1"))
            edges.append(edge(rid, url_id, "http"))

            for tech in techs[:10]:
                tid = safe_id("httpx_t", tech)
                nodes.append(node(tid, tech, "Text", "#10B981"))
                edges.append(edge(url_id, tid, "tech", "dashed"))
        except: pass
    if len(nodes) == 1:
        return err(f"httpx: нет ответа от «{target}»")
    return {"nodes": nodes, "edges": edges}

# ──────────────────────────────────────────────
# WEB — NIKTO
# ──────────────────────────────────────────────

def run_nikto(target):
    out, er, rc = run_cmd(["nikto", "-h", target, "-Format", "txt", "-nointeractive"], timeout=180)
    if out is None:
        return err("nikto не найден. Установите: sudo pacman -S nikto")
    nodes, edges = [], []
    rid = safe_id("nikto", target)
    nodes.append(node(rid, f"Nikto: {target}", "Domain", "#EC4899"))
    for line in out.splitlines():
        if line.startswith("+") and len(line) > 3:
            txt = line[1:].strip()[:120]
            clr = "#EF4444" if any(w in txt.lower() for w in ["vuln","critical","inject","xss","sql"]) else "#F59E0B"
            nid = safe_id("nikto_l", txt[:40])
            nodes.append(node(nid, txt, "Text", clr))
            edges.append(edge(rid, nid, "найдено"))
    if len(nodes) == 1:
        return err(f"Nikto: нет результатов для «{target}»")
    return {"nodes": nodes, "edges": edges}

# ──────────────────────────────────────────────
# OSINT — SHERLOCK
# ──────────────────────────────────────────────

def run_sherlock(username):
    out, er, rc = run_cmd(["sherlock", username, "--print-found", "--no-color"], timeout=120)
    if out is None:
        return err("sherlock не найден. Установите: sudo pacman -S sherlock  или  pip install sherlock-project")
    nodes, edges = [], []
    rid = safe_id("sherlock", username)
    nodes.append(node(rid, f"@{username}", "Person", "#3B82F6"))
    for line in out.splitlines():
        if line.startswith("[+]"):
            url = line[3:].strip()
            site = url.split("/")[2] if url.startswith("http") and "/" in url[8:] else url[:40]
            nid = safe_id("sh_site", site)
            nodes.append(node(nid, f"{site}\n{url[:60]}", "Domain", "#10B981"))
            edges.append(edge(rid, nid, "найден"))
    if len(nodes) == 1:
        return err(f"Sherlock: «{username}» не найден ни на одной платформе")
    return {"nodes": nodes, "edges": edges}

# ──────────────────────────────────────────────
# OSINT — MAIGRET
# ──────────────────────────────────────────────

def run_maigret(username):
    out, er, rc = run_cmd(["maigret", username, "--no-color", "-a"], timeout=180)
    if out is None:
        return err("maigret не найден. Установите: pip install maigret")
    nodes, edges = [], []
    rid = safe_id("maigret", username)
    nodes.append(node(rid, f"@{username}", "Person", "#3B82F6"))
    for line in out.splitlines():
        if "[+]" in line:
            url_m = re.search(r'https?://\S+', line)
            site_m = re.search(r'\[.\]\s+(\S+)', line)
            site = site_m.group(1) if site_m else "?"
            url = url_m.group(0) if url_m else site
            nid = safe_id("mg_site", site)
            nodes.append(node(nid, f"{site}\n{url[:60]}", "Domain", "#10B981"))
            edges.append(edge(rid, nid, "найден"))
    if len(nodes) == 1:
        return err(f"Maigret: «{username}» не найден")
    return {"nodes": nodes, "edges": edges}

# ──────────────────────────────────────────────
# OSINT — PHONEINFOGA
# ──────────────────────────────────────────────

def run_phoneinfoga(number):
    out, er, rc = run_cmd(["phoneinfoga", "scan", "-n", number], timeout=60)
    if out is None:
        return err("phoneinfoga не найден. Установите: yay -S phoneinfoga-bin  или  https://github.com/sundowndev/phoneinfoga")
    nodes, edges = [], []
    rid = safe_id("phone", number)
    nodes.append(node(rid, number, "Phone", "#F59E0B"))
    for line in out.splitlines():
        if ":" in line and line.strip():
            k, _, v = line.partition(":")
            k = k.strip(); v = v.strip()
            if v and len(v) > 1:
                nid = safe_id("phone_f", k, v[:20])
                nodes.append(node(nid, f"{k}:\n{v[:80]}", "Text", "#6366F1"))
                edges.append(edge(rid, nid, k))
    if len(nodes) == 1:
        raw_id = safe_id("phone_raw", number)
        nodes.append(node(raw_id, out[:300] if out else "Нет данных", "Text", "#374151"))
        edges.append(edge(rid, raw_id, "raw", "dashed"))
    return {"nodes": nodes, "edges": edges}

# ──────────────────────────────────────────────
# OSINT — SPIDERFOOT
# ──────────────────────────────────────────────

def run_spiderfoot(target):
    out, er, rc = run_cmd(["sfp.py", "-s", target, "-m", "sfp_dnsresolve,sfp_whois,sfp_ssl,sfp_subdomain", "-q"], timeout=180)
    if out is None:
        return err("SpiderFoot не найден. Установите: pip install spiderfoot  или  https://github.com/smicallef/spiderfoot")
    nodes, edges = [], []
    rid = safe_id("sf", target)
    nodes.append(node(rid, f"SpiderFoot: {target}", "Text", "#4B5563"))
    seen = set()
    for line in out.splitlines():
        parts = line.split(",")
        if len(parts) >= 3:
            dtype = parts[1].strip()
            val = parts[2].strip()
            if val and val not in seen:
                seen.add(val)
                nid = safe_id("sf_r", val[:30])
                clr = "#8B5CF6" if "IP" in dtype else "#EC4899" if "DOMAIN" in dtype else "#10B981"
                nodes.append(node(nid, f"{dtype}\n{val[:80]}", "Text", clr))
                edges.append(edge(rid, nid, dtype))
    if len(nodes) == 1:
        return err(f"SpiderFoot: нет данных для «{target}»")
    return {"nodes": nodes, "edges": edges}

# ──────────────────────────────────────────────
# CERT — CRT.SH
# ──────────────────────────────────────────────

def run_crtsh(target):
    try:
        body = fetch_url(f"https://crt.sh/?q=%.{urllib.parse.quote(target)}&output=json")
        entries = json.loads(body)
    except Exception as e:
        return err(f"crt.sh ошибка: {e}")

    nodes, edges = [], []
    rid = safe_id("crtsh", target)
    nodes.append(node(rid, f"crt.sh: {target}", "Domain", "#EC4899"))

    seen_names = set()
    seen_issuers = set()
    for entry in entries[:80]:
        common = entry.get("common_name","").strip()
        name_value = entry.get("name_value","").strip()
        issuer = entry.get("issuer_name","").strip()
        not_before = entry.get("not_before","")[:10]
        not_after = entry.get("not_after","")[:10]

        for name in set([common] + name_value.splitlines()):
            name = name.strip().lstrip("*.")
            if not name or name in seen_names: continue
            seen_names.add(name)
            nid = safe_id("crt_name", name)
            nodes.append(node(nid, name, "Domain", "#6366F1"))
            edges.append(edge(rid, nid, "CN"))

            if issuer and issuer not in seen_issuers:
                seen_issuers.add(issuer)
                short = issuer.split(",")[0].replace("CN=","")[:40]
                iid = safe_id("crt_iss", short)
                nodes.append(node(iid, f"Issuer:\n{short}\n{not_before} – {not_after}", "Text", "#F59E0B"))
                edges.append(edge(nid, iid, "выдан", "dashed"))

    if len(nodes) == 1:
        return err(f"crt.sh: сертификаты не найдены для «{target}»")
    return {"nodes": nodes, "edges": edges}

# ──────────────────────────────────────────────
# CERT — CERTSPOTTER
# ──────────────────────────────────────────────

def run_certspotter(target):
    try:
        body = fetch_url(f"https://api.certspotter.com/v1/issuances?domain={urllib.parse.quote(target)}&include_subdomains=true&expand=dns_names&expand=issuer")
        entries = json.loads(body)
    except Exception as e:
        return err(f"CertSpotter ошибка: {e}")

    nodes, edges = [], []
    rid = safe_id("certspot", target)
    nodes.append(node(rid, f"CertSpotter: {target}", "Domain", "#EC4899"))
    seen = set()
    for entry in entries[:60]:
        for dns_name in entry.get("dns_names", []):
            dns_name = dns_name.lstrip("*.")
            if not dns_name or dns_name in seen: continue
            seen.add(dns_name)
            nid = safe_id("cs_dn", dns_name)
            nodes.append(node(nid, dns_name, "Domain", "#6366F1"))
            edges.append(edge(rid, nid, "cert"))
        issuer = entry.get("issuer",{})
        org = issuer.get("o","")
        if org and org not in seen:
            seen.add(org)
            iid = safe_id("cs_iss", org)
            nodes.append(node(iid, f"Issuer:\n{org}", "Text", "#F59E0B"))
            edges.append(edge(rid, iid, "выдан", "dashed"))

    if len(nodes) == 1:
        return err(f"CertSpotter: сертификаты не найдены для «{target}»")
    return {"nodes": nodes, "edges": edges}

# ──────────────────────────────────────────────
# INTERNET SCANNER — SHODAN
# ──────────────────────────────────────────────

def run_shodan(target, apikey):
    if not apikey:
        return err("Введите API ключ Shodan")
    try:
        enc = urllib.parse.quote(target)
        # Если похоже на IP — host lookup, иначе search
        is_ip = re.match(r'^\d{1,3}(\.\d{1,3}){3}$', target)
        if is_ip:
            body = fetch_url(f"https://api.shodan.io/shodan/host/{enc}?key={apikey}")
            data = json.loads(body)
            return parse_shodan_host(data, target)
        else:
            body = fetch_url(f"https://api.shodan.io/shodan/host/search?query={enc}&key={apikey}")
            data = json.loads(body)
            return parse_shodan_search(data, target)
    except Exception as e:
        return err(f"Shodan ошибка: {e}")

def parse_shodan_host(data, ip):
    nodes, edges = [], []
    rid = safe_id("shodan", ip)
    org = data.get("org",""); country = data.get("country_name","")
    nodes.append(node(rid, f"{ip}\n{org}\n{country}", "IP", "#8B5CF6"))
    for port_data in data.get("data", [])[:30]:
        port = port_data.get("port","")
        transport = port_data.get("transport","tcp")
        product = port_data.get("product","")
        version = port_data.get("version","")
        lbl = f"{transport}/{port}"
        if product: lbl += f"\n{product}"
        if version: lbl += f" {version}"
        nid = safe_id("sh_port", ip, port)
        nodes.append(node(nid, lbl, "Text", "#1D4ED8"))
        edges.append(edge(rid, nid, "открыт"))
    vulns = data.get("vulns", {})
    for cve in list(vulns.keys())[:10]:
        nid = safe_id("sh_vuln", cve)
        nodes.append(node(nid, cve, "Text", "#EF4444"))
        edges.append(edge(rid, nid, "уязвимость", "dashed"))
    return {"nodes": nodes, "edges": edges}

def parse_shodan_search(data, query):
    nodes, edges = [], []
    rid = safe_id("shodan_q", query)
    total = data.get("total", 0)
    nodes.append(node(rid, f"Shodan: {query}\n{total} результатов", "Text", "#4B5563"))
    for match in data.get("matches", [])[:30]:
        ip = match.get("ip_str","?")
        port = match.get("port","?")
        org = match.get("org","")
        country = match.get("location",{}).get("country_name","")
        nid = safe_id("sh_m", ip, port)
        lbl = f"{ip}:{port}"
        if org: lbl += f"\n{org}"
        if country: lbl += f" · {country}"
        nodes.append(node(nid, lbl, "IP", "#8B5CF6"))
        edges.append(edge(rid, nid))
    if len(nodes) == 1:
        return err(f"Shodan: нет результатов для «{query}»")
    return {"nodes": nodes, "edges": edges}

# ──────────────────────────────────────────────
# INTERNET SCANNER — CENSYS
# ──────────────────────────────────────────────

def run_censys(target, api_id, api_secret):
    if not api_id or not api_secret:
        return err("Введите Censys API ID и Secret")
    try:
        is_ip = re.match(r'^\d{1,3}(\.\d{1,3}){3}$', target)
        if is_ip:
            url = f"https://search.censys.io/api/v2/hosts/{urllib.parse.quote(target)}"
        else:
            url = f"https://search.censys.io/api/v2/hosts/search?q={urllib.parse.quote(target)}&per_page=25"

        import base64
        creds = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()
        req = urllib.request.Request(url, headers={"Authorization": f"Basic {creds}", "User-Agent": "KnotTrace/2.0"})
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read().decode())

        nodes, edges = [], []
        if is_ip:
            result = data.get("result", {})
            rid = safe_id("censys", target)
            nodes.append(node(rid, target, "IP", "#8B5CF6"))
            for svc in result.get("services", [])[:20]:
                port = svc.get("port","?"); proto = svc.get("transport_protocol","")
                name = svc.get("service_name","")
                nid = safe_id("cens_svc", target, port)
                nodes.append(node(nid, f"{proto}/{port}\n{name}", "Text", "#1D4ED8"))
                edges.append(edge(rid, nid, "сервис"))
        else:
            rid = safe_id("censys_q", target)
            nodes.append(node(rid, f"Censys: {target}", "Text", "#4B5563"))
            for hit in data.get("result", {}).get("hits", [])[:25]:
                ip = hit.get("ip","?")
                names = hit.get("autonomous_system",{}).get("name","")
                nid = safe_id("cens_h", ip)
                nodes.append(node(nid, f"{ip}\n{names}", "IP", "#8B5CF6"))
                edges.append(edge(rid, nid))

        if len(nodes) == 1:
            return err(f"Censys: нет результатов для «{target}»")
        return {"nodes": nodes, "edges": edges}
    except Exception as e:
        return err(f"Censys ошибка: {e}")

# ──────────────────────────────────────────────
# INTERNET SCANNER — ZOOMEYE
# ──────────────────────────────────────────────

def run_zoomeye(target, apikey):
    if not apikey:
        return err("Введите API ключ ZoomEye")
    try:
        enc = urllib.parse.quote(target)
        req = urllib.request.Request(
            f"https://api.zoomeye.org/host/search?query={enc}&page=1",
            headers={"API-KEY": apikey, "User-Agent": "KnotTrace/2.0"}
        )
        with urllib.request.urlopen(req, timeout=15) as r:
            data = json.loads(r.read().decode())

        nodes, edges = [], []
        rid = safe_id("zoomeye_q", target)
        total = data.get("total", 0)
        nodes.append(node(rid, f"ZoomEye: {target}\n{total} результатов", "Text", "#4B5563"))
        for match in data.get("matches", [])[:30]:
            ip = match.get("ip","?")
            portinfo = match.get("portinfo", {})
            port = portinfo.get("port","?")
            service = portinfo.get("service","")
            app = portinfo.get("app","")
            country = match.get("geoinfo",{}).get("country",{}).get("names",{}).get("en","")
            nid = safe_id("ze_m", ip, port)
            lbl = f"{ip}:{port}"
            if service: lbl += f"\n{service}"
            if app: lbl += f" · {app}"
            if country: lbl += f"\n{country}"
            nodes.append(node(nid, lbl, "IP", "#8B5CF6"))
            edges.append(edge(rid, nid))

        if len(nodes) == 1:
            return err(f"ZoomEye: нет результатов для «{target}»")
        return {"nodes": nodes, "edges": edges}
    except Exception as e:
        return err(f"ZoomEye ошибка: {e}")

# ──────────────────────────────────────────────
# HTTP HANDLER
# ──────────────────────────────────────────────

ROUTES = {
    "/nmap":        lambda p: run_nmap(p["target"], p.get("mode","quick")),
    "/masscan":     lambda p: run_masscan(p["target"]),
    "/naabu":       lambda p: run_naabu(p["target"]),
    "/subfinder":   lambda p: run_subfinder(p["target"]),
    "/amass":       lambda p: run_amass(p["target"]),
    "/findomain":   lambda p: run_findomain(p["target"]),
    "/dns":         lambda p: run_dns(p["target"]),
    "/whois":       lambda p: run_whois(p["target"]),
    "/reverseip":   lambda p: run_reverseip(p["target"]),
    "/fierce":      lambda p: run_fierce(p["target"]),
    "/whatweb":     lambda p: run_whatweb(p["target"]),
    "/httpx":       lambda p: run_httpx(p["target"]),
    "/nikto":       lambda p: run_nikto(p["target"]),
    "/sherlock":    lambda p: run_sherlock(p["target"]),
    "/maigret":     lambda p: run_maigret(p["target"]),
    "/phoneinfoga": lambda p: run_phoneinfoga(p["target"]),
    "/spiderfoot":  lambda p: run_spiderfoot(p["target"]),
    "/crtsh":       lambda p: run_crtsh(p["target"]),
    "/certspotter": lambda p: run_certspotter(p["target"]),
    "/shodan":      lambda p: run_shodan(p["target"], p.get("apikey","")),
    "/censys":      lambda p: run_censys(p["target"], p.get("api_id",""), p.get("api_secret","")),
    "/zoomeye":     lambda p: run_zoomeye(p["target"], p.get("apikey","")),
    "/ping":        lambda p: {"status": "ok"},
}

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print(f"[KnotTrace] {fmt % args}")

    def send_json(self, data, status=200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            print("[KnotTrace] Предупреждение: Клиент разорвал соединение (тайм-аут или закрытие вкладки).")
        except Exception as e:
            print(f"[KnotTrace] Ошибка при отправке данных: {e}")

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        raw_params = parse_qs(parsed.query)
        params = {k: v[0] for k, v in raw_params.items()}

        handler = ROUTES.get(parsed.path)
        if handler:
            if parsed.path != "/ping" and not params.get("target"):
                self.send_json({"error": "Укажите параметр ?target=..."}, 400)
                return
            print(f"[KnotTrace] {parsed.path} → {params.get('target','')}")
            self.send_json(handler(params))
        else:
            self.send_response(404)
            self.end_headers()

if __name__ == "__main__":
    print("╔══════════════════════════════════════════╗")
    print("║  KnotTrace v2 — сервер запущен           ║")
    print(f"║  http://localhost:{PORT}                ║")
    print("║  при ошибке пишите в тг @ParanoidOpsec   ║")
    print("║  Откройте index.html в браузере          ║")
    print("╚══════════════════════════════════════════╝")
    server = http.server.HTTPServer(("localhost", PORT), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[KnotTrace] Остановлен.")
