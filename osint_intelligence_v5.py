#!/usr/bin/env python3
"""
OSINT INTELLIGENCE GATHERING SYSTEM v5.2
Fuentes públicas y APIs autorizadas: DNS (DoH), TLS, cabeceras HTTP, HIBP, crt.sh, etc.
El JSON final agrega huella técnica y correlación; no accede a cuentas privadas ni credenciales.
"""

import hashlib
import json
import os
import re
import socket
import ssl
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import quote, unquote, urlparse

import requests

DISCLAIMER_ES = (
    "Solo se agregan datos obtenidos de fuentes públicas o con APIs documentadas "
    "(p. ej. registros DNS, certificados TLS visibles, HIBP con clave propia). "
    "No se accede a contenidos privados de redes sociales, buzones ni sistemas protegidos."
)


class OSINTv5:
    DOH_URL = "https://cloudflare-dns.com/dns-query"

    def __init__(self) -> None:
        self.s = requests.Session()
        self.s.headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ),
            "Accept-Language": "es-ES,es;q=0.9,en;q=0.8",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
        self.timeout = 14
        self.email_re = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
        self.phone_re = re.compile(r"(?:\+?(?:54|1|44|34|52)\s?[\d\s\-\(\)]{8,15})")
        self.ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

    # ----- utilidades JSON -----
    @staticmethod
    def _json_safe(obj: Any) -> Any:
        if isinstance(obj, dict):
            return {str(k): OSINTv5._json_safe(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [OSINTv5._json_safe(x) for x in obj]
        if isinstance(obj, set):
            return sorted(str(x) for x in obj)
        if isinstance(obj, (str, int, float, bool)) or obj is None:
            return obj
        return str(obj)

    def _meta_base(self) -> Dict[str, Any]:
        return {
            "version": "5.2",
            "generado_utc": datetime.now(timezone.utc).isoformat(),
            "aviso_legal": DISCLAIMER_ES,
            "hibp_api_configurada": bool(os.environ.get("HIBP_API_KEY", "").strip()),
        }

    # ===== VALIDACION =====
    def val_email(self, e: str) -> bool:
        if not e or "@" not in e:
            return False
        p = e.split("@")
        return len(p) == 2 and bool(p[0]) and "." in p[1]

    def norm_phone(self, n: str) -> str:
        limpio = re.sub(r"[^\d+]", "", n)
        if "54" in limpio or limpio.startswith("11") or limpio.startswith("911"):
            if not limpio.startswith("+"):
                if limpio.startswith("54"):
                    limpio = "+" + limpio
                elif limpio.startswith("9"):
                    limpio = "+54" + limpio
                elif limpio.startswith("11"):
                    limpio = "+54911" + limpio[2:]
            if len(limpio) >= 13:
                return f"{limpio[:3]} {limpio[3:4]} {limpio[4:6]} {limpio[6:10]}-{limpio[10:]}"
        return limpio

    def detect_type(self, s: str) -> Tuple[str, str]:
        s = s.strip()
        if s.startswith("http"):
            return s, "url"
        if self.val_email(s):
            return s, "email"
        if s.startswith("@"):
            return s[1:], "username"
        digits = re.sub(r"\D", "", s)
        if len(digits) >= 8:
            return self.norm_phone(s), "telefono"
        return s, "nombre"

    def _hostname_from(self, target: str) -> Optional[str]:
        t = target.strip()
        if t.startswith("http"):
            h = urlparse(t).hostname
            return h
        return t.replace("www.", "").split("/")[0] or None

    # ===== DNS (DoH, datos reales sin librerías extra) =====
    def dns_over_https(self, domain: str, types: Optional[List[str]] = None) -> Dict[str, Any]:
        types = types or ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
        out: Dict[str, Any] = {"dominio": domain, "registros": {}}
        for rtype in types:
            try:
                r = self.s.get(
                    self.DOH_URL,
                    params={"name": domain, "type": rtype},
                    headers={"accept": "application/dns-json"},
                    timeout=self.timeout,
                )
                if r.status_code != 200:
                    continue
                data = r.json()
                answers = data.get("Answer") or []
                vals: List[str] = []
                for a in answers:
                    if a.get("type") == 16:  # TXT
                        raw = a.get("data", "").strip('"')
                        vals.append(raw)
                    elif "data" in a:
                        vals.append(str(a["data"]))
                if vals:
                    out["registros"][rtype] = sorted(set(vals))
            except Exception as ex:
                out.setdefault("errores", []).append(f"{rtype}: {ex}")
        return out

    # ===== TLS (certificado público del servidor) =====
    def tls_certificate_public(self, hostname: str, port: int = 443) -> Dict[str, Any]:
        res: Dict[str, Any] = {"host": hostname, "puerto": port, "subject": None, "issuer": None, "sans": [], "valido_desde": None, "valido_hasta": None}
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
            if not cert:
                res["nota"] = "Certificado no parseado como dict (depende del SO/OpenSSL)."
                return res

            def _dn_tuple(t):
                if not t:
                    return None
                parts = []
                for item in t:
                    if isinstance(item, (list, tuple)) and len(item) == 2:
                        parts.append(f"{item[0][0]}={item[0][1]}")
                return ", ".join(parts) if parts else None

            res["subject"] = _dn_tuple(cert.get("subject"))
            res["issuer"] = _dn_tuple(cert.get("issuer"))
            nb = cert.get("notBefore")
            na = cert.get("notAfter")
            if nb:
                res["valido_desde"] = nb
            if na:
                res["valido_hasta"] = na
            san = cert.get("subjectAltName") or ()
            for kind, val in san:
                if kind == "DNS":
                    res["sans"].append(val)
            res["sans"] = sorted(set(res["sans"]))[:80]
        except Exception as ex:
            res["error"] = str(ex)
        return res

    def reverse_dns(self, ip: str) -> Dict[str, Any]:
        try:
            name, alias, _ = socket.gethostbyaddr(ip)
            return {"ip": ip, "ptr": name, "alias": list(alias)}
        except Exception as ex:
            return {"ip": ip, "ptr": None, "error": str(ex)}

    def gravatar_from_email(self, email: str) -> Dict[str, Any]:
        em = email.strip().lower()
        digest = hashlib.md5(em.encode("utf-8")).hexdigest()
        url = f"https://www.gravatar.com/avatar/{digest}?d=404"
        existe = False
        try:
            r = self.s.head(url, timeout=8, allow_redirects=True)
            existe = r.status_code == 200
        except Exception:
            pass
        return {"md5": digest, "url_perfil_publico": url, "avatar_publico_detectado": existe}

    # ===== EXTRACCION WEB + cabeceras =====
    def analizar_url_avanzado(self, url: str) -> Dict[str, Any]:
        print(f"\n  [*] Extracción (HTML + cabeceras + JSON-LD): {url}")
        resultado: Dict[str, Any] = {
            "tecnologias": set(),
            "ubicaciones": set(),
            "redes_sociales": set(),
            "emails": set(),
            "telefonos": set(),
            "bio_extraida": "",
            "cabeceras_http": {},
            "url_final": url,
            "codigo_http": None,
        }
        try:
            r = self.s.get(url, timeout=self.timeout)
            resultado["codigo_http"] = r.status_code
            resultado["url_final"] = r.url
            for k, v in r.headers.items():
                resultado["cabeceras_http"][k] = v
            if r.status_code != 200:
                return self._sets_to_lists(resultado)

            html = r.text
            techs: List[str] = []
            if "wp-content" in html:
                techs.append("WordPress")
            if "shopify" in html.lower():
                techs.append("Shopify")
            if "react" in html.lower():
                techs.append("React")
            if "next.js" in html.lower():
                techs.append("Next.js")
            resultado["tecnologias"].update(techs)

            bio = re.search(r'<meta name="description" content="(.*?)"', html, re.IGNORECASE)
            if not bio:
                bio = re.search(r'property="og:description" content="(.*?)"', html, re.IGNORECASE)
            if bio:
                resultado["bio_extraida"] = bio.group(1)[:500]

            potenciales_emails = self.email_re.findall(html)
            mailto_links = re.findall(r'mailto:([^\s"\'\?]+)', html, re.IGNORECASE)
            for e in potenciales_emails + mailto_links:
                if not any(x in e.lower() for x in ["example.com", "email.com", "sentry.io", "domain.com"]):
                    resultado["emails"].add(e)

            potenciales_tels = self.phone_re.findall(html)
            tel_links = re.findall(r"tel:([^\s\"']+)", html, re.IGNORECASE)
            for t in potenciales_tels + tel_links:
                t_limpio = re.sub(r"[^\d+]", "", t)
                if 8 <= len(t_limpio) <= 16 and not t_limpio.startswith(("177", "763", "158", "183")):
                    resultado["telefonos"].add(self.norm_phone(t))

            social_patterns = [
                "facebook.com/",
                "twitter.com/",
                "x.com/",
                "instagram.com/",
                "linkedin.com/in/",
                "youtube.com/@",
                "tiktok.com/@",
                "linktr.ee/",
            ]
            urls_en_pagina = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', html)
            for u in urls_en_pagina:
                u_clean = u.split("?")[0].split('"')[0].split("'")[0].rstrip("/")
                if any(u_clean.lower().endswith(ext) for ext in [".js", ".css", ".webp", ".jpg", ".png", ".ico", ".svg", ".json"]):
                    continue
                if any(p in u_clean.lower() for p in social_patterns):
                    if not any(
                        x in u_clean.lower()
                        for x in ["/p/", "/reels/", "/tv/", "/tags/", "/explore/", "/static/", "/rsrc.php/"]
                    ):
                        resultado["redes_sociales"].add(u_clean)

            json_lds = re.findall(r'<script type="application/ld\+json">(.*?)</script>', html, re.DOTALL | re.IGNORECASE)

            def extract_ld(obj: Any) -> None:
                if isinstance(obj, dict):
                    if "sameAs" in obj:
                        same = obj["sameAs"]
                        if isinstance(same, list):
                            resultado["redes_sociales"].update(same)
                        elif isinstance(same, str):
                            resultado["redes_sociales"].add(same)
                    if "email" in obj and isinstance(obj["email"], str):
                        resultado["emails"].add(obj["email"])
                    if "telephone" in obj and isinstance(obj["telephone"], str):
                        resultado["telefonos"].add(self.norm_phone(obj["telephone"]))
                    if "address" in obj and isinstance(obj["address"], dict) and "addressLocality" in obj["address"]:
                        resultado["ubicaciones"].add(obj["address"]["addressLocality"])
                    for v in obj.values():
                        extract_ld(v)
                elif isinstance(obj, list):
                    for item in obj:
                        extract_ld(item)

            for j in json_lds:
                try:
                    data = json.loads(j.strip())
                    extract_ld(data)
                except json.JSONDecodeError:
                    continue

            regiones = [
                "Argentina",
                "Buenos Aires",
                "CABA",
                "Córdoba",
                "Rosario",
                "Mendoza",
                "La Plata",
                "Tucumán",
                "España",
                "Madrid",
                "México",
                "Chile",
                "Uruguay",
                "Colombia",
                "Perú",
                "USA",
            ]
            for reg in regiones:
                if re.search(r"\b" + re.escape(reg) + r"\b", html, re.IGNORECASE):
                    resultado["ubicaciones"].add(reg)
        except Exception as e:
            print(f"  [-] Error Deep Scan: {e}")

        return self._sets_to_lists(resultado)

    @staticmethod
    def _sets_to_lists(resultado: Dict[str, Any]) -> Dict[str, Any]:
        for k, v in list(resultado.items()):
            if isinstance(v, set):
                resultado[k] = sorted(v)
        return resultado

    # ===== WHOIS + DNS + IP =====
    def ip_whois(self, target: str) -> Dict[str, Any]:
        print(f"\n  [*] Resolviendo IP/DNS para: {target}...")
        res: Dict[str, Any] = {
            "ips": [],
            "whois_data": {},
            "dns_records": {},
            "asn": "",
            "org": "",
            "pais": "",
            "ciudad": "",
            "isp": "",
            "ptr_por_ip": [],
        }
        try:
            domain = urlparse(target).hostname or target.replace("www.", "")
            if "http" not in target:
                domain = target
            ips = list({i[4][0] for i in socket.getaddrinfo(domain, None)})
            res["ips"] = ips
            for ip in ips[:3]:
                r = self.s.get(
                    f"http://ip-api.com/json/{ip}?fields=status,country,city,isp,org,as,query",
                    timeout=10,
                )
                if r.status_code == 200:
                    d = r.json()
                    res["pais"] = d.get("country", "") or res["pais"]
                    res["ciudad"] = d.get("city", "") or res["ciudad"]
                    res["isp"] = d.get("isp", "") or res["isp"]
                    res["org"] = d.get("org", "") or res["org"]
                    res["asn"] = d.get("as", "") or res["asn"]
                    print(f"  [+] IP: {ip} | Pais: {res['pais']} | Ciudad: {res['ciudad']} | ISP: {res['isp']}")
                res["ptr_por_ip"].append(self.reverse_dns(ip))
        except Exception as ex:
            print(f"  [-] Error IP: {ex}")
        return res

    # ===== HIBP (requiere API key para resultados fiables) =====
    def hibp(self, email: str) -> Dict[str, Any]:
        print(f"\n  [*] Have I Been Pwned: {email}")
        res: Dict[str, Any] = {
            "email": email,
            "comprometido": False,
            "brechas": [],
            "pastes": [],
            "total_cuentas": 0,
            "api_usada": False,
            "mensaje": "",
        }
        key = os.environ.get("HIBP_API_KEY", "").strip()
        headers = {"User-Agent": "OSINT-Intelligence-v5", "Add-Padding": "true"}
        if key:
            headers["hibp-api-key"] = key
            res["api_usada"] = True
        try:
            r = self.s.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email)}",
                headers=headers,
                timeout=12,
            )
            if r.status_code == 200:
                brechas = r.json()
                res["comprometido"] = True
                for b in brechas:
                    info = {
                        "nombre": b.get("Title", ""),
                        "dominio": b.get("Domain", ""),
                        "fecha": b.get("BreachDate", ""),
                        "registros": b.get("PwnCount", 0),
                        "tipos": b.get("DataClasses", []),
                        "verificado": b.get("IsVerified", False),
                    }
                    res["brechas"].append(info)
                    res["total_cuentas"] += int(info["registros"] or 0)
                    print(f"  [!] BRECHA: {info['nombre']} ({info['fecha']}) - {info['registros']:,} registros")
            elif r.status_code == 404:
                print("  [+] No encontrado en brechas conocidas (HIBP)")
            elif r.status_code == 401:
                res["mensaje"] = "HIBP devolvió 401: configure la variable de entorno HIBP_API_KEY (https://haveibeenpwned.com/API/Key)."
                print(f"  [-] {res['mensaje']}")
            else:
                res["mensaje"] = f"HIBP HTTP {r.status_code}"
                print(f"  [-] {res['mensaje']}")
        except Exception as ex:
            res["mensaje"] = str(ex)
            print(f"  [-] HIBP Error: {ex}")
        return res

    # ===== GITHUB =====
    def github(self, user: str) -> Dict[str, Any]:
        print(f"\n  [*] GitHub: {user}")
        res: Dict[str, Any] = {
            "encontrado": False,
            "nombre": "",
            "email": "",
            "ubicacion": "",
            "empresa": "",
            "bio": "",
            "blog": "",
            "repos": 0,
            "seguidores": 0,
            "url": "",
            "lenguajes": [],
            "commits_emails": set(),
        }
        try:
            r = self.s.get(f"https://api.github.com/users/{user}", timeout=self.timeout)
            if r.status_code == 200:
                d = r.json()
                res.update(
                    {
                        "encontrado": True,
                        "nombre": d.get("name", ""),
                        "email": d.get("email", ""),
                        "ubicacion": d.get("location", ""),
                        "empresa": d.get("company", ""),
                        "bio": d.get("bio", ""),
                        "blog": d.get("blog", ""),
                        "repos": d.get("public_repos", 0),
                        "seguidores": d.get("followers", 0),
                        "url": d.get("html_url", ""),
                    }
                )
                print(f"  [+] GitHub: {res['nombre']} | {res['ubicacion']} | {res['repos']} repos | {res['seguidores']} seguidores")
                if res["email"]:
                    print(f"      Email publico: {res['email']}")
                rr = self.s.get(f"https://api.github.com/users/{user}/repos?per_page=30", timeout=12)
                if rr.status_code == 200:
                    langs: Set[str] = set()
                    for repo in rr.json():
                        if repo.get("language"):
                            langs.add(repo["language"])
                    res["lenguajes"] = sorted(langs)
                rr2 = self.s.get(f"https://api.github.com/users/{user}/events/public?per_page=30", timeout=12)
                if rr2.status_code == 200:
                    for ev in rr2.json():
                        if ev.get("type") == "PushEvent":
                            for c in ev.get("payload", {}).get("commits", []):
                                em = c.get("author", {}).get("email", "")
                                if em and "noreply" not in em:
                                    res["commits_emails"].add(em)
                    if res["commits_emails"]:
                        print(f"      Emails en commits: {', '.join(res['commits_emails'])}")
                res["commits_emails"] = sorted(res["commits_emails"])
        except Exception:
            pass
        return res

    # ===== SHODAN InternetDB =====
    def shodan_host(self, ip: str) -> Dict[str, Any]:
        print(f"\n  [*] Shodan InternetDB: {ip}")
        res: Dict[str, Any] = {"ip": ip, "puertos": [], "servicios": [], "vulns": [], "os": "", "hostname": ""}
        try:
            r = self.s.get(f"https://internetdb.shodan.io/{ip}", timeout=10)
            if r.status_code == 200:
                d = r.json()
                res["puertos"] = d.get("ports", [])
                res["servicios"] = d.get("cpes", [])
                res["vulns"] = d.get("vulns", [])
                res["hostname"] = ", ".join(d.get("hostnames", []))
                print(f"  [+] Puertos abiertos: {res['puertos']}")
                if res["vulns"]:
                    print(f"  [!] CVEs: {', '.join(res['vulns'][:5])}")
        except Exception:
            pass
        return res

    def shodan_host_enriquecido(self, ip: str) -> Dict[str, Any]:
        """InternetDB + detalle NVD (límite de CVEs por rate limit de NVD sin API key)."""
        base = self.shodan_host(ip)
        cves = list(base.get("vulns") or [])
        detalles: List[Dict[str, Any]] = []
        max_cve = 6
        for i, cve in enumerate(cves[:max_cve]):
            if i:
                time.sleep(6.6)
            detalles.append(self.nvd_cve_lookup(cve))
        base["cves_detalle_nvd"] = detalles
        base["cves_total_shodan"] = len(cves)
        base["cves_analizados_nvd"] = len(detalles)
        base["nota_shodan_cve"] = (
            "InternetDB asocia CVE a la huella del servicio expuesto; no prueba versión ni parche aplicado en este host."
        )
        return base

    def nvd_cve_lookup(self, cve_id: str) -> Dict[str, Any]:
        cve_id = cve_id.strip().upper()
        out: Dict[str, Any] = {
            "cve": cve_id,
            "published": None,
            "last_modified": None,
            "descripcion": "",
            "cvss_v31": None,
            "cvss_v2": None,
            "severidad_aprox": None,
            "antiguedad": None,
            "parche_en_este_host": "desconocido",
            "nota": (
                "NVD describe la vulnerabilidad a nivel global. "
                "Saber si ESTE servidor está parcheado exige inventario de versiones o escaneo autenticado."
            ),
        }
        try:
            r = self.s.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"cveId": cve_id},
                timeout=25,
            )
            if r.status_code != 200:
                out["error"] = f"NVD HTTP {r.status_code}"
                return out
            data = r.json()
            vulns = data.get("vulnerabilities") or []
            if not vulns:
                out["error"] = "Sin registro en NVD"
                return out
            c = vulns[0].get("cve") or {}
            out["published"] = c.get("published")
            out["last_modified"] = c.get("lastModified")
            for d in c.get("descriptions") or []:
                if d.get("lang") == "en":
                    out["descripcion"] = (d.get("value") or "")[:1200]
                    break
            if not out["descripcion"] and c.get("descriptions"):
                out["descripcion"] = (c["descriptions"][0].get("value") or "")[:1200]
            metrics = c.get("metrics") or {}
            for key in ("cvssMetricV31", "cvssMetricV30"):
                lst = metrics.get(key) or []
                if lst:
                    sc = (lst[0].get("cvssData") or {}).get("baseScore")
                    if sc is not None:
                        out["cvss_v31"] = float(sc)
                    break
            v2 = (metrics.get("cvssMetricV2") or [])
            if v2:
                sc2 = (v2[0].get("cvssData") or {}).get("baseScore")
                if sc2 is not None:
                    out["cvss_v2"] = float(sc2)
            score = out["cvss_v31"] if out["cvss_v31"] is not None else out["cvss_v2"]
            if score is not None:
                if score >= 9:
                    out["severidad_aprox"] = "critica"
                elif score >= 7:
                    out["severidad_aprox"] = "alta"
                elif score >= 4:
                    out["severidad_aprox"] = "media"
                else:
                    out["severidad_aprox"] = "baja"
            if out["published"]:
                try:
                    y = int(str(out["published"])[:4])
                    out["antiguedad"] = "reciente" if y >= 2023 else ("intermedia" if y >= 2018 else "antigua")
                except ValueError:
                    out["antiguedad"] = None
        except Exception as ex:
            out["error"] = str(ex)
        return out

    def mozilla_observatory_scan(self, host: str) -> Dict[str, Any]:
        print(f"\n  [*] Mozilla HTTP Observatory: {host}")
        res: Dict[str, Any] = {
            "host": host,
            "grado": None,
            "puntuacion": None,
            "estado": None,
            "tests_pasados": None,
            "tests_fallidos": None,
            "error": None,
        }
        base = "https://http-observatory.security.mozilla.org/api/v1"
        data: Dict[str, Any] = {}
        for intento in range(3):
            try:
                r = self.s.post(f"{base}/analyze?host={quote(host)}", timeout=55)
                if r.status_code == 200:
                    data = r.json()
                    break
                if r.status_code >= 500:
                    time.sleep(4 + intento * 2)
            except Exception as ex:
                res["error"] = str(ex)
                time.sleep(2)
        if not data:
            res["error"] = res.get("error") or "Observatory no respondió (502/timeout frecuentes; reintentar más tarde)."
            print(f"  [-] {res['error']}")
            return res
        scan_id = data.get("scan_id")
        res["estado"] = data.get("state")
        res["grado"] = data.get("grade")
        res["puntuacion"] = data.get("score")
        res["tests_pasados"] = data.get("tests_passed")
        res["tests_fallidos"] = data.get("tests_failed")
        for _ in range(22):
            if data.get("grade") is not None:
                break
            if data.get("state") in ("FINISHED", "ABORTED") and data.get("grade") is None:
                break
            if not scan_id:
                break
            time.sleep(2)
            try:
                gr = self.s.get(f"{base}/getScanResults?scan={scan_id}", timeout=40)
                if gr.status_code == 200:
                    data = gr.json()
                    res["estado"] = data.get("state")
                    res["grado"] = data.get("grade")
                    res["puntuacion"] = data.get("score")
                    res["tests_pasados"] = data.get("tests_passed")
                    res["tests_fallidos"] = data.get("tests_failed")
            except Exception:
                break
        if res["grado"]:
            print(f"  [+] Observatory: grado {res['grado']} (score {res['puntuacion']})")
        return res

    def security_txt_publico(self, host: str) -> Dict[str, Any]:
        print(f"\n  [*] security.txt: {host}")
        res: Dict[str, Any] = {"host": host, "presente": False, "url": None, "vista_previa": ""}
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}/.well-known/security.txt"
            try:
                r = self.s.get(url, timeout=10, allow_redirects=True)
                if r.status_code == 200 and len(r.text) > 10:
                    res["presente"] = True
                    res["url"] = r.url
                    res["vista_previa"] = r.text[:2500]
                    print(f"  [+] security.txt: {res['url']}")
                    return res
            except Exception:
                continue
        print("  [-] security.txt no encontrado")
        return res

    def analisis_cabeceras_seguridad(self, url: str) -> Dict[str, Any]:
        print(f"\n  [*] Cabeceras de seguridad HTTP: {url}")
        hallazgos: List[Dict[str, Any]] = []
        try:
            r = self.s.head(url, timeout=12, allow_redirects=True)
            if r.status_code >= 400:
                r = self.s.get(url, timeout=12, allow_redirects=True)
            h = {k.lower(): v for k, v in r.headers.items()}
            checks = {
                "strict-transport-security": h.get("strict-transport-security"),
                "content-security-policy": h.get("content-security-policy"),
                "x-frame-options": h.get("x-frame-options"),
                "x-content-type-options": h.get("x-content-type-options"),
                "referrer-policy": h.get("referrer-policy"),
                "permissions-policy": h.get("permissions-policy"),
                "cross-origin-opener-policy": h.get("cross-origin-opener-policy"),
            }
            if not checks["strict-transport-security"] and url.lower().startswith("https://"):
                hallazgos.append(
                    {
                        "tipo": "hardening",
                        "hallazgo": "Sin cabecera Strict-Transport-Security en la respuesta analizada",
                        "riesgo": "medio",
                        "recomendacion": "Definir HSTS adecuado (includeSubDomains/preload según política).",
                    }
                )
            if not checks["content-security-policy"]:
                hallazgos.append(
                    {
                        "tipo": "hardening",
                        "hallazgo": "Sin Content-Security-Policy",
                        "riesgo": "medio",
                        "recomendacion": "Añadir CSP acotado para reducir impacto de XSS.",
                    }
                )
            csp_txt = str(checks.get("content-security-policy") or "").lower()
            if not checks["x-frame-options"] and "frame-ancestors" not in csp_txt:
                hallazgos.append(
                    {
                        "tipo": "hardening",
                        "hallazgo": "Sin X-Frame-Options ni frame-ancestors en CSP",
                        "riesgo": "bajo_medio",
                        "recomendacion": "Restringir clickjacking (DENY/SAMEORIGIN o frame-ancestors).",
                    }
                )
            if not checks["x-content-type-options"]:
                hallazgos.append(
                    {
                        "tipo": "hardening",
                        "hallazgo": "Sin X-Content-Type-Options: nosniff",
                        "riesgo": "bajo",
                        "recomendacion": "Enviar nosniff en respuestas.",
                    }
                )
            return {
                "url_analizada": r.url,
                "codigo": r.status_code,
                "cabeceras_relevantes": {k: v for k, v in checks.items() if v},
                "hallazgos": hallazgos,
            }
        except Exception as ex:
            return {"url_analizada": url, "error": str(ex), "hallazgos": hallazgos}

    def escaneo_hallazgos_seguridad(
        self, host: str, url: str, shodan_block: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        print(f"\n  [*] Informe de hallazgos (superficie pública): {host}")
        shodan_block = shodan_block or {}
        cves_detalle = shodan_block.get("cves_detalle_nvd") or []
        bloque: Dict[str, Any] = {
            "metodologia": (
                "Combinación de cabeceras HTTP reales, security.txt, Mozilla Observatory (si responde) "
                "y CVEs sugeridos por Shodan InternetDB para la IP. "
                "No sustituye pentest ni escaneo autenticado; no se afirma parche aplicado por CVE sin evidencia de versión."
            ),
            "observatory_mozilla": self.mozilla_observatory_scan(host),
            "security_txt": self.security_txt_publico(host),
            "cabeceras_http": self.analisis_cabeceras_seguridad(url),
            "cves_desde_shodan_detalle_nvd": cves_detalle,
            "resumen_cve_por_host": (
                "Los CVE de Shodan son candidatos a revisar contra el software y versiones reales detrás de los puertos abiertos."
            ),
        }
        if shodan_block.get("puertos"):
            bloque["puertos_abiertos_internetdb"] = shodan_block.get("puertos")
        return bloque

    def informe_superficie_web(self, url: str, host: str) -> Dict[str, Any]:
        print(f"\n  [*] Informe superficie web/dominio: {host}")
        out: Dict[str, Any] = {}
        out["extraccion_profunda"] = self.analizar_url_avanzado(url)
        out["ip"] = self.ip_whois(url)
        out["whois"] = self.whois_dominio(host)
        out["subdominios"] = self.subdominios(host)
        self._enriquecer_dominio(host, out)
        sh: Dict[str, Any] = {}
        ips = out["ip"].get("ips") or []
        if ips:
            sh = self.shodan_host_enriquecido(ips[0])
            out["shodan"] = sh
        out["escaneo_seguridad"] = self.escaneo_hallazgos_seguridad(host, url, sh)
        return out

    def _queries_filtraciones(self, objetivo: str) -> List[str]:
        q = objetivo.strip()
        if not q:
            return []
        candidatos: List[str] = [q]
        if q.startswith("http"):
            p = urlparse(q)
            if p.hostname:
                candidatos.append(p.hostname)
                segs = [x for x in (p.path or "").split("/") if len(x) > 2]
                for s in segs[-2:]:
                    candidatos.append(s)
            try:
                sin_q = p._replace(query="", fragment="").geturl()
                if sin_q and sin_q not in candidatos:
                    candidatos.append(sin_q)
            except Exception:
                pass
        if "@" in q and self.val_email(q):
            candidatos.append(q.split("@", 1)[1])
        out: List[str] = []
        seen: Set[str] = set()
        for x in candidatos:
            x = x.strip()
            if x and x not in seen:
                seen.add(x)
                out.append(x)
        return out[:10]

    def psbdmp_search(self, keyword: str) -> Dict[str, Any]:
        resultado: Dict[str, Any] = {"keyword": keyword, "pastebin_urls": [], "raw_count": 0, "error": None}
        for api_root in ("https://psbdmp.ws/api/v3/search/", "https://psbdmp.cc/api/v3/search/"):
            try:
                r = self.s.get(api_root + quote(keyword, safe=""), timeout=16)
                if r.status_code != 200:
                    continue
                data = r.json()
                if not isinstance(data, list):
                    continue
                resultado["raw_count"] = len(data)
                for item in data[:25]:
                    if not isinstance(item, dict):
                        continue
                    pid = item.get("_id") or item.get("id")
                    if pid:
                        resultado["pastebin_urls"].append(f"https://pastebin.com/{pid}")
                if resultado["pastebin_urls"]:
                    resultado["fuente_api"] = api_root
                    return resultado
            except Exception as ex:
                resultado["error"] = str(ex)
        return resultado

    def duckduckgo_html_urls(self, query: str, limit: int = 15) -> List[str]:
        urls: List[str] = []
        try:
            r = self.s.post(
                "https://html.duckduckgo.com/html/",
                data={"q": query, "kl": "es-es"},
                timeout=18,
            )
            text = r.text or ""
            for enc in re.findall(r"uddg=([^&\"]+)", text):
                try:
                    u = unquote(enc)
                    if u.startswith("http"):
                        urls.append(u)
                except Exception:
                    continue
            for m in re.finditer(r'result__a[^>]+href="(https?://[^"]+)"', text):
                u = m.group(1)
                if "duckduckgo.com" not in u.lower():
                    urls.append(u)
        except Exception:
            pass
        seen: Set[str] = set()
        out: List[str] = []
        for u in urls:
            if u not in seen:
                seen.add(u)
                out.append(u)
        return out[:limit]

    def busqueda_filtraciones_publica(self, objetivo: str) -> Dict[str, Any]:
        print(f"\n  [*] Filtraciones (fuentes públicas múltiples): {objetivo}")
        res: Dict[str, Any] = {
            "objetivo_original": objetivo,
            "consultas_generadas": self._queries_filtraciones(objetivo),
            "paste_urls": [],
            "emails_en_pastes": [],
            "google_pastebin": {"urls": [], "error": None},
            "duckduckgo": [],
            "psbdmp_por_consulta": [],
            "nota": (
                "Referencias indexadas o en APIs de dumps públicos. Vacío no implica inexistencia de filtraciones. "
                "No se guardan contraseñas."
            ),
        }
        paste_set: Set[str] = set()
        emails: Set[str] = set()

        for keyword in res["consultas_generadas"][:5]:
            try:
                gurl = f"https://www.google.com/search?q=site%3Apastebin.com+%22{quote(keyword)}%22&hl=es&num=15"
                gr = self.s.get(gurl, timeout=self.timeout)
                if gr.status_code == 200:
                    for pu in re.findall(r'href="(https?://pastebin\.com/[^"&]+)"', gr.text):
                        paste_set.add(pu.split("?")[0])
                        res["google_pastebin"]["urls"].append(pu.split("?")[0])
            except Exception as ex:
                res["google_pastebin"]["error"] = str(ex)

            ddg_q = f'site:pastebin.com "{keyword}"'
            durls = self.duckduckgo_html_urls(ddg_q, limit=12)
            res["duckduckgo"].append({"consulta": ddg_q, "urls": durls})
            for u in durls:
                if "pastebin.com" in u.lower():
                    paste_set.add(u.split("?")[0])

            ps = self.psbdmp_search(keyword)
            res["psbdmp_por_consulta"].append(ps)
            for u in ps.get("pastebin_urls") or []:
                paste_set.add(u.split("?")[0])

            time.sleep(1.3)

        res["paste_urls"] = sorted(paste_set)[:40]
        for pu in res["paste_urls"][:12]:
            try:
                pr = self.s.get(pu, timeout=10)
                if pr.status_code == 200:
                    emails.update(self.email_re.findall(pr.text))
            except Exception:
                pass
        res["emails_en_pastes"] = sorted(emails)[:40]
        if res["paste_urls"]:
            print(f"  [+] Enlaces únicos a pastes: {len(res['paste_urls'])}")
        else:
            print("  [-] Sin enlaces de pastes en esta pasada (API/buscadores pueden bloquear o no haber coincidencias).")
        return res

    def _parece_dominio_o_url(self, s: str) -> bool:
        s = s.strip()
        if s.startswith("http://") or s.startswith("https://"):
            return True
        if " " in s or len(s) < 4:
            return False
        core = s.replace("https://", "").replace("http://", "").split("/")[0].strip()
        return bool(re.match(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$", core))

    def _normalizar_url_y_host(self, org: str) -> Tuple[str, str]:
        org = org.strip()
        if org.startswith("http://") or org.startswith("https://"):
            p = urlparse(org)
            host = (p.hostname or "").strip()
            url = org
        else:
            host = org.replace("https://", "").replace("http://", "").split("/")[0].strip()
            url = f"https://{host}/"
        if not host:
            host = urlparse(url).hostname or ""
        return url, host

    # ===== Google (fragil; solo heurística) =====
    def google_dorks(self, objetivo: str, tipo: str = "nombre") -> Dict[str, Any]:
        print(f"\n  [*] Google Dorks (heurístico): {objetivo}")
        res: Dict[str, Any] = {
            "emails": set(),
            "urls": [],
            "redes": set(),
            "nombres": set(),
            "ubicaciones": set(),
            "documentos": [],
            "filtraciones": set(),
        }
        dorks: List[str] = []
        if tipo == "email":
            dorks = [
                f'"{objetivo}"',
                f'"{objetivo}" filetype:pdf OR filetype:xls',
                f'"{objetivo}" site:pastebin.com',
                f'"{objetivo}" site:linkedin.com',
                f'"{objetivo}" site:github.com',
            ]
        elif tipo == "nombre":
            dorks = [
                f'"{objetivo}"',
                f'"{objetivo}" site:linkedin.com',
                f'"{objetivo}" site:instagram.com',
                f'"{objetivo}" site:github.com',
                f'"{objetivo}" filetype:pdf cv',
                f'"{objetivo}" intext:@gmail.com OR intext:@hotmail.com',
            ]
        elif tipo == "telefono":
            n_d = re.sub(r"\D", "", objetivo)
            dorks = [
                f'"{objetivo}"',
                f'"{n_d}" whatsapp OR telegram',
                f'"{objetivo}" site:facebook.com OR site:linkedin.com',
                f'"{n_d}" nombre OR owner',
            ]
        elif tipo == "organizacion":
            dorks = [
                f'site:opencorporates.com "{objetivo}"',
                f'site:linkedin.com/company "{objetivo}"',
                f'"{objetivo}" filetype:pdf',
            ]

        social_ps = [
            "facebook.com/",
            "twitter.com/",
            "x.com/",
            "instagram.com/",
            "linkedin.com/in/",
            "tiktok.com/@",
            "youtube.com/@",
            "github.com/",
        ]
        for dork in dorks:
            try:
                url = f"https://www.google.com/search?q={quote(dork)}&hl=es&num=20"
                r = self.s.get(url, timeout=self.timeout)
                if r.status_code == 200:
                    emails = self.email_re.findall(r.text)
                    for e in emails:
                        if not any(x in e.lower() for x in ["example", "sentry", "noreply"]):
                            res["emails"].add(e)
                    urls_found = re.findall(r'href="(https?://[^"&]+)"', r.text)
                    for u in urls_found:
                        if "google" in u.lower():
                            continue
                        uc = u.split("?")[0].rstrip("/")
                        if any(p in uc.lower() for p in social_ps):
                            res["redes"].add(uc)
                        elif ".pdf" in uc.lower() or ".xls" in uc.lower():
                            res["documentos"].append(uc)
                        elif len(res["urls"]) < 15:
                            res["urls"].append(uc)

                    snippets = re.findall(r'<div class="[^"]*"[^>]*>([^<]{30,200})</div>', r.text)
                    for s in snippets:
                        txt = re.sub(r"<[^>]+>", "", s).strip()
                        for loc in [
                            "Buenos Aires",
                            "Cordoba",
                            "Rosario",
                            "Mendoza",
                            "CABA",
                            "Madrid",
                            "Barcelona",
                            "Miami",
                            "Mexico",
                            "Santiago",
                            "Bogota",
                            "Lima",
                        ]:
                            if loc.lower() in txt.lower():
                                res["ubicaciones"].add(loc)
                        if "pastebin" in dork.lower() and len(txt) > 30:
                            res["filtraciones"].add(txt[:150])
                time.sleep(1.6)
            except Exception:
                pass

        res["emails"] = sorted(res["emails"])[:20]
        res["redes"] = sorted(res["redes"])[:15]
        res["ubicaciones"] = sorted(res["ubicaciones"])
        res["filtraciones"] = sorted(res["filtraciones"])[:10]
        res["documentos"] = sorted(set(res["documentos"]))[:10]
        if res["emails"]:
            print(f"  [+] Emails encontrados: {len(res['emails'])}")
        if res["redes"]:
            print(f"  [+] Redes detectadas: {len(res['redes'])}")
        return res

    # ===== REDES SOCIALES (solo perfil público / código HTTP) =====
    def redes_sociales(self, username: str) -> Dict[str, Any]:
        print(f"\n  [*] Enumerando redes sociales: {username}")
        u = username.replace(" ", "").lower()
        plataformas = {
            "GitHub": f"https://github.com/{u}",
            "Twitter/X": f"https://x.com/{u}",
            "Instagram": f"https://instagram.com/{u}",
            "TikTok": f"https://tiktok.com/@{u}",
            "Facebook": f"https://facebook.com/{u}",
            "YouTube": f"https://youtube.com/@{u}",
            "Reddit": f"https://reddit.com/user/{u}",
            "LinkedIn": f"https://linkedin.com/in/{u}",
            "Pinterest": f"https://pinterest.com/{u}",
            "Telegram": f"https://t.me/{u}",
            "Twitch": f"https://twitch.tv/{u}",
            "Medium": f"https://medium.com/@{u}",
        }
        encontrados: Dict[str, Any] = {}
        for nombre, url in plataformas.items():
            try:
                r = self.s.get(url, timeout=6, allow_redirects=True)
                texto = (r.text or "").lower()
                neg = ("page not found", "404", "doesn't exist", "no existe", "suspended")
                ok = r.status_code == 200 and not any(x in texto for x in neg)
                if ok:
                    info: Dict[str, Any] = {"url": r.url, "estado": "posible_perfil_publico", "codigo": r.status_code, "emails": []}
                    emails = self.email_re.findall(r.text)
                    info["emails"] = [e for e in emails if "example" not in e.lower()][:5]
                    encontrados[nombre] = info
                    print(f"  [+] {nombre}: {r.url}")
            except Exception:
                pass
        return encontrados

    def sherlock_hunt(self, username: str) -> Dict[str, str]:
        extra = {
            "Hackerone": f"https://hackerone.com/{username}",
            "Bugcrowd": f"https://bugcrowd.com/{username}",
            "Leetcode": f"https://leetcode.com/{username}",
            "Codeforces": f"https://codeforces.com/profile/{username}",
            "Linktree": f"https://linktr.ee/{username}",
        }
        res: Dict[str, str] = {}
        for nombre, url in extra.items():
            try:
                r = self.s.get(url, timeout=6)
                if r.status_code == 200 and username.lower() in r.text.lower():
                    res[nombre] = url
            except Exception:
                pass
        return res

    def whois_dominio(self, dominio: str) -> Dict[str, Any]:
        print(f"\n  [*] WHOIS (scraping whois.com): {dominio}")
        res = {"dominio": dominio, "registrante": "", "email": "", "creacion": ""}
        try:
            r = self.s.get(f"https://www.whois.com/whois/{dominio}", timeout=10)
            if r.status_code == 200:
                emails = self.email_re.findall(r.text)
                res["email"] = emails[0] if emails else ""
                reg = re.search(r"Registrant\s+(?:Name|Organization):\s*(.+)", r.text, re.I)
                if reg:
                    res["registrante"] = reg.group(1).strip()
        except Exception:
            pass
        return res

    def subdominios(self, dominio: str) -> List[str]:
        print(f"\n  [*] Subdominios (crt.sh): {dominio}")
        subs: Set[str] = set()
        try:
            r = self.s.get(f"https://crt.sh/?q=%.{dominio}&output=json", timeout=16)
            if r.status_code == 200:
                for entry in r.json():
                    for n in entry.get("name_value", "").split("\n"):
                        n = n.strip().lstrip("*.")
                        if dominio in n:
                            subs.add(n)
        except Exception:
            pass
        subs_list = sorted(subs)[:80]
        print(f"  [+] Detectados {len(subs_list)} nombres en certificados")
        return subs_list

    def correlacionar(self, datos: Any) -> Dict[str, Any]:
        c: Dict[str, Set[str]] = {
            "emails": set(),
            "telefonos": set(),
            "ubicaciones": set(),
            "redes_sociales": set(),
            "cves": set(),
        }

        def extract(obj: Any) -> None:
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if k in ("email", "emails", "commits_emails", "emails_en_pastes") and v:
                        if isinstance(v, list):
                            c["emails"].update(str(x) for x in v if "@" in str(x))
                        elif isinstance(v, str) and "@" in v:
                            c["emails"].add(v)
                    if k in ("telefono", "telefonos", "numero", "normalizado") and v:
                        if isinstance(v, list):
                            c["telefonos"].update(str(x) for x in v)
                        elif isinstance(v, str):
                            c["telefonos"].add(v)
                    if k in ("ubicacion", "ubicaciones", "ciudad", "pais") and v:
                        if isinstance(v, list):
                            c["ubicaciones"].update(str(x) for x in v if x)
                        elif isinstance(v, str) and v:
                            c["ubicaciones"].add(v)
                    if k in ("redes", "plataformas", "redes_sociales"):
                        if isinstance(v, dict):
                            c["redes_sociales"].update(v.keys())
                        elif isinstance(v, list):
                            c["redes_sociales"].update(str(x) for x in v)
                    for val in v if isinstance(v, list) else [v]:
                        if isinstance(val, (dict, list)):
                            extract(val)
            elif isinstance(obj, list):
                for item in obj:
                    extract(item)

        extract(datos)
        try:
            blob = json.dumps(datos, default=str)
            for m in re.finditer(r"CVE-\d{4}-\d{4,7}", blob, re.I):
                c["cves"].add(m.group(0).upper())
        except Exception:
            pass
        return {
            "emails": [e for e in sorted(c["emails"]) if "example" not in e][:30],
            "telefonos": [t for t in sorted(c["telefonos"]) if len(re.sub(r"\D", "", t)) >= 8][:20],
            "ubicaciones": sorted(c["ubicaciones"])[:20],
            "redes_sociales": sorted(c["redes_sociales"])[:30],
            "cves": sorted(c["cves"])[:40],
        }

    def guardar(self, resultado: Dict[str, Any]) -> Optional[str]:
        try:
            ts = int(time.time())
            obj = str(resultado.get("objetivo", "unknown"))
            for ch in ["https://", "http://", "www.", ":", "/", "\\", "?", "*", "|", "<", ">", " ", '"']:
                obj = obj.replace(ch, "_")
            fn = f"OSINT_v5_{obj[:40]}_{ts}.json"
            payload = dict(resultado)
            payload["meta"] = {**self._meta_base(), **payload.get("meta", {})}
            safe = self._json_safe(payload)
            with open(fn, "w", encoding="utf-8") as f:
                json.dump(safe, f, indent=2, ensure_ascii=False)
            print(f"\n[+] JSON guardado: {fn}")
            return fn
        except Exception as ex:
            print(f"[-] Error guardando: {ex}")
            return None

    def _enriquecer_dominio(self, host: str, datos: Dict[str, Any]) -> None:
        datos["dns_doh"] = self.dns_over_https(host)
        datos["tls_certificado_publico"] = self.tls_certificate_public(host)

    def menu(self) -> None:
        while True:
            print("\n" + "=" * 65)
            print("  OSINT INTELLIGENCE SYSTEM v5.2")
            print("  OSINT público | Filtraciones multi-fuente | Org/URL + escaneo superficie")
            print("=" * 65)
            print("\n  1. Buscar por EMAIL")
            print("  2. Buscar por NOMBRE / PERSONA")
            print("  3. Busqueda reversa TELEFONO")
            print("  4. Analizar DOMINIO / URL")
            print("  5. Buscar USERNAME (redes públicas)")
            print("  6. Buscar FILTRACIONES (Pastebin + DDG + psbdmp si responde)")
            print("  7. Buscar ORGANIZACION / GOBIERNO (URL/dominio: informe + vulns superficie)")
            print("  8. Salir\n")
            op = input("Opcion (1-8): ").strip()
            res: Optional[Dict[str, Any]] = None

            if op == "1":
                e = input("Email: ").strip()
                if self.val_email(e):
                    res = {"objetivo": e, "tipo": "email", "timestamp": datetime.now().isoformat(), "datos": {}}
                    user, dominio = e.split("@")[0], e.split("@")[1]
                    res["datos"]["hibp"] = self.hibp(e)
                    res["datos"]["gravatar"] = self.gravatar_from_email(e)
                    res["datos"]["google"] = self.google_dorks(e, "email")
                    res["datos"]["redes"] = self.redes_sociales(user)
                    res["datos"]["github"] = self.github(user)
                    if dominio.lower() not in ("gmail.com", "hotmail.com", "yahoo.com", "outlook.com", "icloud.com", "proton.me", "protonmail.com"):
                        res["datos"]["whois"] = self.whois_dominio(dominio)
                        self._enriquecer_dominio(dominio, res["datos"])
                        res["datos"]["subdominios"] = self.subdominios(dominio)
            elif op == "2":
                n = input("Nombre completo: ").strip()
                if n:
                    res = {"objetivo": n, "tipo": "nombre", "timestamp": datetime.now().isoformat(), "datos": {}}
                    user = n.replace(" ", "").lower()
                    res["datos"]["google"] = self.google_dorks(n, "nombre")
                    res["datos"]["redes"] = self.redes_sociales(user)
                    res["datos"]["sherlock"] = self.sherlock_hunt(user)
            elif op == "3":
                t = input("Telefono: ").strip()
                if t:
                    res = {"objetivo": t, "tipo": "telefono", "timestamp": datetime.now().isoformat(), "datos": {}}
                    res["datos"]["google"] = self.google_dorks(t, "telefono")
            elif op == "4":
                d = input("URL o Dominio: ").strip()
                if d:
                    if not d.startswith("http"):
                        d = "https://" + d
                    res = {"objetivo": d, "tipo": "url", "timestamp": datetime.now().isoformat(), "datos": {}}
                    dominio = urlparse(d).hostname or d.replace("https://", "").replace("http://", "")
                    res["datos"] = self.informe_superficie_web(d, dominio)
            elif op == "5":
                u = input("Username: ").strip()
                if u:
                    res = {"objetivo": u, "tipo": "username", "timestamp": datetime.now().isoformat(), "datos": {}}
                    res["datos"]["redes"] = self.redes_sociales(u)
                    res["datos"]["sherlock"] = self.sherlock_hunt(u)
                    res["datos"]["github"] = self.github(u)
                    res["datos"]["google"] = self.google_dorks(u, "nombre")
            elif op == "6":
                obj = input("Buscar en pastes (email/nombre/dominio/URL): ").strip()
                if obj:
                    res = {"objetivo": obj, "tipo": "pastes", "timestamp": datetime.now().isoformat(), "datos": {}}
                    res["datos"]["filtraciones_publicas"] = self.busqueda_filtraciones_publica(obj)
            elif op == "7":
                org = input("Organizacion o Gobierno (o URL/dominio): ").strip()
                if org:
                    res = {"objetivo": org, "tipo": "organizacion", "timestamp": datetime.now().isoformat(), "datos": {}}
                    res["datos"]["google"] = self.google_dorks(org, "organizacion")
                    if self._parece_dominio_o_url(org):
                        url_org, host_org = self._normalizar_url_y_host(org)
                        res["datos"].update(self.informe_superficie_web(url_org, host_org))
            elif op == "8":
                print("\n[*] Saliendo...\n")
                break
            else:
                print("[-] Opcion invalida")
                continue

            if res:
                print(f"\n{'=' * 65}\n  RESUMEN FINAL - {res['objetivo']}\n{'=' * 65}")
                res["correlacion"] = self.correlacionar(res["datos"])
                c = res["correlacion"]
                if c["emails"]:
                    print(f"\n[+] EMAILS: {', '.join(c['emails'][:10])}")
                if c["telefonos"]:
                    print(f"[+] TELEFONOS: {', '.join(c['telefonos'][:5])}")
                if c["ubicaciones"]:
                    print(f"[+] UBICACIONES: {', '.join(c['ubicaciones'][:5])}")
                if c["redes_sociales"]:
                    print(f"[+] REDES: {', '.join(c['redes_sociales'][:10])}")
                if c.get("cves"):
                    print(f"[+] CVEs (en JSON): {', '.join(c['cves'][:12])}")
                self.guardar(res)
            input("\n[Enter para continuar...]")


if __name__ == "__main__":
    try:
        OSINTv5().menu()
    except KeyboardInterrupt:
        sys.exit(0)
