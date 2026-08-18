#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Sinh blog tĩnh (VI + EN nếu có bản dịch) từ các file KB_*.md / KB_*.en.md.
Có dark mode (nhớ qua localStorage) và nút chuyển ngữ."""
import re, os, unicodedata, html as _html
import markdown
from markdown.extensions.toc import TocExtension

DIR = os.path.dirname(os.path.abspath(__file__))

GROUPS_BASE = [
    ("A", ["01", "02", "03", "04"]),
    ("B", ["05", "06", "07"]),
    ("C", ["08", "09", "10"]),
    ("D", ["11", "12"]),
    ("E", ["13", "14"]),
    ("F", ["15", "16", "17"]),
    ("G", ["99"]),
]
SLUGS = {
    "00": "Index", "01": "Networking", "02": "Linux", "03": "Windows-AD",
    "04": "Crypto-Core", "05": "AppSec-OWASP", "06": "DevSecOps-Scanning-Semgrep",
    "07": "CICD-GitOps", "08": "SIEM-Wazuh", "09": "ELK-Zabbix", "10": "SOC-IR",
    "11": "IDS-WAF-NetDef", "12": "Pentest-VulnScan", "13": "Cloud",
    "14": "Virtualization-Containers", "15": "ThreatIntel-Frameworks",
    "16": "Compliance-GRC", "17": "Python-Security", "99": "Glossary",
}

LANGS = {
    "vi": {
        "out": "notes.html", "ext": ".md", "htmllang": "vi",
        "home": "Trang chủ", "home_href": "./",
        "title": "Sổ tay An toàn thông tin",
        "metadesc": "Blog chia sẻ kiến thức an toàn thông tin — ghi chép trong quá trình học và làm việc.",
        "tag": "Chia sẻ kiến thức · ghi chép khi học &amp; làm",
        "search": "Lọc mục lục…", "intro": "Giới thiệu & Mục lục",
        "other": "EN", "other_href": "en/notes.html",
        "prev": "Chương trước", "next": "Chương sau", "theme_title": "Sáng / Tối / Wibu",
        "groups": {
            "A": "Phần A · Nền tảng", "B": "Phần B · An ninh ứng dụng & DevSecOps",
            "C": "Phần C · Giám sát, Phát hiện & Ứng phó", "D": "Phần D · Phòng thủ mạng & Kiểm thử",
            "E": "Phần E · Hạ tầng, Ảo hóa & Đám mây", "F": "Phần F · Tấn công, Tuân thủ & Tự động hóa",
            "G": "Phụ lục",
        },
        "short": {
            "01": "Mạng máy tính", "02": "Hệ điều hành Linux", "03": "Windows & Active Directory",
            "04": "Mật mã & Nền tảng bảo mật", "05": "An ninh ứng dụng Web (OWASP)",
            "06": "DevSecOps & Quét mã nguồn", "07": "CI/CD & GitOps", "08": "SIEM & Quản lý log",
            "09": "Observability & Giám sát hạ tầng", "10": "Vận hành SOC & Ứng phó sự cố",
            "11": "Phòng thủ mạng (IDS/WAF/VPN)", "12": "Kiểm thử & Đánh giá lỗ hổng",
            "13": "Bảo mật Đám mây", "14": "Ảo hóa & Container", "15": "Threat Intel & Khung tấn công",
            "16": "Tuân thủ & Quản trị (GRC)", "17": "Lập trình & Tự động hóa",
            "99": "Thuật ngữ & viết tắt",
        },
        "foot1": 'Ghi chép & chia sẻ bởi <span class="name">Fee</span> · tự do cho mục đích học tập.',
        "foot2": "Nội dung mang tính giáo dục, nhằm mục đích phòng thủ. Hãy thực hành hợp pháp, chỉ trên hệ thống bạn được phép.",
    },
    "en": {
        "out": "en/notes.html", "ext": ".en.md", "htmllang": "en",
        "home": "Home", "home_href": "../",
        "title": "Security Handbook",
        "metadesc": "A security knowledge handbook — notes collected while learning and working in security.",
        "tag": "Notes from learning &amp; working in security",
        "search": "Filter contents…", "intro": "Intro & Contents",
        "other": "VI", "other_href": "../notes.html",
        "prev": "Previous", "next": "Next", "theme_title": "Light / Dark / Wibu",
        "groups": {
            "A": "Part A · Fundamentals", "B": "Part B · Application Security & DevSecOps",
            "C": "Part C · Monitoring, Detection & Response", "D": "Part D · Network Defense & Testing",
            "E": "Part E · Infrastructure, Virtualization & Cloud", "F": "Part F · Offense, Compliance & Automation",
            "G": "Appendix",
        },
        "short": {
            "01": "Networking", "02": "Linux", "03": "Windows & Active Directory",
            "04": "Cryptography & Foundations", "05": "Web App Security (OWASP)",
            "06": "DevSecOps & Code Scanning", "07": "CI/CD & GitOps", "08": "SIEM & Log Management",
            "09": "Observability & Monitoring", "10": "SOC & Incident Response",
            "11": "Network Defense (IDS/WAF/VPN)", "12": "Pentest & Vuln Assessment",
            "13": "Cloud Security", "14": "Virtualization & Containers", "15": "Threat Intel & Frameworks",
            "16": "Compliance & Governance (GRC)", "17": "Programming & Automation",
            "99": "Glossary & Abbreviations",
        },
        "foot1": 'Written & shared by <span class="name">Fee</span> · free for learning purposes.',
        "foot2": "Educational content for defensive purposes. Practice legally, only on systems you are authorized to test.",
    },
}


def make_slugify(prefix):
    def slug(value, sep):
        value = unicodedata.normalize("NFKD", value)
        value = re.sub(r"[^\w\s-]", "", value, flags=re.U).strip().lower()
        value = re.sub(r"[\s]+", sep, value, flags=re.U)
        return f"{prefix}-{value}" if value else prefix
    return slug


def page_name(n):
    return "notes.html" if n == "00" else f"ch{n}.html"


def render(cfg, n):
    slug = SLUGS[n]
    path = f"{DIR}/KB_{n}_{slug}{cfg['ext']}"
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        text = f.read()
    md = markdown.Markdown(extensions=[
        "fenced_code", "tables", "sane_lists", "attr_list",
        TocExtension(slugify=make_slugify(f"ch{n}"), toc_depth="1-3"),
    ])
    body = md.convert(text)
    body = re.sub(r'href="#sec-(\d{2})"', lambda m: f'href="{page_name(m.group(1))}"', body)
    toks = md.toc_tokens
    subs = []
    def walk(nodes):
        for t in nodes:
            if t.get("level") == 2:
                subs.append(t)
            walk(t.get("children", []))
    walk(toks)
    title = SLUGS[n]
    for t in toks:
        if t.get("level") == 1:
            title = t["name"]; break
    section = f'<section class="chapter" id="sec-{n}" data-ch="{n}">\n{body}\n</section>'
    return {"n": n, "section": section, "subs": subs, "title": title}


def nav_block(cfg, r, current):
    n = r["n"]
    short = cfg["intro"] if n == "00" else cfg["short"][n]
    is_cur = (n == current)
    subs = "".join(
        f'<a class="nav-sub" href="#{s["id"]}">{_html.escape(s["name"])}</a>' for s in r["subs"]
    ) if is_cur else ""
    cls = "nav-chapter open active" if is_cur else "nav-chapter"
    href = "#top" if is_cur else page_name(n)
    return (f'<div class="{cls}" data-ch="{n}">'
            f'<a class="nav-ch-title" href="{href}"><span class="num">{n}</span>'
            f'<span class="t">{_html.escape(short)}</span></a>'
            f'<div class="nav-subs">{subs}</div></div>')


CSS = r"""
:root{
  --bg:#f4efe3; --panel:#ebe3d1; --panel2:#e1d7c0; --ink:#2b2620; --muted:#79705e;
  --line:#d6cbb3; --accent:#0f6e60; --accent2:#b1502c; --code-bg:#241f18; --code-ink:#ece3d1;
  --tbl-head:#e6dcc5; --tbl-zebra:#efe8d6; --kbd:#e6dcc5; --codeborder:#3a3228; --scroll:#cabda2;
  --serif:Georgia,"Iowan Old Style","Times New Roman",serif;
}
html[data-theme="dark"]{
  --bg:#16140f; --panel:#1e1b15; --panel2:#2a261d; --ink:#e9e2d2; --muted:#9c917c;
  --line:#322d23; --accent:#46b3a3; --accent2:#e0824f; --code-bg:#0e0c08; --code-ink:#e9e2d2;
  --tbl-head:#2a261d; --tbl-zebra:#1c1914; --kbd:#2c271e; --codeborder:#322d23; --scroll:#3a3328;
}
html[data-theme="wibu"]{
  --bg:#241a38; --panel:rgba(38,28,55,.74); --panel2:rgba(60,44,86,.72); --ink:#f4ecff; --muted:#cbb9e6;
  --line:rgba(255,255,255,.15); --accent:#ff79b0; --accent2:#a78bff; --code-bg:rgba(15,10,25,.85); --code-ink:#f0e8ff;
  --tbl-head:rgba(60,44,86,.72); --tbl-zebra:rgba(48,35,70,.45); --kbd:rgba(70,52,98,.7); --codeborder:rgba(255,255,255,.13); --scroll:#7a5fae;
}
html[data-theme="wibu"] body{
  background-color:#241a38;
  background-image:var(--wibu-bg, none), linear-gradient(135deg,#2a1e44 0%,#46315f 55%,#5a3f74 100%);
  background-size:cover; background-position:center; background-attachment:fixed;
}
html[data-theme="wibu"] .sidebar,
html[data-theme="wibu"] .brand,
html[data-theme="wibu"] .search,
html[data-theme="wibu"] .topbar{backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px)}
html[data-theme="wibu"] .main{background:rgba(18,12,30,.55);border:1px solid var(--line);border-radius:16px;
  margin-top:20px;margin-bottom:20px;backdrop-filter:blur(4px);-webkit-backdrop-filter:blur(4px)}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--ink);
  font:16px/1.72 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,"Noto Sans",sans-serif;}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}

.wrap{display:flex;min-height:100vh}
.sidebar{width:322px;flex:0 0 322px;background:var(--panel);border-right:1px solid var(--line);
  height:100vh;position:sticky;top:0;overflow-y:auto;padding:0}
.brand{padding:20px 18px 13px;border-bottom:1px solid var(--line);position:sticky;top:0;background:var(--panel);z-index:2}
.brand h1{font-family:var(--serif);font-size:19px;margin:0 0 3px;letter-spacing:.2px;color:var(--ink)}
.brand .tag{margin:3px 0 0;font-size:11.5px;color:var(--muted);line-height:1.45}
.brand .author{display:block;margin-top:7px;font-size:11.5px;color:var(--accent2);font-weight:600}
.controls{display:flex;gap:7px;margin-top:11px}
.ctrl-btn{display:inline-flex;align-items:center;justify-content:center;gap:5px;background:var(--bg);
  border:1px solid var(--line);color:var(--ink);border-radius:7px;padding:5px 10px;font-size:12px;
  cursor:pointer;font-family:inherit;line-height:1;text-decoration:none}
.ctrl-btn:hover{border-color:var(--accent);text-decoration:none}
.search{padding:10px 14px;position:sticky;top:118px;background:var(--panel);z-index:2;border-bottom:1px solid var(--line)}
.search input{width:100%;background:var(--bg);border:1px solid var(--line);color:var(--ink);
  border-radius:7px;padding:8px 10px;font-size:13px;outline:none}
.search input:focus{border-color:var(--accent)}
.nav{padding:8px 8px 40px}
.nav-group{padding:16px 10px 5px;font-family:var(--serif);font-size:11px;font-weight:700;letter-spacing:.4px;
  text-transform:uppercase;color:var(--accent2)}
.nav-chapter{margin:1px 0}
.nav-ch-title{display:flex;gap:9px;align-items:baseline;padding:7px 10px;border-radius:7px;color:var(--ink);font-size:13.5px}
.nav-ch-title .num{font-family:var(--serif);font-size:11px;color:var(--muted);font-variant-numeric:tabular-nums;min-width:18px}
.nav-ch-title:hover{background:var(--panel2);text-decoration:none}
.nav-chapter.active>.nav-ch-title{background:var(--bg);box-shadow:inset 3px 0 0 var(--accent);color:var(--ink);font-weight:700}
.nav-chapter.active>.nav-ch-title .num{color:var(--accent)}
.nav-subs{display:none;margin:2px 0 6px 27px;border-left:1px solid var(--line);padding-left:9px}
.nav-chapter.open .nav-subs{display:block}
.nav-sub{display:block;padding:4px 8px;font-size:12px;color:var(--muted);border-radius:6px;line-height:1.4}
.nav-sub:hover{color:var(--accent);background:var(--panel2);text-decoration:none}

.content{flex:1;min-width:0;padding:0 0 120px}
.topbar{display:none}
.main{max-width:820px;margin:0 auto;padding:40px 44px}
.chapter{border-bottom:1px solid var(--line);padding-bottom:44px;margin-bottom:14px}
.chapter h1{font-family:var(--serif);font-size:31px;line-height:1.22;margin:40px 0 20px;padding-bottom:12px;
  border-bottom:2px solid var(--accent);color:var(--ink);scroll-margin-top:16px}
.chapter:first-child h1{margin-top:8px}
h2{font-family:var(--serif);font-size:23px;margin:36px 0 12px;color:var(--ink);scroll-margin-top:16px}
h3{font-family:var(--serif);font-size:18px;margin:24px 0 8px;color:var(--ink);scroll-margin-top:16px}
h4{font-size:14px;margin:18px 0 6px;color:var(--accent);font-weight:700}
p{margin:11px 0}
ul,ol{margin:11px 0;padding-left:24px}
li{margin:5px 0}
strong{color:var(--ink);font-weight:700}
hr{border:0;border-top:1px solid var(--line);margin:28px 0}
blockquote{margin:15px 0;padding:9px 16px;border-left:3px solid var(--accent2);
  background:var(--panel);border-radius:0 7px 7px 0;color:var(--muted)}

code{font-family:"SF Mono","JetBrains Mono",Consolas,"Liberation Mono",monospace;font-size:13px}
:not(pre)>code{background:var(--kbd);color:var(--accent2);padding:1.5px 6px;border-radius:5px;font-size:12.5px}
pre{background:var(--code-bg);border:1px solid var(--codeborder);border-radius:9px;padding:14px 16px;
  overflow-x:auto;margin:15px 0;line-height:1.55}
pre code{color:var(--code-ink);background:none;padding:0;font-size:12.7px;white-space:pre}

.tbl-scroll,table{width:100%}
table{border-collapse:collapse;margin:16px 0;font-size:13.5px;display:block;overflow-x:auto}
th,td{border:1px solid var(--line);padding:8px 11px;text-align:left;vertical-align:top}
th{background:var(--tbl-head);color:var(--ink);font-weight:700;white-space:nowrap}
tbody tr:nth-child(even){background:var(--tbl-zebra)}

.menu-btn{display:none}
@media(max-width:980px){
  .sidebar{position:fixed;left:0;top:0;z-index:50;transform:translateX(-100%);transition:transform .25s}
  .sidebar.show{transform:none;box-shadow:0 0 40px rgba(20,15,8,.45)}
  .topbar{display:flex;align-items:center;gap:10px;position:sticky;top:0;z-index:40;
    background:var(--panel);border-bottom:1px solid var(--line);padding:10px 16px}
  .menu-btn{display:inline-flex;background:var(--bg);border:1px solid var(--line);color:var(--ink);
    border-radius:7px;padding:7px 12px;font-size:14px;cursor:pointer}
  .topbar .ttl{font-family:var(--serif);font-size:15px;font-weight:700;flex:1}
  .main{padding:24px 18px}
  .chapter h1{font-size:25px}
}
::-webkit-scrollbar{width:11px;height:11px}
::-webkit-scrollbar-thumb{background:var(--scroll);border-radius:6px;border:2px solid var(--bg)}
::-webkit-scrollbar-track{background:transparent}

.site-foot{max-width:820px;margin:54px auto 0;padding:24px 44px 0;border-top:1px solid var(--line);
  color:var(--muted);font-size:13px;line-height:1.7}
.site-foot a{color:var(--accent)}
.site-foot .name{color:var(--ink);font-weight:700}
@media(max-width:980px){.site-foot{padding:24px 18px 0}}
.brand h1 a{color:var(--ink);text-decoration:none}
.brand h1 a:hover{color:var(--accent)}
.nav-sub.here{color:var(--accent);background:var(--panel2);font-weight:600}
.pager{max-width:820px;margin:34px auto 0;display:flex;gap:14px;justify-content:space-between}
.pg{flex:1 1 0;min-width:0;display:block;padding:13px 16px;border:1px solid var(--line);border-radius:10px;
  background:var(--panel);color:var(--ink);text-decoration:none}
a.pg:hover{border-color:var(--accent);text-decoration:none}
a.pg:hover b{color:var(--accent)}
.pg span{display:block;font-size:11.5px;color:var(--muted);margin-bottom:3px}
.pg b{display:block;font-size:13.5px;font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.pg.next{text-align:right}
span.pg{border:0;background:none}
@media(max-width:980px){.pager{padding:0 18px}}
"""

JS = r"""
const root=document.documentElement;
const THEMES=['light','dark','wibu'];
const ICON={light:'☀️',dark:'🌙',wibu:'🌸'};
function curTheme(){return root.getAttribute('data-theme')||'light';}
function syncTheme(){const c=curTheme();document.querySelectorAll('.themeBtn').forEach(b=>b.textContent=ICON[c]||'☀️');}
function setTheme(t){if(t==='light')root.removeAttribute('data-theme');else root.setAttribute('data-theme',t);localStorage.setItem('kb-theme',t);syncTheme();}
syncTheme();
document.querySelectorAll('.themeBtn').forEach(b=>b.addEventListener('click',()=>{
  const i=THEMES.indexOf(curTheme());setTheme(THEMES[(i+1)%THEMES.length]);
}));
const navChapters=[...document.querySelectorAll('.nav-chapter')];
document.querySelectorAll('.nav-sub, .nav-ch-title').forEach(a=>a.addEventListener('click',()=>{if(window.innerWidth<=980)document.querySelector('.sidebar').classList.remove('show');}));
const cur=document.querySelector('.nav-chapter.active');
if(cur){
  const heads=[...document.querySelectorAll('.chapter h2[id]')];
  const links=new Map([...cur.querySelectorAll('.nav-sub')].map(a=>[a.getAttribute('href').slice(1),a]));
  const obs=new IntersectionObserver((es)=>{es.forEach(e=>{if(e.isIntersecting){
    links.forEach(a=>a.classList.remove('here'));
    const a=links.get(e.target.id); if(a){a.classList.add('here');a.scrollIntoView({block:'nearest'});}
  }});},{rootMargin:'-10% 0px -80% 0px',threshold:0});
  heads.forEach(h=>obs.observe(h));
}
const box=document.getElementById('q');
if(box)box.addEventListener('input',()=>{const q=box.value.trim().toLowerCase();
  navChapters.forEach(c=>{const title=c.querySelector('.nav-ch-title').innerText.toLowerCase();
    const subs=[...c.querySelectorAll('.nav-sub')];let any=title.includes(q);
    subs.forEach(s=>{const m=s.innerText.toLowerCase().includes(q);s.style.display=(!q||m)?'block':'none';if(m)any=true;});
    c.style.display=(!q||any)?'block':'none';});
});
const mb=document.getElementById('menu');if(mb)mb.addEventListener('click',()=>document.querySelector('.sidebar').classList.toggle('show'));
document.addEventListener('keydown',e=>{
  if(e.target.tagName==='INPUT'||e.metaKey||e.ctrlKey||e.altKey)return;
  const p=document.querySelector('link[rel=prev]'),n=document.querySelector('link[rel=next]');
  if(e.key==='ArrowLeft'&&p)location.href=p.href;
  if(e.key==='ArrowRight'&&n)location.href=n.href;
});
"""

HEAD_THEME = "<script>(function(){var t=localStorage.getItem('kb-theme');if(t&&t!=='light')document.documentElement.setAttribute('data-theme',t);})();</script>"


def build(lang, other_exists):
    cfg = LANGS[lang]
    order = ["00"] + [n for _, ns in GROUPS_BASE for n in ns]
    rendered = {n: render(cfg, n) for n in order}
    if rendered["00"] is None:
        return False
    present = [n for n in order if rendered[n]]

    lang_btn = (f'<a class="ctrl-btn themeLink" href="{cfg["other_href"]}">🌐 {cfg["other"]}</a>'
                if other_exists else "")
    home_btn = f'<a class="ctrl-btn" href="{cfg["home_href"]}">🏠 {cfg["home"]}</a>'
    controls = f'{home_btn}<button class="ctrl-btn themeBtn" title="{cfg["theme_title"]}">🌙</button>{lang_btn}'
    prefix = "../" if lang == "en" else ""
    # Nền Wibu trỏ cố định tới assets/wibu-bg.jpg — thay file đó + push là đổi nền, không cần rebuild.
    wibu_style = f'<style>:root{{--wibu-bg:url("{prefix}assets/wibu-bg.jpg")}}</style>'
    outdir = os.path.dirname(f"{DIR}/{cfg['out']}")
    if outdir:
        os.makedirs(outdir, exist_ok=True)

    for idx, n in enumerate(present):
        r = rendered[n]
        nav = [nav_block(cfg, rendered["00"], n)]
        for g, ns in GROUPS_BASE:
            items = [x for x in ns if rendered[x]]
            if not items:
                continue
            nav.append(f'<div class="nav-group">{_html.escape(cfg["groups"][g])}</div>')
            nav += [nav_block(cfg, rendered[x], n) for x in items]

        prev_n = present[idx - 1] if idx > 0 else None
        next_n = present[idx + 1] if idx + 1 < len(present) else None
        rel = ""
        if prev_n: rel += f'<link rel="prev" href="{page_name(prev_n)}">'
        if next_n: rel += f'<link rel="next" href="{page_name(next_n)}">'

        def label(x):
            return cfg["intro"] if x == "00" else f'{x} · {cfg["short"][x]}'
        pager = '<nav class="pager">'
        pager += (f'<a class="pg prev" href="{page_name(prev_n)}"><span>← {cfg["prev"]}</span>'
                  f'<b>{_html.escape(label(prev_n))}</b></a>') if prev_n else '<span class="pg"></span>'
        pager += (f'<a class="pg next" href="{page_name(next_n)}"><span>{cfg["next"]} →</span>'
                  f'<b>{_html.escape(label(next_n))}</b></a>') if next_n else '<span class="pg"></span>'
        pager += '</nav>'

        ch_title = r["title"] if n != "00" else cfg["title"]
        page_title = f"{ch_title} — {cfg['title']}" if n != "00" else f"{cfg['title']} — Fee"
        page = f"""<!doctype html>
<html lang="{cfg['htmllang']}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_html.escape(page_title)}</title>
<meta name="description" content="{cfg['metadesc']}">
<meta property="og:title" content="{_html.escape(page_title)}">
<meta property="og:description" content="{cfg['metadesc']}">
<meta property="og:type" content="article">
<link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>📓</text></svg>">
{rel}
{HEAD_THEME}
{wibu_style}
<style>{CSS}</style>
</head>
<body>
<div class="wrap">
  <aside class="sidebar" id="sidebar">
    <div class="brand"><h1><a href="{page_name('00')}">{cfg['title']}</a></h1>
      <p class="tag">{cfg['tag']}</p>
      <span class="author">✍️ Fee</span>
      <div class="controls">{controls}</div></div>
    <div class="search"><input id="q" type="search" placeholder="{cfg['search']}" autocomplete="off"></div>
    <nav class="nav">{''.join(nav)}</nav>
  </aside>
  <div class="content">
    <div class="topbar"><button class="menu-btn" id="menu">☰</button><span class="ttl">{cfg['title']}</span>
      <button class="ctrl-btn themeBtn" title="{cfg['theme_title']}">🌙</button>{lang_btn}</div>
    <main class="main" id="top">
      {r['section']}
      {pager}
    </main>
    <footer class="site-foot">
      <p>{cfg['foot1']}
      &nbsp;·&nbsp; <a href="https://github.com/fee-191" target="_blank" rel="noopener">GitHub</a>
      &nbsp;·&nbsp; <a href="https://linkedin.com/in/leduongphi191" target="_blank" rel="noopener">LinkedIn</a></p>
      <p>{cfg['foot2']}</p>
    </footer>
  </div>
</div>
<script>{JS}</script>
</body>
</html>
"""
        out = os.path.join(outdir or DIR, page_name(n))
        with open(out, "w", encoding="utf-8") as f:
            f.write(page)
    return True


en_exists = all(os.path.exists(f"{DIR}/KB_{n}_{SLUGS[n]}.en.md") for n in SLUGS)
build("vi", other_exists=en_exists)
if en_exists:
    build("en", other_exists=True)
print(f"OK — VI built. EN built: {en_exists}")
