#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re, os, unicodedata, html as _html
import markdown
from markdown.extensions.toc import TocExtension

DIR = os.path.dirname(os.path.abspath(__file__))
OUT = f"{DIR}/index.html"

INTRO = ("00", "Index", "Giới thiệu & Mục lục")

GROUPS = [
    ("Phần A · Nền tảng", [
        ("01", "Networking", "Mạng máy tính"),
        ("02", "Linux", "Hệ điều hành Linux"),
        ("03", "Windows-AD", "Windows & Active Directory"),
        ("04", "Crypto-Core", "Mật mã & Nền tảng bảo mật"),
    ]),
    ("Phần B · An ninh ứng dụng & DevSecOps", [
        ("05", "AppSec-OWASP", "An ninh ứng dụng Web (OWASP)"),
        ("06", "DevSecOps-Scanning-Semgrep", "DevSecOps & Quét mã nguồn"),
        ("07", "CICD-GitOps", "CI/CD & GitOps"),
    ]),
    ("Phần C · Giám sát, Phát hiện & Ứng phó", [
        ("08", "SIEM-Wazuh", "SIEM & Quản lý log"),
        ("09", "ELK-Zabbix", "Observability & Giám sát hạ tầng"),
        ("10", "SOC-IR", "Vận hành SOC & Ứng phó sự cố"),
    ]),
    ("Phần D · Phòng thủ mạng & Kiểm thử", [
        ("11", "IDS-WAF-NetDef", "Phòng thủ mạng (IDS/WAF/VPN)"),
        ("12", "Pentest-VulnScan", "Kiểm thử & Đánh giá lỗ hổng"),
    ]),
    ("Phần E · Hạ tầng, Ảo hóa & Đám mây", [
        ("13", "Cloud", "Bảo mật Đám mây"),
        ("14", "Virtualization-Containers", "Ảo hóa & Container"),
    ]),
    ("Phần F · Tấn công, Tuân thủ & Tự động hóa", [
        ("15", "ThreatIntel-Frameworks", "Threat Intel & Khung tấn công"),
        ("16", "Compliance-GRC", "Tuân thủ & Quản trị (GRC)"),
        ("17", "Python-Security", "Lập trình & Tự động hóa"),
    ]),
]

def make_slugify(prefix):
    def slug(value, sep):
        value = unicodedata.normalize('NFKD', value)
        value = re.sub(r'[^\w\s-]', '', value, flags=re.U).strip().lower()
        value = re.sub(r'[\s]+', sep, value, flags=re.U)
        return f"{prefix}-{value}" if value else prefix
    return slug

sections_html = []
nav_html = []

def render(n, slug, short):
    path = f"{DIR}/KB_{n}_{slug}.md"
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read()
    except FileNotFoundError:
        return
    md = markdown.Markdown(extensions=[
        'fenced_code', 'tables', 'sane_lists', 'attr_list',
        TocExtension(slugify=make_slugify(f"ch{n}"), toc_depth="1-3")
    ])
    body = md.convert(text)
    toks = md.toc_tokens
    ch_id = f"sec-{n}"
    for t in toks:
        if t.get('level') == 1:
            ch_id = t['id']; break
    subs = []
    def walk(nodes):
        for t in nodes:
            if t.get('level') == 2:
                subs.append(t)
            walk(t.get('children', []))
    walk(toks)
    sections_html.append(f'<section class="chapter" id="sec-{n}" data-ch="{n}">\n{body}\n</section>')
    sub_links = "".join(
        f'<a class="nav-sub" href="#{s["id"]}">{_html.escape(s["name"])}</a>'
        for s in subs
    )
    nav_html.append(
        f'<div class="nav-chapter" data-ch="{n}">'
        f'<a class="nav-ch-title" href="#{ch_id}"><span class="num">{n}</span>'
        f'<span class="t">{_html.escape(short)}</span></a>'
        f'<div class="nav-subs">{sub_links}</div></div>'
    )

render(*INTRO)
for gtitle, chs in GROUPS:
    nav_html.append(f'<div class="nav-group">{_html.escape(gtitle)}</div>')
    for n, slug, short in chs:
        render(n, slug, short)

CSS = r"""
:root{
  --bg:#f4efe3;        /* giấy ngà */
  --panel:#ebe3d1;     /* sidebar giấy đậm hơn */
  --panel2:#e1d7c0;    /* hover / input */
  --ink:#2b2620;       /* mực nâu đen */
  --muted:#79705e;     /* chữ phụ */
  --line:#d6cbb3;      /* viền */
  --accent:#0f6e60;    /* teal trầm */
  --accent2:#b1502c;   /* nâu đỏ */
  --code-bg:#241f18;   /* khối code: nâu đen ấm */
  --code-ink:#ece3d1;  /* chữ trong code */
  --tbl-head:#e6dcc5;  /* header bảng */
  --tbl-zebra:#efe8d6; /* zebra */
  --kbd:#e6dcc5;       /* nền inline code */
  --serif:Georgia,"Iowan Old Style","Times New Roman",serif;
}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;background:var(--bg);color:var(--ink);
  font:16px/1.72 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,"Noto Sans",sans-serif;}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}

/* layout */
.wrap{display:flex;min-height:100vh}
.sidebar{width:322px;flex:0 0 322px;background:var(--panel);border-right:1px solid var(--line);
  height:100vh;position:sticky;top:0;overflow-y:auto;padding:0}
.brand{padding:20px 18px 13px;border-bottom:1px solid var(--line);position:sticky;top:0;background:var(--panel);z-index:2}
.brand h1{font-family:var(--serif);font-size:19px;margin:0 0 3px;letter-spacing:.2px;color:var(--ink)}
.brand .tag{margin:3px 0 0;font-size:11.5px;color:var(--muted);line-height:1.45}
.brand .author{display:block;margin-top:7px;font-size:11.5px;color:var(--accent2);font-weight:600}
.search{padding:10px 14px;position:sticky;top:70px;background:var(--panel);z-index:2;border-bottom:1px solid var(--line)}
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

/* content */
.content{flex:1;min-width:0;padding:0 0 120px}
.topbar{display:none}
.main{max-width:820px;margin:0 auto;padding:40px 44px}
.chapter{border-bottom:1px solid var(--line);padding-bottom:44px;margin-bottom:14px}
.chapter h1{font-family:var(--serif);font-size:31px;line-height:1.22;margin:40px 0 20px;padding-bottom:12px;
  border-bottom:2px solid var(--accent);color:var(--ink);scroll-margin-top:16px}
.chapter:first-child h1{margin-top:8px}
h2{font-family:var(--serif);font-size:23px;margin:36px 0 12px;color:var(--ink);scroll-margin-top:16px}
h3{font-family:var(--serif);font-size:18px;margin:24px 0 8px;color:var(--ink);scroll-margin-top:16px}
h4{font-size:14px;margin:18px 0 6px;color:var(--accent);font-weight:700;text-transform:none}
p{margin:11px 0}
ul,ol{margin:11px 0;padding-left:24px}
li{margin:5px 0}
strong{color:var(--ink);font-weight:700}
hr{border:0;border-top:1px solid var(--line);margin:28px 0}
blockquote{margin:15px 0;padding:9px 16px;border-left:3px solid var(--accent2);
  background:var(--panel);border-radius:0 7px 7px 0;color:#5f574a}

/* code */
code{font-family:"SF Mono","JetBrains Mono",Consolas,"Liberation Mono",monospace;font-size:13px}
:not(pre)>code{background:var(--kbd);color:#9c4421;padding:1.5px 6px;border-radius:5px;font-size:12.5px}
pre{background:var(--code-bg);border:1px solid #3a3228;border-radius:9px;padding:14px 16px;
  overflow-x:auto;margin:15px 0;line-height:1.55}
pre code{color:var(--code-ink);background:none;padding:0;font-size:12.7px;white-space:pre}

/* tables */
.tbl-scroll,table{width:100%}
table{border-collapse:collapse;margin:16px 0;font-size:13.5px;display:block;overflow-x:auto}
th,td{border:1px solid var(--line);padding:8px 11px;text-align:left;vertical-align:top}
th{background:var(--tbl-head);color:var(--ink);font-weight:700;white-space:nowrap}
tbody tr:nth-child(even){background:var(--tbl-zebra)}

/* responsive */
.menu-btn{display:none}
@media(max-width:980px){
  .sidebar{position:fixed;left:0;top:0;z-index:50;transform:translateX(-100%);transition:transform .25s}
  .sidebar.show{transform:none;box-shadow:0 0 40px rgba(40,30,15,.35)}
  .topbar{display:flex;align-items:center;gap:12px;position:sticky;top:0;z-index:40;
    background:var(--panel);border-bottom:1px solid var(--line);padding:10px 16px}
  .menu-btn{display:inline-flex;background:var(--bg);border:1px solid var(--line);color:var(--ink);
    border-radius:7px;padding:7px 12px;font-size:14px;cursor:pointer}
  .topbar .ttl{font-family:var(--serif);font-size:15px;font-weight:700}
  .main{padding:24px 18px}
  .chapter h1{font-size:25px}
}
::-webkit-scrollbar{width:11px;height:11px}
::-webkit-scrollbar-thumb{background:#cabda2;border-radius:6px;border:2px solid var(--bg)}
::-webkit-scrollbar-track{background:transparent}

.site-foot{max-width:820px;margin:54px auto 0;padding:24px 44px 0;border-top:1px solid var(--line);
  color:var(--muted);font-size:13px;line-height:1.7}
.site-foot a{color:var(--accent)}
.site-foot .name{color:var(--ink);font-weight:700}
@media(max-width:980px){.site-foot{padding:24px 18px 0}}
"""

JS = r"""
const navChapters=[...document.querySelectorAll('.nav-chapter')];
function openOnly(ch){navChapters.forEach(c=>{c.classList.toggle('open',c.dataset.ch===ch);c.classList.toggle('active',c.dataset.ch===ch);});}
navChapters.forEach(c=>{c.querySelector('.nav-ch-title').addEventListener('click',()=>{openOnly(c.dataset.ch);if(window.innerWidth<=980)document.querySelector('.sidebar').classList.remove('show');});});
document.querySelectorAll('.nav-sub').forEach(a=>a.addEventListener('click',()=>{if(window.innerWidth<=980)document.querySelector('.sidebar').classList.remove('show');}));
// scrollspy by chapter
const secs=[...document.querySelectorAll('.chapter')];
const obs=new IntersectionObserver((es)=>{es.forEach(e=>{if(e.isIntersecting){openOnly(e.target.dataset.ch);const act=document.querySelector('.nav-chapter.active');if(act)act.scrollIntoView({block:'nearest'});}});},{rootMargin:'-10% 0px -80% 0px',threshold:0});
secs.forEach(s=>obs.observe(s));
// search filter
const box=document.getElementById('q');
box.addEventListener('input',()=>{const q=box.value.trim().toLowerCase();
  navChapters.forEach(c=>{const title=c.querySelector('.nav-ch-title').innerText.toLowerCase();
    const subs=[...c.querySelectorAll('.nav-sub')];let any=title.includes(q);
    subs.forEach(s=>{const m=s.innerText.toLowerCase().includes(q);s.style.display=(!q||m)?'block':'none';if(m)any=true;});
    c.style.display=(!q||any)?'block':'none';if(q&&any)c.classList.add('open');});
});
// menu toggle
const mb=document.getElementById('menu');if(mb)mb.addEventListener('click',()=>document.querySelector('.sidebar').classList.toggle('show'));
// open first chapter
if(navChapters[0])navChapters[0].classList.add('open','active');
"""

page = f"""<!doctype html>
<html lang="vi">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sổ tay An toàn thông tin — Lê Dương Phi</title>
<meta name="description" content="Blog chia sẻ kiến thức an toàn thông tin — ghi chép trong quá trình học và làm việc.">
<style>{CSS}</style>
</head>
<body>
<div class="wrap">
  <aside class="sidebar" id="sidebar">
    <div class="brand"><h1>Sổ tay An toàn thông tin</h1>
      <p class="tag">Chia sẻ kiến thức · ghi chép khi học &amp; làm</p>
      <span class="author">✍️ Lê Dương Phi</span></div>
    <div class="search"><input id="q" type="search" placeholder="Lọc mục lục…" autocomplete="off"></div>
    <nav class="nav">{''.join(nav_html)}</nav>
  </aside>
  <div class="content">
    <div class="topbar"><button class="menu-btn" id="menu">☰ Mục lục</button><span class="ttl">Giáo trình An toàn thông tin</span></div>
    <main class="main">
      {''.join(sections_html)}
    </main>
    <footer class="site-foot">
      <p>Ghi chép & chia sẻ bởi <span class="name">Lê Dương Phi</span> · tự do cho mục đích học tập.
      &nbsp;·&nbsp; <a href="https://github.com/fee-191" target="_blank" rel="noopener">GitHub</a>
      &nbsp;·&nbsp; <a href="https://linkedin.com/in/leduongphi191" target="_blank" rel="noopener">LinkedIn</a></p>
      <p>Nội dung mang tính giáo dục, nhằm mục đích phòng thủ. Hãy thực hành hợp pháp, chỉ trên hệ thống bạn được phép.</p>
    </footer>
  </div>
</div>
<script>{JS}</script>
</body>
</html>
"""

with open(OUT, "w", encoding="utf-8") as f:
    f.write(page)

import os
print(f"OK: {OUT}  ({os.path.getsize(OUT)//1024} KB)")
print(f"Chương render: {len(sections_html)}")
