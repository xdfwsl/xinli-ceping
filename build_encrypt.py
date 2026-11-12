#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
build_encrypt.py v2.0.0 —— 把 src/ 下的明文站点构建为密码保护的发布目录。

    python build_encrypt.py                # 密码取环境变量 XL_PASSWORD
    python build_encrypt.py --password ...  # 或命令行传入（注意 shell 历史）

产物（写到仓库根目录，即 GitHub Pages 的发布根）：
    index.html / scale.html / records.html / about.html   外壳页（只含密码输入框）
    js/gate.js                                             解密门（无密钥）
    css/style.css                                          样式（不含量表内容）
    enc/site.js                                            页面正文 + 引擎 + 目录 的密文
    enc/d/<hmac>.js                                        每个量表数据文件的密文，文件名为 HMAC(id)
    robots.txt / .nojekyll

密码学：PBKDF2-HMAC-SHA256（默认 300000 次迭代，16 字节随机 salt，salt 保存在 src/kdf_salt.hex 以便重建后"记住本设备"仍有效）
派生 64 字节：前 32 字节 AES-256-GCM 密钥，后 32 字节 HMAC-SHA256 密钥（用于数据文件名）。每个密文独立 12 字节随机 IV。
密码不写入任何文件；构建完成后自动检查输出目录里搜不到明文题目。
"""
import argparse, base64, hashlib, hmac, json, os, re, secrets, shutil, sys, time

__version__ = "2.3.0"

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    sys.exit("需要 cryptography 包：pip install cryptography")

ROOT = os.path.dirname(os.path.abspath(__file__))
PAGES = ["index", "scale", "records", "about"]


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def read(p):
    with open(p, encoding="utf-8") as f:
        return f.read()


def write(p, s):
    os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
    with open(p, "w", encoding="utf-8", newline="\n") as f:
        f.write(s)


def parse_page(html):
    """取 <title>、<body> 内正文（去掉 script 标签）、外链脚本名、内联初始化代码。"""
    title = re.search(r"<title>(.*?)</title>", html, re.S)
    body = re.search(r"<body[^>]*>(.*)</body>", html, re.S).group(1)
    scripts, inits = [], []
    for m in re.finditer(r"<script([^>]*)>(.*?)</script>", body, re.S):
        src = re.search(r'src="([^"]+)"', m.group(1))
        if src:
            scripts.append(os.path.splitext(os.path.basename(src.group(1)))[0])
        elif m.group(2).strip():
            inits.append(m.group(2).strip())
    body = re.sub(r"<script[^>]*>.*?</script>", "", body, flags=re.S).strip()
    return {"title": title.group(1).strip() if title else "心理测评量表", "body": body, "scripts": scripts, "init": "\n".join(inits)}


def main():
    ap = argparse.ArgumentParser(description="构建密码保护的静态站")
    ap.add_argument("--src", default=os.path.join(ROOT, "src"))
    ap.add_argument("--out", default=ROOT)
    ap.add_argument("--password", default=os.environ.get("XL_PASSWORD", ""))
    ap.add_argument("--iter", type=int, default=300000)
    ap.add_argument("--salt-file", default=None, help="默认 <src>/kdf_salt.hex，不存在则随机生成并保存")
    a = ap.parse_args()
    if not a.password:
        sys.exit("未提供密码：设置环境变量 XL_PASSWORD 或使用 --password")
    if a.iter < 300000:
        sys.exit("迭代次数不得低于 300000")
    src, out = os.path.abspath(a.src), os.path.abspath(a.out)
    if not os.path.isdir(os.path.join(src, "data")):
        sys.exit("源目录不对：" + src)

    salt_file = a.salt_file or os.path.join(src, "kdf_salt.hex")
    if os.path.exists(salt_file):
        salt = bytes.fromhex(read(salt_file).strip())
    else:
        salt = secrets.token_bytes(16)
        write(salt_file, salt.hex() + "\n")
        print("已生成新的 salt ->", salt_file)

    import unicodedata
    pw = unicodedata.normalize("NFKC", a.password).encode("utf-8")
    bits = hashlib.pbkdf2_hmac("sha256", pw, salt, a.iter, dklen=64)
    aes, mac = AESGCM(bits[:32]), bits[32:]

    def enc(text: str):
        iv = secrets.token_bytes(12)
        ct = aes.encrypt(iv, text.encode("utf-8"), None)
        return {"iv": b64(iv), "ct": b64(ct)}

    def dname(scale_id: str):
        return hmac.new(mac, scale_id.encode("utf-8"), hashlib.sha256).hexdigest()[:24]

    version = (re.search(r"VERSION = '([^']+)'", read(os.path.join(src, "js", "app.js"))) or [None, "0"])[1]
    build = time.strftime("%Y%m%d%H%M%S")

    # 1. 页面 + 脚本
    site = {"v": 1, "version": version, "build": build, "kdf": {"name": "PBKDF2-SHA256", "iter": a.iter, "salt": b64(salt)},
            "check": enc("ok:" + version), "pages": {}, "scripts": {}}
    for pg in PAGES:
        site["pages"][pg] = enc(json.dumps(parse_page(read(os.path.join(src, pg + ".html"))), ensure_ascii=False))
    for name in ["catalog", "app"]:
        site["scripts"][name] = enc(read(os.path.join(src, "js", name + ".js")))

    # 2. 清理旧产物并写入
    enc_dir = os.path.join(out, "enc")
    if os.path.isdir(enc_dir):
        shutil.rmtree(enc_dir)
    os.makedirs(os.path.join(enc_dir, "d"))
    write(os.path.join(enc_dir, "site.js"), "window.XL_ENC=" + json.dumps(site, ensure_ascii=False, separators=(",", ":")) + ";\n")

    data_files = sorted(f for f in os.listdir(os.path.join(src, "data")) if f.endswith(".js"))
    for f in data_files:
        sid = f[:-3]
        blob = enc(read(os.path.join(src, "data", f)))
        write(os.path.join(enc_dir, "d", dname(sid) + ".js"), "XLGATE.data(%s,%s);\n" % (json.dumps(dname(sid)), json.dumps(blob)))

    shell = read(os.path.join(ROOT, "tools", "shell.html"))
    for pg in PAGES:
        write(os.path.join(out, pg + ".html"), shell.replace("{{PAGE}}", pg).replace("{{VERSION}}", version).replace("{{BUILD}}", build))
    os.makedirs(os.path.join(out, "js"), exist_ok=True)
    os.makedirs(os.path.join(out, "css"), exist_ok=True)
    shutil.copyfile(os.path.join(ROOT, "tools", "gate.js"), os.path.join(out, "js", "gate.js"))
    shutil.copyfile(os.path.join(src, "css", "style.css"), os.path.join(out, "css", "style.css"))
    write(os.path.join(out, "robots.txt"), "User-agent: *\nDisallow: /\n")
    write(os.path.join(out, ".nojekyll"), "")
    # 发布目录里不应残留明文 data/ 或 docs/
    for stale in ["data", "docs"]:
        if os.path.isdir(os.path.join(out, stale)) and os.path.abspath(os.path.join(out, stale)) != os.path.abspath(os.path.join(src, stale)):
            shutil.rmtree(os.path.join(out, stale))
    for stale in ["js/app.js", "js/catalog.js"]:
        p = os.path.join(out, stale)
        if os.path.exists(p):
            os.remove(p)

    # 3. 明文泄漏自检：从每个量表随机抽 3 条题干，在全部产物里搜索
    probes = []
    for f in data_files:
        ts = re.findall(r"\bt:\s*'((?:[^'\\]|\\.){8,})'", read(os.path.join(src, "data", f)))
        probes += [(f, t) for t in ts[:1] + ts[len(ts) // 2: len(ts) // 2 + 1] + ts[-1:]]
    outputs = []
    for d, _, fs in os.walk(out):
        if any(x in d for x in (os.sep + "src", os.sep + ".git", os.sep + "_work", os.sep + "tools")):
            continue
        for fn in fs:
            if fn.endswith((".html", ".js", ".css", ".json", ".txt", ".md")):
                outputs.append(os.path.join(d, fn))
    blob_all = "\n".join(read(p) for p in outputs)
    leaks = [(f, t) for f, t in probes if t in blob_all]
    if leaks:
        for f, t in leaks:
            print("!! 明文泄漏:", f, t[:30])
        sys.exit("构建失败：发布目录里出现明文题目")

    total = sum(os.path.getsize(os.path.join(enc_dir, "d", f)) for f in os.listdir(os.path.join(enc_dir, "d")))
    print("构建完成 v%s build %s：页面 %d，量表密文 %d 个（%.0f KB），site.js %.0f KB，迭代 %d，输出 %s" % (
        version, build, len(PAGES), len(data_files), total / 1024, os.path.getsize(os.path.join(enc_dir, "site.js")) / 1024, a.iter, out))
    print("明文自检：抽样 %d 条题干，产物中均未出现。" % len(probes))


if __name__ == "__main__":
    main()
