# 心理测评量表（静态站 · 内容加密）v2.0.0

纯 HTML/CSS/JS 静态站，手机优先，无后端、无统计脚本，答题记录只存在浏览器本机。
**全部页面正文、引擎、量表目录和题目数据都以 AES-256-GCM 密文发布**，仓库和线上只有密文；打开站点先输入访问密码，在浏览器内用 Web Crypto 解密后运行。密码不在仓库任何地方。

## 目录结构

```
index.html / scale.html / records.html / about.html   发布用外壳页（只有密码框）
js/gate.js        解密门：PBKDF2-SHA256 派生密钥 → AES-GCM 解密 → 运行站点（不含密钥）
css/style.css     样式
enc/site.js       页面正文 + 引擎 app.js + 目录 catalog.js 的密文，以及 KDF 参数（salt、迭代次数）
enc/d/<hmac>.js   每个量表数据文件的密文；文件名是 HMAC-SHA256(密钥, 量表id) 前 24 位，不暴露量表名
build_encrypt.py  构建脚本（明文 src/ → 上述密文产物）
tools/            外壳模板 shell.html、gate.js 源文件
src/              明文源文件 —— 已在 .gitignore 中，永远不要提交
  ├─ index.html scale.html records.html about.html
  ├─ js/app.js（答题与计分引擎） js/catalog.js（量表目录与分类）
  ├─ data/<id>.js（每个量表一个文件：题目、选项、计分、来源、自测）
  ├─ docs/如何新增量表.md
  └─ kdf_salt.hex（PBKDF2 的 salt，构建时自动生成并复用；不是秘密）
```

## 加密方式

- 密码 → PBKDF2-HMAC-SHA256，300000 次迭代，16 字节随机 salt → 64 字节：前 32 字节为 AES-256-GCM 密钥，后 32 字节为 HMAC 密钥（只用于生成数据文件名）。
- 每个密文独立 12 字节随机 IV；GCM 自带认证，密码错误会直接解密失败，不存在"绕过 JS 判断"的可能。
- 输对密码后派生密钥放在 `sessionStorage`（当前标签页内各页面免重复输入）；勾选"记住本设备"则同时存入 `localStorage`。页面右下角"🔒 锁定"可清除。
- 需要 HTTPS、`http://localhost` 或直接双击本地文件（Chrome/Edge 的 `file://` 也支持 Web Crypto）。

## 重新构建（以后新增或修改量表）

1. 在 `src/data/` 新建或修改 `<id>.js`，并在 `src/js/catalog.js` 登记（字段说明见 `src/docs/如何新增量表.md`）。
2. 校验：`"D:\Program Files\nodejs\node.exe" _work\validate.js --catalog`（检查题数、计分、自测答案）。
3. 构建（密码只通过环境变量传入，不要写进任何文件）：
   ```powershell
   $env:XL_PASSWORD = "<访问密码>"
   E:\programs\miniconda3\envs\llms\python.exe build_encrypt.py
   Remove-Item Env:XL_PASSWORD
   ```
   脚本会清空并重建 `enc/`、重写 4 个外壳页，并自检发布目录中搜不到题目明文。
4. 本地验证：`XL_PASSWORD=... python _work/e2e.py --all`（Playwright 自动走一遍密码门、全部量表页、PHQ-9 计分）。
5. 提交并推送 `main` 分支（只会提交密文产物；`src/`、`_work/` 已被忽略）。GitHub Pages 从 `main` 根目录发布，通常 1–3 分钟生效。

改密码：换一个 `XL_PASSWORD` 重新构建即可（旧密码立即失效；已"记住本设备"的浏览器需重新输入）。

## 注意

- 明文站点在 `src/` 里也能直接双击 `src/index.html` 使用（无密码），仅限本机。
- 本仓库的 git 历史从加密版本开始，不含任何明文题目。
- 量表结果仅供筛查参考，不能替代临床诊断。心理援助热线 12356 · 希望24热线 400-161-9995。
