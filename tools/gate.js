/* 心理测评量表 · 站点密码门 v2.0.0
 * 页面正文、引擎脚本、量表目录与全部量表题目都以 AES-256-GCM 密文随站点发布（见 enc/）。
 * 本文件只负责：输入密码 → PBKDF2-SHA256 派生密钥 → 在浏览器内用 Web Crypto 解密 → 运行站点。
 * 不含任何密钥、口令或明文内容。
 */
(function () {
  'use strict';
  var SK = 'xl.key';            // sessionStorage/localStorage 里保存的派生密钥（base64，64 字节）
  var ENC = null, KEYS = null, PAGE = 'index';
  var te = new TextEncoder(), td = new TextDecoder();

  function subtle() { return window.crypto && window.crypto.subtle; }
  function b64enc(buf) { var u = new Uint8Array(buf), s = ''; for (var i = 0; i < u.length; i++) s += String.fromCharCode(u[i]); return btoa(s); }
  function b64dec(str) { var s = atob(str), u = new Uint8Array(s.length); for (var i = 0; i < s.length; i++) u[i] = s.charCodeAt(i); return u; }

  function deriveBits(pw) {
    return subtle().importKey('raw', te.encode(pw.normalize('NFKC')), 'PBKDF2', false, ['deriveBits']).then(function (k) {
      return subtle().deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: b64dec(ENC.kdf.salt), iterations: ENC.kdf.iter }, k, 512);
    });
  }
  function importKeys(bits) {
    var u = new Uint8Array(bits);
    return Promise.all([
      subtle().importKey('raw', u.slice(0, 32), { name: 'AES-GCM' }, false, ['decrypt']),
      subtle().importKey('raw', u.slice(32, 64), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
    ]).then(function (ks) { return { aes: ks[0], mac: ks[1] }; });
  }
  function decrypt(blob) {
    return subtle().decrypt({ name: 'AES-GCM', iv: b64dec(blob.iv) }, KEYS.aes, b64dec(blob.ct)).then(function (pt) { return td.decode(pt); });
  }
  function dataName(id) {
    return subtle().sign('HMAC', KEYS.mac, te.encode(id)).then(function (sig) {
      var u = new Uint8Array(sig), h = '';
      for (var i = 0; i < 12; i++) h += (u[i] < 16 ? '0' : '') + u[i].toString(16);
      return h;
    });
  }
  function runScript(src, name) {
    var s = document.createElement('script');
    s.text = src + '\n//# sourceURL=' + name;
    document.body.appendChild(s);
  }
  function forget() { try { sessionStorage.removeItem(SK); localStorage.removeItem(SK); } catch (e) {} }

  function render() {
    return decrypt(ENC.pages[PAGE]).then(function (json) {
      var p = JSON.parse(json);
      document.title = p.title || document.title;
      document.body.innerHTML = p.body;
      var chain = Promise.resolve();
      (p.scripts || []).forEach(function (name) {
        chain = chain.then(function () { return decrypt(ENC.scripts[name]).then(function (src) { runScript(src, name + '.js'); }); });
      });
      return chain.then(function () {
        if (p.init) runScript(p.init, 'init.js');
        var a = document.createElement('a');
        a.className = 'lockfab'; a.href = '#'; a.textContent = '🔒 锁定';
        a.title = '清除本设备上保存的密钥，下次打开需重新输入密码';
        a.onclick = function (e) { e.preventDefault(); forget(); location.href = 'index.html'; };
        document.body.appendChild(a);
      });
    });
  }

  function showGate(msg) {
    var g = document.getElementById('gate');
    if (!g) return;
    g.style.display = '';
    var inp = document.getElementById('pw'), btn = document.getElementById('go'), rem = document.getElementById('rem'), err = document.getElementById('err');
    if (msg) err.textContent = msg;
    if (!subtle()) { err.textContent = '当前浏览器或打开方式不支持 Web Crypto，请改用 https 链接或较新的浏览器。'; btn.disabled = true; return; }
    function go() {
      var pw = inp.value;
      if (!pw) { err.textContent = '请输入密码'; return; }
      btn.disabled = true; err.textContent = '正在解密…';
      deriveBits(pw).then(function (bits) {
        return importKeys(bits).then(function (k) { KEYS = k; return decrypt(ENC.check); }).then(function () {
          var b = b64enc(bits);
          try { sessionStorage.setItem(SK, b); if (rem.checked) localStorage.setItem(SK, b); } catch (e) {}
          return render();
        });
      }).catch(function () {
        KEYS = null; btn.disabled = false; err.textContent = '密码错误，请重试'; inp.select();
      });
    }
    btn.onclick = go;
    inp.onkeydown = function (e) { if (e.key === 'Enter') go(); };
    setTimeout(function () { inp.focus(); }, 50);
  }

  var pendingData = {};
  window.XLGATE = {
    version: '2.0.0',
    boot: function (page) {
      PAGE = page || 'index';
      ENC = window.XL_ENC;
      if (!ENC) { showGate('站点密文未加载'); return; }
      var stored = null;
      try { stored = sessionStorage.getItem(SK) || localStorage.getItem(SK); } catch (e) {}
      if (stored && subtle()) {
        importKeys(b64dec(stored)).then(function (k) { KEYS = k; return decrypt(ENC.check); }).then(render)
          .catch(function () { KEYS = null; forget(); showGate(); });
      } else showGate();
    },
    // 由引擎调用：按量表 id 加载并解密 enc/d/<hmac>.js
    loadData: function (id, onerr) {
      if (!KEYS) { if (onerr) onerr(); return; }
      dataName(id).then(function (name) {
        pendingData[name] = { onerr: onerr };
        var s = document.createElement('script');
        s.src = 'enc/d/' + name + '.js';
        s.onerror = function () { delete pendingData[name]; if (onerr) onerr(); };
        document.body.appendChild(s);
      });
    },
    // 由 enc/d/<name>.js 回调
    data: function (name, blob) {
      var p = pendingData[name]; delete pendingData[name];
      decrypt(blob).then(function (src) { runScript(src, 'data-' + name + '.js'); }).catch(function () { if (p && p.onerr) p.onerr(); });
    },
    lock: function () { forget(); location.reload(); }
  };
})();
