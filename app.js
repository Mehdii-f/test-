/* ==========================================================
   سیسمونی نی‌نی ماه - منطق اصلی سایت
   - بدون هیچ inline-script (سازگار با CSP)
   - تمام خروجی‌ها با textContent / DOM ساخته می‌شوند (ضد XSS)
   - ورودی‌ها هنگام ذخیره و بازیابی پاک‌سازی و اعتبارسنجی می‌شوند
   ========================================================== */
(() => {
  'use strict';

  // جلوگیری از قرار گرفتن سایت داخل iframe (Clickjacking)
  if (window.top !== window.self) {
    document.body.replaceChildren();
    return;
  }

  const CFG = Object.assign({
    ADMIN_SESSION_MIN: 20, PBKDF2_ITER: 210000
  }, window.NINIMAH_CONFIG || {});

  const KEYS = {
    data: 'ninimah:data:v2',
    admin: 'ninimah:admin:v2',
    lock: 'ninimah:admin-lock:v2',
    session: 'ninimah:admin-session:v2'
  };
  const LOGO_FALLBACK = 'assets/logo-placeholder.svg';
  const DEFAULT_LOGO = 'assets/logo.png';
  const FADE_DISTANCE = 140;
  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const hasCrypto = !!(window.crypto && window.crypto.subtle);
  const enc = new TextEncoder();

  /* ---------------------------------------------------------
     ابزارهای عمومی
     --------------------------------------------------------- */
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
  const clamp = (n, a, b) => Math.min(b, Math.max(a, n));
  const sleep = ms => new Promise(r => setTimeout(r, ms));
  const uid = () => 'x' + Date.now().toString(36) + Math.random().toString(36).slice(2, 8);

  function h(tag, props = {}, ...kids) {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(props)) {
      if (v == null || v === false) continue;
      if (k === 'class') n.className = v;
      else if (k === 'text') n.textContent = v;
      else if (k === 'dataset') Object.assign(n.dataset, v);
      else n.setAttribute(k, v === true ? '' : String(v));
    }
    kids.flat().forEach(c => {
      if (c == null || c === false) return;
      n.append(c.nodeType ? c : document.createTextNode(String(c)));
    });
    return n;
  }

  const store = {
    get(k, fb) { try { const v = localStorage.getItem(k); return v == null ? fb : JSON.parse(v); } catch { return fb; } },
    set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); return true; } catch { return false; } },
    del(k) { try { localStorage.removeItem(k); } catch { /* ignore */ } }
  };
  const session = {
    get() { try { return JSON.parse(sessionStorage.getItem(KEYS.session)); } catch { return null; } },
    set(v) { try { sessionStorage.setItem(KEYS.session, JSON.stringify(v)); } catch { /* ignore */ } },
    del() { try { sessionStorage.removeItem(KEYS.session); } catch { /* ignore */ } }
  };

  const toEn = s => String(s)
    .replace(/[۰-۹]/g, d => '۰۱۲۳۴۵۶۷۸۹'.indexOf(d))
    .replace(/[٠-٩]/g, d => '٠١٢٣٤٥٦٧٨٩'.indexOf(d));
  const normFa = s => toEn(String(s)).toLowerCase().replace(/ي/g, 'ی').replace(/ك/g, 'ک');
  const str = (v, max = 200) => typeof v === 'string'
    ? v.replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, max) : '';
  const num = v => {
    const d = toEn(String(v ?? '')).replace(/[^\d]/g, '');
    const n = Number(d.slice(0, 12));
    return Number.isFinite(n) ? n : 0;
  };
  const formatPrice = p => p > 0 ? `${p.toLocaleString('fa-IR')} تومان` : 'تماس بگیرید';
  const escXml = s => String(s).replace(/[<>&"']/g, c => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&apos;' }[c]));

  /** فقط آدرس‌های امن: https، مسیر نسبی داخل پروژه، یا تصویر data: */
  function safeUrl(u) {
    if (typeof u !== 'string') return '';
    u = u.trim();
    if (!u || u.length > 4_000_000) return '';
    if (/^data:image\/(png|jpe?g|webp|gif);base64,[a-z0-9+/=]+$/i.test(u)) return u;
    // تصاویر SVG تولیدشده توسط خود سایت (placeholder)؛ داخل <img> هیچ اسکریپتی اجرا نمی‌شود
    if (/^data:image\/svg\+xml;charset=utf-8,[A-Za-z0-9%_.~!*'()-]+$/.test(u)) return u;
    if (/^https:\/\//i.test(u) && u.length < 2048) { try { new URL(u); return u; } catch { return ''; } }
    if (/^(?!\/\/)[\w\-./]+\.(png|jpe?g|webp|gif|svg)$/i.test(u) && !u.includes('..')) return u;
    return '';
  }

  function placeholder(emoji, label, hue = 205) {
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 600 450"><defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="hsl(${hue} 100% 90%)"/><stop offset="1" stop-color="hsl(${hue + 12} 95% 70%)"/></linearGradient></defs><rect width="600" height="450" fill="url(#g)"/><circle cx="470" cy="105" r="52" fill="#fff" opacity=".6"/><text x="300" y="255" font-size="120" text-anchor="middle">${escXml(emoji)}</text><text x="300" y="360" font-size="28" font-family="Tahoma,sans-serif" text-anchor="middle" fill="#0757b8">${escXml(label)}</text></svg>`;
    return 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(svg);
  }

  function withFallback(img, fallback) {
    img.addEventListener('error', () => {
      if (img.dataset.fb) return;
      img.dataset.fb = '1';
      img.src = typeof fallback === 'function' ? fallback() : fallback;
    });
    return img;
  }

  /* ---------------------------------------------------------
     داده‌ها: مقدار پیش‌فرض + پاک‌سازی
     --------------------------------------------------------- */
  const DEFAULT_SETTINGS = {
    siteName: 'سیسمونی نی‌نی ماه',
    slogan: 'دنیای آرامش و زیبایی برای فرشته کوچک شما',
    heroBadge: '✨ کامل‌ترین مجموعه سیسمونی نوزاد',
    heroTitle: 'هر آنچه برای شروع یک',
    heroHighlight: 'زندگی شیرین نیاز دارید',
    heroText: 'از پوشاک ضدحساسیت پنبه ارگانیک تا سرویس خواب، لوازم بهداشتی استاندارد و اسباب‌بازی‌های فکری؛ با عشق در کنار شما هستیم.',
    heroNote: 'کیفیت تضمین‌شده • ارسال به سراسر کشور',
    aboutTitle: 'همراه مطمئن والدین خوش‌سلیقه',
    aboutText: 'فروشگاه سیسمونی نی‌نی ماه با هدف ارائه باکیفیت‌ترین و ایمن‌ترین محصولات نوزاد و کودک راه‌اندازی شده است. ما در انتخاب تک‌تک کالاها، لطافت پوست نوزاد، ارگونومی استاندارد و طراحی دلنشین را در اولویت قرار می‌دهیم.',
    hours: 'پشتیبانی همه‌روزه از ساعت ۹ الی ۲۱',
    phone: '', whatsapp: '', instagram: '', telegram: '', address: '',
    logo: DEFAULT_LOGO
  };
  const OPTIONAL = new Set(['phone', 'whatsapp', 'instagram', 'telegram', 'address']);
  const LONG = new Set(['heroText', 'aboutText', 'address']);

  function cleanSetting(k, raw, def) {
    if (k === 'logo') return safeUrl(raw) || def;
    const s = typeof raw === 'string' ? raw : '';
    if (k === 'phone') { const v = str(toEn(s), 20); return /^[\d+\s-]{0,20}$/.test(v) ? v : ''; }
    if (k === 'whatsapp') {
      let d = toEn(s).replace(/\D/g, '');
      if (d.startsWith('0')) d = '98' + d.slice(1);
      return /^\d{8,15}$/.test(d) ? d : '';
    }
    if (k === 'instagram' || k === 'telegram') {
      const v = str(s, 80).replace(/^https?:\/\/(www\.)?(instagram\.com|t\.me)\//i, '').replace(/^@/, '').replace(/\/.*$/, '');
      return /^[A-Za-z0-9._]{1,40}$/.test(v) ? v : '';
    }
    const v = str(s, LONG.has(k) ? 500 : 150);
    return v || (OPTIONAL.has(k) ? '' : def);
  }

  const DEFAULT_CATS = [
    { id: 'clothes', name: 'پوشاک', icon: '👕' },
    { id: 'bed', name: 'تخت و کمد', icon: '🛏️' },
    { id: 'hygiene', name: 'بهداشتی', icon: '🛁' },
    { id: 'toys', name: 'اسباب بازی و اکسسوری', icon: '🧸' }
  ];
  const P = (id, cat, name, price, desc) => ({ id, cat, name, price, desc, img: '' });
  const DEFAULT_PRODUCTS = [
    P('p1', 'clothes', 'ست ۵ تکه بیمارستانی نوزاد طرح ماه', 980000, 'پنبه ارگانیک ۱۰۰٪ ضدحساسیت، مناسب بدو تولد'),
    P('p2', 'clothes', 'سرهمی نخی دکمه‌دار آسمانی', 540000, 'طراحی راحت برای تعویض پوشک با پارچه تنفس‌پذیر'),
    P('p3', 'clothes', 'بادی آستین کوتاه بسته ۳ عددی', 620000, 'دوخت ظریف بدون برچسب آزاردهنده داخلی'),
    P('p4', 'clothes', 'ست کلاه، دستکش و پاپوش نوزاد', 310000, 'بافت نرم و گرم، مناسب هوای سرد'),
    P('p5', 'clothes', 'سرهمی زمستانی پلار کلاه‌دار', 1150000, 'آستر پنبه‌ای و رویه پلار نرم'),
    P('p6', 'bed', 'تخت کنار مادر قابل تنظیم مدل رویا', 6800000, 'توری ضدحشره، حالت گهواره و تنظیم ارتفاع'),
    P('p7', 'bed', 'سرویس کامل تخت و کمد کودک مدل ابر', 24500000, 'چوب راش و MDF با رنگ پلی‌اورتان غیرسمی'),
    P('p8', 'bed', 'تشک طبی ضدرفلاکس نوزاد', 1450000, 'فوم هوشمند حافظه‌دار با روکش قابل شست‌وشو'),
    P('p9', 'bed', 'کمد ۴ کشو کودک مدل ستاره', 8900000, 'ریل‌های بی‌صدا و لبه‌های گرد ایمن'),
    P('p10', 'bed', 'ست ۷ تکه روتختی و محافظ تخت', 2100000, 'پنبه ۱۰۰٪ با طرح ماه و ستاره'),
    P('p11', 'hygiene', 'پک کامل حمام و مراقبت پوست نوزاد', 1290000, 'شامپو سر و بدن، لوسیون مرطوب‌کننده و کرم سوختگی'),
    P('p12', 'hygiene', 'وان حمام تاشو دماسنج‌دار نوزاد', 1750000, 'تشک توری نگهدارنده و نمایشگر دمای آب'),
    P('p13', 'hygiene', 'ست مانیکور و برس موی طبیعی کودک', 390000, 'قیچی سرگرد ایمن و برس الیاف طبیعی'),
    P('p14', 'hygiene', 'دستمال مرطوب بدون الکل بسته ۶ عددی', 480000, 'ضدحساسیت با عصاره آلوئه‌ورا'),
    P('p15', 'hygiene', 'ست شیشه شیر ضدکولیک و استریل‌کننده', 690000, 'سرشیشه سیلیکونی نرم و بدون BPA'),
    P('p16', 'toys', 'آویز موزیکال بالای تخت طرح ماه و ستاره', 1120000, 'لالایی ملایم با چرخش آرام و نور شب‌تاب'),
    P('p17', 'toys', 'تشک بازی جغجغه‌دار آموزشی', 1680000, 'تقویت حس بینایی، لامسه و مهارت‌های حرکتی'),
    P('p18', 'toys', 'کوله‌پشتی لوازم نوزاد ضدآب', 1490000, 'محفظه عایق حرارتی شیشه شیر و زیرانداز تعویض'),
    P('p19', 'toys', 'جغجغه و دندان‌گیر سیلیکونی', 260000, 'سیلیکون فوودگرید، مناسب دوران دندان‌درآوردن'),
    P('p20', 'toys', 'عروسک پولیشی خرگوش و ماه', 450000, 'نرم و قابل شست‌وشو، مناسب هدیه تولد')
  ];

  function defaults() {
    return {
      settings: { ...DEFAULT_SETTINGS },
      categories: DEFAULT_CATS.map(c => ({ ...c })),
      products: DEFAULT_PRODUCTS.map(p => ({ ...p })),
      slides: [
        { img: placeholder('👗', '', 205), caption: 'تنوع بی‌نظیر پوشاک نخی و ضدحساسیت نوزاد' },
        { img: placeholder('🛏️', '', 215), caption: 'طراحی آرامش‌بخش اتاق کودک با سرویس‌های استاندارد' },
        { img: placeholder('🧸', '', 195), caption: 'مشاوره تخصصی برای انتخاب بهترین سیسمونی' }
      ]
    };
  }

  /** هر داده‌ای که از localStorage یا فایل پشتیبان وارد شود از این فیلتر می‌گذرد */
  function sanitizeData(raw) {
    const d = defaults();
    if (!raw || typeof raw !== 'object') return d;
    if (!Array.isArray(raw.categories) || !Array.isArray(raw.products) || !Array.isArray(raw.slides)) return d;

    const out = { settings: {}, categories: [], products: [], slides: [] };
    const rs = raw.settings && typeof raw.settings === 'object' ? raw.settings : {};
    for (const k of Object.keys(DEFAULT_SETTINGS)) out.settings[k] = cleanSetting(k, rs[k], DEFAULT_SETTINGS[k]);

    const ids = new Set();
    for (const c of raw.categories.slice(0, 40)) {
      if (!c || typeof c !== 'object') continue;
      let id = str(c.id, 40);
      if (!/^[\w-]+$/.test(id) || ids.has(id)) id = uid();
      const name = str(c.name, 60);
      if (!name) continue;
      ids.add(id);
      out.categories.push({ id, name, icon: str(c.icon, 4) || '🍼' });
    }
    const pids = new Set();
    for (const p of raw.products.slice(0, 500)) {
      if (!p || typeof p !== 'object') continue;
      const cat = str(p.cat, 40);
      const name = str(p.name, 120);
      if (!name || !ids.has(cat)) continue;
      let id = str(p.id, 40);
      if (!/^[\w-]+$/.test(id) || pids.has(id)) id = uid();
      pids.add(id);
      out.products.push({ id, cat, name, price: num(p.price), desc: str(p.desc, 300), img: safeUrl(p.img) });
    }
    for (const s of raw.slides.slice(0, 30)) {
      if (!s || typeof s !== 'object') continue;
      const img = safeUrl(s.img);
      if (img) out.slides.push({ img, caption: str(s.caption, 150) });
    }
    return out;
  }

  let data = sanitizeData(store.get(KEYS.data, null));

  /** تغییر داده با امکان بازگشت در صورت پر بودن حافظه مرورگر */
  function mutate(fn) {
    const backup = JSON.parse(JSON.stringify(data));
    fn();
    if (!store.set(KEYS.data, data)) {
      data = backup;
      toast('حافظه مرورگر پر است. تصاویر کوچک‌تر انتخاب کنید یا به‌جای آپلود، لینک https بدهید.', 'danger');
      return false;
    }
    renderPublic();
    renderAdmin();
    return true;
  }

  /* ---------------------------------------------------------
     Toast و مودال
     --------------------------------------------------------- */
  function toast(text, type = 'info', ms = 4200) {
    const t = h('div', { class: `toast toast-${type}`, role: 'status', text });
    $('#toasts').append(t);
    setTimeout(() => t.remove(), ms);
  }

  function setMsg(id, text, type = 'info') {
    const el = $('#' + id);
    if (!el) return;
    if (!text) { el.hidden = true; el.textContent = ''; return; }
    el.className = `alert alert-${type}`;
    el.textContent = text;
    el.hidden = false;
  }

  let lastFocus = null;
  function setView(modalId, name) {
    $$('[data-view]', $('#' + modalId)).forEach(v => { v.hidden = v.dataset.view !== name; });
  }
  function openModal(id) {
    const m = $('#' + id);
    lastFocus = document.activeElement;
    m.classList.add('open');
    m.setAttribute('aria-hidden', 'false');
    document.body.classList.add('no-scroll');
    setTimeout(() => {
      const f = $$('input:not([type=hidden]):not([type=file]), select, textarea', m).find(el => el.offsetParent !== null);
      if (f) f.focus();
    }, 30);
  }
  function closeModal(id) {
    const m = $('#' + id);
    m.classList.remove('open');
    m.setAttribute('aria-hidden', 'true');
    if (!$('.modal.open')) document.body.classList.remove('no-scroll');
    if (lastFocus && lastFocus.focus) lastFocus.focus();
  }

  /* ---------------------------------------------------------
     نمایش عمومی سایت
     --------------------------------------------------------- */
  let activeCat = 'all';
  const catById = id => data.categories.find(c => c.id === id);
  const catHue = id => 195 + (Math.max(0, data.categories.findIndex(c => c.id === id)) * 9) % 40;

  function productImage(p) {
    const c = catById(p.cat);
    return p.img || placeholder(c ? c.icon : '🍼', p.name.slice(0, 26), catHue(p.cat));
  }

  function contactHref(p) {
    const s = data.settings;
    const msg = `سلام، درباره «${p.name}» می‌خواستم اطلاعات بگیرم.`;
    if (s.whatsapp) return `https://wa.me/${s.whatsapp}?text=${encodeURIComponent(msg)}`;
    if (s.phone) return `tel:${s.phone.replace(/[^\d+]/g, '')}`;
    return '';
  }

  function renderBrand() {
    const s = data.settings;
    document.title = `${s.siteName} | فروشگاه تخصصی نوزاد و کودک`;
    $('#brandName').textContent = s.siteName;
    $('#brandSlogan').textContent = s.slogan;
    $('#heroBadge').textContent = s.heroBadge;
    $('#heroTitle').textContent = s.heroTitle;
    $('#heroHighlight').textContent = s.heroHighlight;
    $('#heroText').textContent = s.heroText;
    $('#heroNote').textContent = s.heroNote;
    $('#aboutTitle').textContent = s.aboutTitle;
    $('#aboutText').textContent = s.aboutText;
    $('#footName').textContent = s.siteName;
    for (const id of ['siteLogo', 'heroLogo']) {
      const img = $('#' + id);
      img.dataset.fb = '';
      img.src = safeUrl(s.logo) || LOGO_FALLBACK;
    }
    const li = (...kids) => h('li', {}, ...kids);
    const items = [];
    if (s.phone) items.push(li(h('a', { href: `tel:${s.phone.replace(/[^\d+]/g, '')}`, dir: 'ltr', text: `📞 ${s.phone}` })));
    if (s.whatsapp) items.push(li(h('a', { href: `https://wa.me/${s.whatsapp}`, target: '_blank', rel: 'noopener noreferrer', text: '💬 واتساپ' })));
    if (s.instagram) items.push(li(h('a', { href: `https://instagram.com/${s.instagram}`, target: '_blank', rel: 'noopener noreferrer', text: `📷 اینستاگرام: ${s.instagram}` })));
    if (s.telegram) items.push(li(h('a', { href: `https://t.me/${s.telegram}`, target: '_blank', rel: 'noopener noreferrer', text: `✈️ تلگرام: ${s.telegram}` })));
    if (s.address) items.push(li(`📍 ${s.address}`));
    if (s.hours) items.push(li(`🕘 ${s.hours}`));
    $('#footContact').replaceChildren(...items);
  }

  function renderTabs() {
    if (activeCat !== 'all' && !catById(activeCat)) activeCat = 'all';
    const mk = (id, label) => h('button', {
      class: 'cat-btn' + (activeCat === id ? ' active' : ''), type: 'button', role: 'tab',
      'aria-selected': String(activeCat === id), dataset: { action: 'cat', cat: id }, text: label
    });
    $('#categoryTabs').replaceChildren(
      mk('all', 'همه'),
      ...data.categories.map(c => mk(c.id, `${c.icon} ${c.name}`))
    );
  }

  function renderProducts() {
    const q = normFa($('#searchInput').value.trim());
    const list = data.products.filter(p =>
      (activeCat === 'all' || p.cat === activeCat) &&
      (!q || normFa(p.name).includes(q) || normFa(p.desc).includes(q)));
    const grid = $('#productsGrid');
    if (!list.length) { grid.replaceChildren(h('p', { class: 'empty', text: 'محصولی با این مشخصات یافت نشد.' })); return; }

    grid.replaceChildren(...list.map(p => {
      const c = catById(p.cat);
      const href = contactHref(p);
      const img = withFallback(h('img', { src: productImage(p), alt: p.name, loading: 'lazy', decoding: 'async' }),
        () => placeholder(c ? c.icon : '🍼', '', catHue(p.cat)));
      const action = href
        ? h('a', { class: 'btn btn-soft btn-sm', href, target: href.startsWith('http') ? '_blank' : null, rel: 'noopener noreferrer', text: 'استعلام / سفارش' })
        : h('button', { class: 'btn btn-soft btn-sm', type: 'button', dataset: { action: 'no-contact' }, text: 'استعلام / سفارش' });
      return h('article', { class: 'product-card fx' },
        h('div', { class: 'product-img' }, h('span', { class: 'product-tag', text: c ? c.name : '' }), img),
        h('div', { class: 'product-body' },
          h('div', {}, h('h4', { class: 'product-title', text: p.name }), h('p', { class: 'product-desc', text: p.desc })),
          h('div', { class: 'product-footer' }, h('span', { class: 'product-price', text: formatPrice(p.price) }), action)));
    }));
    updateFade();
  }

  /* ---------- اسلایدر ---------- */
  let slideIdx = 0, slideTimer = null, slideHover = false;

  function renderSlider() {
    const track = $('#slidesTrack'), dots = $('#sliderDots');
    const n = data.slides.length;
    if (slideIdx >= n) slideIdx = 0;
    track.replaceChildren(...data.slides.map(s => h('div', { class: 'slide' },
      withFallback(h('img', { src: s.img, alt: s.caption || 'تصویر فروشگاه', loading: 'lazy' }), () => placeholder('🍼', '', 205)),
      s.caption ? h('div', { class: 'slide-caption', text: s.caption }) : null)));
    dots.replaceChildren(...data.slides.map((_, i) =>
      h('button', { class: 'dot', type: 'button', 'aria-label': `اسلاید ${i + 1}`, dataset: { action: 'slide-go', i } })));
    $$('.slider-btn').forEach(b => { b.hidden = n < 2; });
    updateSlider();
  }
  function updateSlider() {
    // کانتینر RTL است: اسلاید بعدی سمت چپ قرار دارد، پس track به راست می‌رود
    $('#slidesTrack').style.transform = `translateX(${slideIdx * 100}%)`;
    $$('.dot').forEach((d, i) => d.classList.toggle('active', i === slideIdx));
  }
  function moveSlide(step) {
    const n = data.slides.length;
    if (n < 2) return;
    slideIdx = (slideIdx + step + n) % n;
    updateSlider();
  }
  function startAuto() {
    clearInterval(slideTimer);
    if (reduceMotion) return;
    slideTimer = setInterval(() => { if (!slideHover && !document.hidden) moveSlide(1); }, 4500);
  }
  function initSliderEvents() {
    const sl = $('#aboutSlider');
    sl.addEventListener('mouseenter', () => { slideHover = true; });
    sl.addEventListener('mouseleave', () => { slideHover = false; });
    sl.addEventListener('focusin', () => { slideHover = true; });
    sl.addEventListener('focusout', () => { slideHover = false; });
    let x0 = null;
    sl.addEventListener('pointerdown', e => { x0 = e.clientX; });
    sl.addEventListener('pointerup', e => {
      if (x0 == null) return;
      const dx = e.clientX - x0;
      x0 = null;
      if (Math.abs(dx) > 40) moveSlide(dx > 0 ? 1 : -1);
    });
    sl.addEventListener('pointercancel', () => { x0 = null; });
  }

  function renderPublic() {
    renderBrand();
    renderTabs();
    renderProducts();
    renderSlider();
  }

  /* ---------------------------------------------------------
     افکت محو شدن عناصر هنگام رفتن به زیر هدر
     --------------------------------------------------------- */
  let ticking = false;
  function updateFade() {
    const header = $('#mainHeader');
    header.classList.toggle('scrolled', window.scrollY > 30);
    if (reduceMotion) return;
    const hb = header.getBoundingClientRect().bottom;
    for (const el of $$('.fx')) {
      const r = el.getBoundingClientRect();
      const o = clamp((r.bottom - hb) / FADE_DISTANCE, 0, 1);
      const v = o >= 0.995 ? '' : o.toFixed(2);
      if (el.style.opacity !== v) el.style.opacity = v;
    }
  }
  function onScroll() {
    if (ticking) return;
    ticking = true;
    requestAnimationFrame(() => { ticking = false; updateFade(); });
  }

  /* ---------------------------------------------------------
     رمزنگاری
     --------------------------------------------------------- */
  const b64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
  const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  async function derive(pass, salt, iterations) {
    const key = await crypto.subtle.importKey('raw', enc.encode(pass), 'PBKDF2', false, ['deriveBits']);
    return new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, key, 256));
  }
  function safeEqual(a, b) {
    if (a.length !== b.length) return false;
    let r = 0;
    for (let i = 0; i < a.length; i++) r |= a[i] ^ b[i];
    return r === 0;
  }
  function passwordProblem(pass, user) {
    if (pass.length < 10) return 'رمز عبور باید حداقل ۱۰ کاراکتر باشد.';
    if (!/[a-z]/.test(pass) || !/[A-Z]/.test(pass) || !/\d/.test(pass)) return 'رمز باید شامل حرف کوچک، حرف بزرگ و عدد انگلیسی باشد.';
    if (user && pass.toLowerCase().includes(user.toLowerCase())) return 'رمز عبور نباید شامل نام کاربری باشد.';
    return '';
  }

  /* ---------------------------------------------------------
     مدیر: احراز هویت
     --------------------------------------------------------- */
  const sessionValid = () => { const s = session.get(); return !!(s && s.exp > Date.now()); };
  function startSession() { session.set({ exp: Date.now() + CFG.ADMIN_SESSION_MIN * 60000 }); }
  function adminOk() {
    if (sessionValid()) { startSession(); return true; }
    if ($('#adminModal').classList.contains('open')) { showAdminView(); toast('نشست شما منقضی شد. دوباره وارد شوید.', 'danger'); }
    return false;
  }
  function showAdminView() {
    const rec = store.get(KEYS.admin, null);
    const v = !rec ? 'setup' : sessionValid() ? 'dash' : 'login';
    setView('adminModal', v);
    $('#adminCard').classList.toggle('wide', v === 'dash');
    setMsg('adminMsg', '');
    if (v === 'dash') { renderAdmin(); fillSettingsForm(); }
  }
  function openAdmin() {
    showAdminView();
    openModal('adminModal');
    if (!hasCrypto) setMsg('adminMsg', 'مرورگر شما از رمزنگاری پشتیبانی نمی‌کند؛ سایت باید روی https یا localhost باز شود.', 'danger');
  }
  async function adminSetup() {
    if (!hasCrypto) return;
    const user = str($('#setupUser').value, 30);
    const p1 = $('#setupPass').value, p2 = $('#setupPass2').value;
    if (!/^[A-Za-z0-9_.-]{3,30}$/.test(user)) return setMsg('adminMsg', 'نام کاربری فقط شامل حروف انگلیسی، عدد و _ . - و حداقل ۳ کاراکتر باشد.', 'danger');
    const prob = passwordProblem(p1, user);
    if (prob) return setMsg('adminMsg', prob, 'danger');
    if (p1 !== p2) return setMsg('adminMsg', 'رمز و تکرار آن یکسان نیستند.', 'danger');
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const hash = await derive(p1, salt, CFG.PBKDF2_ITER);
    if (!store.set(KEYS.admin, { user, salt: b64(salt), hash: b64(hash), iter: CFG.PBKDF2_ITER })) return setMsg('adminMsg', 'ذخیره‌سازی ممکن نشد.', 'danger');
    $('#setupPass').value = ''; $('#setupPass2').value = '';
    startSession();
    showAdminView();
    toast('حساب مدیر ساخته شد.', 'success');
  }
  async function adminLogin() {
    if (!hasCrypto) return;
    const lock = store.get(KEYS.lock, { fails: 0, until: 0 });
    if (Date.now() < lock.until) {
      const sec = Math.ceil((lock.until - Date.now()) / 1000);
      return setMsg('adminMsg', `به دلیل تلاش‌های ناموفق، ورود ${sec.toLocaleString('fa-IR')} ثانیه قفل است.`, 'danger');
    }
    const rec = store.get(KEYS.admin, null);
    if (!rec) return showAdminView();
    const btn = $('#adminLoginBtn');
    btn.disabled = true;
    try {
      const user = $('#adminUser').value.trim();
      const got = await derive($('#adminPass').value, unb64(rec.salt), rec.iter);
      const ok = safeEqual(got, unb64(rec.hash)) && user === rec.user;
      await sleep(500 + Math.random() * 300);
      if (ok) {
        store.del(KEYS.lock);
        $('#adminPass').value = '';
        startSession();
        showAdminView();
      } else {
        lock.fails = (lock.fails || 0) + 1;
        let text = `نام کاربری یا رمز عبور اشتباه است. (${(lock.fails % 3 || 3).toLocaleString('fa-IR')} از ۳)`;
        if (lock.fails % 3 === 0) {
          const sec = Math.min(3600, 60 * Math.pow(2, lock.fails / 3 - 1));
          lock.until = Date.now() + sec * 1000;
          text = `۳ بار ورود ناموفق! دسترسی به مدت ${sec.toLocaleString('fa-IR')} ثانیه مسدود شد.`;
        }
        store.set(KEYS.lock, lock);
        setMsg('adminMsg', text, 'danger');
      }
    } finally { btn.disabled = false; }
  }
  function adminLogout() {
    session.del();
    closeModal('adminModal');
    toast('با موفقیت خارج شدید.');
  }
  async function changePassword() {
    if (!adminOk()) return;
    const rec = store.get(KEYS.admin, null);
    const cur = $('#pwCurrent').value, nw = $('#pwNew').value;
    const got = await derive(cur, unb64(rec.salt), rec.iter);
    if (!safeEqual(got, unb64(rec.hash))) { await sleep(600); return setMsg('pwMsg', 'رمز فعلی نادرست است.', 'danger'); }
    const prob = passwordProblem(nw, rec.user);
    if (prob) return setMsg('pwMsg', prob, 'danger');
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const hash = await derive(nw, salt, CFG.PBKDF2_ITER);
    store.set(KEYS.admin, { user: rec.user, salt: b64(salt), hash: b64(hash), iter: CFG.PBKDF2_ITER });
    $('#pwCurrent').value = ''; $('#pwNew').value = '';
    setMsg('pwMsg', 'رمز عبور با موفقیت تغییر کرد.', 'success');
  }

  /* ---------------------------------------------------------
     مدیر: ابزار تصویر
     --------------------------------------------------------- */
  async function fileToDataUrl(file, { max = 900, type = 'image/jpeg', q = 0.82 } = {}) {
    if (!/^image\/(png|jpe?g|webp|gif)$/i.test(file.type)) throw new Error('فرمت تصویر مجاز نیست (PNG, JPG, WEBP, GIF).');
    if (file.size > 10 * 1024 * 1024) throw new Error('حجم تصویر بیش از ۱۰ مگابایت است.');
    const url = URL.createObjectURL(file);
    try {
      const img = await new Promise((res, rej) => {
        const i = new Image();
        i.onload = () => res(i);
        i.onerror = () => rej(new Error('تصویر قابل خواندن نیست.'));
        i.src = url;
      });
      const scale = Math.min(1, max / Math.max(img.naturalWidth, img.naturalHeight));
      const w = Math.max(1, Math.round(img.naturalWidth * scale));
      const hh = Math.max(1, Math.round(img.naturalHeight * scale));
      const c = document.createElement('canvas');
      c.width = w; c.height = hh;
      const ctx = c.getContext('2d');
      if (type === 'image/jpeg') { ctx.fillStyle = '#fff'; ctx.fillRect(0, 0, w, hh); }
      ctx.drawImage(img, 0, 0, w, hh);
      const out = c.toDataURL(type, q);
      return safeUrl(out) ? out : (() => { throw new Error('تبدیل تصویر ناموفق بود.'); })();
    } finally { URL.revokeObjectURL(url); }
  }
  function setPreview(id, url, fallback) {
    const el = $('#' + id);
    el.dataset.fb = '';
    el.src = url || fallback;
  }

  /* ---------------------------------------------------------
     مدیر: داشبورد
     --------------------------------------------------------- */
  let currentTab = 'products';
  let prodEditId = null, prodImg = '';
  let slideImgPending = '';
  let logoPending = null;

  function switchTab(name) {
    currentTab = name;
    $$('[data-panel]').forEach(p => { p.hidden = p.dataset.panel !== name; });
    $$('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === name));
  }

  const rowBtn = (label, action, dataset, cls = 'btn-soft') =>
    h('button', { class: `btn btn-sm ${cls}`, type: 'button', dataset: { action, ...dataset }, text: label });

  function renderAdmin() {
    if (!$('#adminModal').classList.contains('open') || $('[data-view=dash]').hidden) return;

    const sel = $('#prodCat'), prev = sel.value;
    sel.replaceChildren(...data.categories.map(c => h('option', { value: c.id, text: `${c.icon} ${c.name}` })));
    if (prev && catById(prev)) sel.value = prev;

    $('#adminProducts').replaceChildren(...(data.products.length ? data.products.map(p => {
      const c = catById(p.cat);
      return h('div', { class: 'row' },
        h('div', { class: 'row-main' },
          withFallback(h('img', { class: 'thumb', src: productImage(p), alt: '' }), () => placeholder('🍼', '')),
          h('div', {}, h('strong', { text: p.name }), h('small', { text: `${c ? c.name : '—'} • ${formatPrice(p.price)}` }))),
        h('div', { class: 'row-actions' },
          rowBtn('ویرایش', 'prod-edit', { id: p.id }),
          rowBtn('حذف', 'prod-del', { id: p.id }, 'btn-danger')));
    }) : [h('p', { class: 'hint', text: 'هنوز محصولی ثبت نشده است.' })]));

    $('#adminCategories').replaceChildren(...data.categories.map(c => h('div', { class: 'row' },
      h('div', { class: 'row-main' },
        h('input', { class: 'cat-input cat-icon', value: c.icon, maxlength: 4, 'aria-label': 'آیکون', dataset: { catId: c.id, field: 'icon' } }),
        h('input', { class: 'cat-input cat-name', value: c.name, maxlength: 60, 'aria-label': 'نام دسته‌بندی', dataset: { catId: c.id, field: 'name' } }),
        h('small', { text: `${data.products.filter(p => p.cat === c.id).length.toLocaleString('fa-IR')} محصول` })),
      h('div', { class: 'row-actions' }, rowBtn('حذف', 'cat-del', { id: c.id }, 'btn-danger')))));

    $('#adminSlides').replaceChildren(...(data.slides.length ? data.slides.map((s, i) => h('div', { class: 'row' },
      h('div', { class: 'row-main' },
        withFallback(h('img', { class: 'thumb', src: s.img, alt: '' }), () => placeholder('🍼', '')),
        h('div', {}, h('strong', { text: s.caption || '(بدون متن)' }), h('small', { text: `اسلاید ${(i + 1).toLocaleString('fa-IR')}` }))),
      h('div', { class: 'row-actions' },
        rowBtn('↑', 'slide-up', { i }), rowBtn('↓', 'slide-down', { i }), rowBtn('حذف', 'slide-del', { i }, 'btn-danger'))))
      : [h('p', { class: 'hint', text: 'اسلایدی وجود ندارد.' })]));
  }

  function fillSettingsForm() {
    const s = data.settings;
    $$('#settingsForm [name]').forEach(el => { el.value = s[el.name] || ''; });
    logoPending = null;
    setPreview('logoPreview', safeUrl(s.logo), LOGO_FALLBACK);
    setMsg('setMsg', '');
  }

  /* ---------- محصولات ---------- */
  function resetProductForm() {
    prodEditId = null; prodImg = '';
    $('#productForm').reset();
    $('#productFormTitle').textContent = 'افزودن محصول';
    $('#prodCancel').hidden = true;
    setPreview('prodPreview', '', placeholder('🍼', 'بدون عکس'));
    setMsg('prodMsg', '');
  }
  function editProduct(id) {
    const p = data.products.find(x => x.id === id);
    if (!p) return;
    prodEditId = id; prodImg = p.img;
    $('#prodName').value = p.name;
    $('#prodCat').value = p.cat;
    $('#prodPrice').value = p.price || '';
    $('#prodDesc').value = p.desc;
    $('#prodImgUrl').value = p.img.startsWith('data:') ? '' : p.img;
    $('#productFormTitle').textContent = 'ویرایش محصول';
    $('#prodCancel').hidden = false;
    setPreview('prodPreview', productImage(p), '');
    $('#productForm').scrollIntoView({ behavior: reduceMotion ? 'auto' : 'smooth', block: 'center' });
  }
  function saveProduct() {
    if (!adminOk()) return;
    const name = str($('#prodName').value, 120);
    const cat = $('#prodCat').value;
    const price = num($('#prodPrice').value);
    const desc = str($('#prodDesc').value, 300);
    const urlRaw = $('#prodImgUrl').value.trim();
    if (!name) return setMsg('prodMsg', 'نام محصول الزامی است.', 'danger');
    if (!catById(cat)) return setMsg('prodMsg', 'ابتدا یک دسته‌بندی بسازید.', 'danger');
    if (urlRaw && !safeUrl(urlRaw)) return setMsg('prodMsg', 'آدرس عکس معتبر نیست؛ فقط https یا مسیر فایل داخل پروژه مجاز است.', 'danger');
    const img = urlRaw ? safeUrl(urlRaw) : prodImg;
    const ok = mutate(() => {
      if (prodEditId) {
        const i = data.products.findIndex(p => p.id === prodEditId);
        if (i > -1) data.products[i] = { id: prodEditId, cat, name, price, desc, img };
      } else {
        data.products.unshift({ id: uid(), cat, name, price, desc, img });
      }
    });
    if (ok) { resetProductForm(); toast('محصول ذخیره شد.', 'success'); }
  }

  /* ---------- دسته‌بندی‌ها ---------- */
  function addCategory() {
    if (!adminOk()) return;
    const name = str($('#newCatName').value, 60);
    const icon = str($('#newCatIcon').value, 4) || '🍼';
    if (!name) return setMsg('catMsg', 'نام دسته‌بندی را وارد کنید.', 'danger');
    if (data.categories.some(c => c.name === name)) return setMsg('catMsg', 'این دسته‌بندی از قبل وجود دارد.', 'danger');
    if (data.categories.length >= 40) return setMsg('catMsg', 'حداکثر ۴۰ دسته‌بندی مجاز است.', 'danger');
    if (mutate(() => data.categories.push({ id: uid(), name, icon }))) {
      $('#categoryForm').reset(); setMsg('catMsg', '');
      toast('دسته‌بندی افزوده شد.', 'success');
    }
  }
  function deleteCategory(id) {
    if (!adminOk()) return;
    const used = data.products.filter(p => p.cat === id).length;
    if (used) return toast(`ابتدا ${used.toLocaleString('fa-IR')} محصول این دسته را منتقل یا حذف کنید.`, 'danger');
    if (!confirm('این دسته‌بندی حذف شود؟')) return;
    mutate(() => { data.categories = data.categories.filter(c => c.id !== id); });
  }
  function editCategoryField(el) {
    if (!adminOk()) return;
    const c = catById(el.dataset.catId);
    if (!c) return;
    const val = str(el.value, el.dataset.field === 'icon' ? 4 : 60);
    if (!val) { renderAdmin(); return; }
    if (el.dataset.field === 'name' && data.categories.some(x => x.id !== c.id && x.name === val)) { toast('این نام تکراری است.', 'danger'); renderAdmin(); return; }
    mutate(() => { c[el.dataset.field] = val; });
  }

  /* ---------- اسلایدر ---------- */
  function addSlide() {
    if (!adminOk()) return;
    const urlRaw = $('#slideUrl').value.trim();
    if (urlRaw && !safeUrl(urlRaw)) return setMsg('slideMsg', 'آدرس عکس معتبر نیست؛ فقط https یا مسیر فایل داخل پروژه.', 'danger');
    const img = urlRaw ? safeUrl(urlRaw) : slideImgPending;
    if (!img) return setMsg('slideMsg', 'یک عکس انتخاب یا لینک آن را وارد کنید.', 'danger');
    if (data.slides.length >= 30) return setMsg('slideMsg', 'حداکثر ۳۰ اسلاید مجاز است.', 'danger');
    const caption = str($('#slideCaption').value, 150);
    if (mutate(() => data.slides.push({ img, caption }))) {
      $('#slideForm').reset(); slideImgPending = '';
      setPreview('slidePreview', '', placeholder('🖼️', ''));
      setMsg('slideMsg', ''); toast('اسلاید افزوده شد.', 'success');
    }
  }
  function moveSlideItem(i, dir) {
    if (!adminOk()) return;
    const j = i + dir;
    if (j < 0 || j >= data.slides.length) return;
    mutate(() => { [data.slides[i], data.slides[j]] = [data.slides[j], data.slides[i]]; });
  }
  function deleteSlide(i) {
    if (!adminOk() || !confirm('این اسلاید حذف شود؟')) return;
    mutate(() => { data.slides.splice(i, 1); });
  }

  /* ---------- تنظیمات و لوگو ---------- */
  function saveSettings() {
    if (!adminOk()) return;
    const next = {};
    for (const k of Object.keys(DEFAULT_SETTINGS)) {
      if (k === 'logo') continue;
      const el = $(`#settingsForm [name="${k}"]`);
      next[k] = cleanSetting(k, el ? el.value : '', DEFAULT_SETTINGS[k]);
    }
    next.logo = logoPending === '' ? DEFAULT_LOGO : (logoPending || data.settings.logo);
    if (mutate(() => { data.settings = next; })) { fillSettingsForm(); toast('تنظیمات ذخیره شد.', 'success'); }
  }

  /* ---------- پشتیبان ---------- */
  function exportData() {
    if (!adminOk()) return;
    const blob = new Blob([JSON.stringify({ app: 'ninimah', version: 2, exportedAt: new Date().toISOString(), data }, null, 2)], { type: 'application/json' });
    const a = h('a', { href: URL.createObjectURL(blob), download: 'ninimah-backup.json' });
    document.body.append(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  }
  async function importData(file) {
    if (!adminOk() || !file) return;
    if (file.size > 12 * 1024 * 1024) return setMsg('bkMsg', 'حجم فایل بیش از حد مجاز است.', 'danger');
    let parsed;
    try { parsed = JSON.parse(await file.text()); } catch { return setMsg('bkMsg', 'فایل JSON معتبر نیست.', 'danger'); }
    const raw = parsed && parsed.data ? parsed.data : parsed;
    if (!raw || !Array.isArray(raw.categories) || !Array.isArray(raw.products) || !Array.isArray(raw.slides)) return setMsg('bkMsg', 'ساختار فایل پشتیبان درست نیست.', 'danger');
    if (!confirm('اطلاعات فعلی سایت با فایل پشتیبان جایگزین شود؟')) return;
    if (mutate(() => { data = sanitizeData(raw); })) { fillSettingsForm(); setMsg('bkMsg', 'بازیابی با موفقیت انجام شد.', 'success'); }
  }
  function resetSite() {
    if (!adminOk() || !confirm('همه محصولات، اسلایدها و تنظیمات به حالت اولیه برمی‌گردد. ادامه می‌دهید؟')) return;
    mutate(() => { data = defaults(); });
    fillSettingsForm(); resetProductForm();
  }

  /* ---------------------------------------------------------
     رویدادها
     --------------------------------------------------------- */
  document.addEventListener('click', e => {
    const t = e.target.closest('[data-action]');
    if (t) {
      const d = t.dataset;
      switch (d.action) {
        case 'open-admin': openAdmin(); break;
        case 'close-modal': { const m = t.closest('.modal'); if (m) closeModal(m.id); break; }
        case 'cat': activeCat = d.cat; renderTabs(); renderProducts(); break;
        case 'no-contact': toast('اطلاعات تماس هنوز در تنظیمات فروشگاه ثبت نشده است.'); break;
        case 'slide-next': moveSlide(1); break;
        case 'slide-prev': moveSlide(-1); break;
        case 'slide-go': slideIdx = Number(d.i) || 0; updateSlider(); break;
        case 'tab': switchTab(d.tab); break;
        case 'admin-logout': adminLogout(); break;
        case 'prod-edit': if (adminOk()) editProduct(d.id); break;
        case 'prod-del':
          if (adminOk() && confirm('این محصول حذف شود؟')) mutate(() => { data.products = data.products.filter(p => p.id !== d.id); });
          break;
        case 'prod-cancel': resetProductForm(); break;
        case 'prod-clear-img': prodImg = ''; $('#prodImgUrl').value = ''; $('#prodImgFile').value = ''; setPreview('prodPreview', '', placeholder('🍼', 'بدون عکس')); break;
        case 'cat-del': deleteCategory(d.id); break;
        case 'slide-up': moveSlideItem(Number(d.i), -1); break;
        case 'slide-down': moveSlideItem(Number(d.i), 1); break;
        case 'slide-del': deleteSlide(Number(d.i)); break;
        case 'logo-reset': logoPending = ''; $('#logoFile').value = ''; setPreview('logoPreview', DEFAULT_LOGO, LOGO_FALLBACK); break;
        case 'export': exportData(); break;
        case 'reset-site': resetSite(); break;
        default: break;
      }
      return;
    }
    if (e.target.classList && e.target.classList.contains('modal')) closeModal(e.target.id);
  });

  document.addEventListener('submit', e => {
    e.preventDefault();
    switch (e.target.id) {
      case 'searchForm': renderProducts(); break;
      case 'adminSetupForm': adminSetup(); break;
      case 'adminLoginForm': adminLogin(); break;
      case 'productForm': saveProduct(); break;
      case 'categoryForm': addCategory(); break;
      case 'slideForm': addSlide(); break;
      case 'settingsForm': saveSettings(); break;
      case 'passwordForm': changePassword(); break;
      default: break;
    }
  });

  document.addEventListener('change', async e => {
    const el = e.target;
    try {
      if (el.id === 'prodImgFile' && el.files[0]) {
        if (!adminOk()) return;
        prodImg = await fileToDataUrl(el.files[0]);
        $('#prodImgUrl').value = '';
        setPreview('prodPreview', prodImg, '');
        setMsg('prodMsg', '');
      } else if (el.id === 'slideFile' && el.files[0]) {
        if (!adminOk()) return;
        slideImgPending = await fileToDataUrl(el.files[0], { max: 1400, q: 0.8 });
        $('#slideUrl').value = '';
        setPreview('slidePreview', slideImgPending, '');
        setMsg('slideMsg', '');
      } else if (el.id === 'logoFile' && el.files[0]) {
        if (!adminOk()) return;
        logoPending = await fileToDataUrl(el.files[0], { max: 500, type: 'image/webp', q: 0.92 });
        setPreview('logoPreview', logoPending, '');
      } else if (el.id === 'importFile') {
        await importData(el.files[0]);
        el.value = '';
      } else if (el.dataset && el.dataset.catId) {
        editCategoryField(el);
      }
    } catch (err) {
      const target = { prodImgFile: 'prodMsg', slideFile: 'slideMsg', logoFile: 'setMsg' }[el.id];
      if (target) setMsg(target, err.message, 'danger'); else toast(err.message, 'danger');
      el.value = '';
    }
  });

  $('#prodImgUrl').addEventListener('input', () => {
    const u = safeUrl($('#prodImgUrl').value);
    if (u) { prodImg = ''; $('#prodImgFile').value = ''; setPreview('prodPreview', u, ''); }
  });
  $('#slideUrl').addEventListener('input', () => {
    const u = safeUrl($('#slideUrl').value);
    if (u) { slideImgPending = ''; $('#slideFile').value = ''; setPreview('slidePreview', u, ''); }
  });
  $('#searchInput').addEventListener('input', renderProducts);

  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') { const m = $('.modal.open'); if (m) closeModal(m.id); }
  });
  // هر فعالیتی در پنل، نشست مدیر را تمدید می‌کند
  $('#adminModal').addEventListener('input', () => { if (sessionValid()) startSession(); });
  setInterval(() => {
    if ($('#adminModal').classList.contains('open') && !$('[data-view=dash]').hidden && !sessionValid()) {
      showAdminView();
      toast('به دلیل بی‌فعالیتی از پنل خارج شدید.', 'danger');
    }
  }, 15000);

  window.addEventListener('scroll', onScroll, { passive: true });
  window.addEventListener('resize', onScroll);

  /* ---------------------------------------------------------
     شروع
     --------------------------------------------------------- */
  withFallback($('#siteLogo'), LOGO_FALLBACK);
  withFallback($('#heroLogo'), LOGO_FALLBACK);
  withFallback($('#logoPreview'), LOGO_FALLBACK);
  setPreview('prodPreview', '', placeholder('🍼', 'بدون عکس'));
  setPreview('slidePreview', '', placeholder('🖼️', ''));
  initSliderEvents();
  renderPublic();
  startAuto();
  updateFade();
})();
