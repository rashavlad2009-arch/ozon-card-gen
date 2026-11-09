export default function handler(req, res) {
  res.setHeader('Content-Type', 'image/svg+xml; charset=utf-8');
  res.setHeader('Cache-Control', 'public, max-age=86400');

  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630">
    <defs>
      <linearGradient id="bg" x1="0%" y1="0%" x2="100%" y2="100%">
        <stop offset="0%" stop-color="#06080f"/>
        <stop offset="50%" stop-color="#0f172a"/>
        <stop offset="100%" stop-color="#1e1b4b"/>
      </linearGradient>
      <linearGradient id="accent" x1="0%" y1="0%" x2="100%" y2="0%">
        <stop offset="0%" stop-color="#6366f1"/>
        <stop offset="50%" stop-color="#a855f7"/>
        <stop offset="100%" stop-color="#ec4899"/>
      </linearGradient>
      <linearGradient id="emerald" x1="0%" y1="0%" x2="100%" y2="0%">
        <stop offset="0%" stop-color="#10b981"/>
        <stop offset="100%" stop-color="#14b8a6"/>
      </linearGradient>
    </defs>

    <!-- Темный студийный фон -->
    <rect width="1200" height="630" fill="url(#bg)"/>
    <circle cx="950" cy="315" r="280" fill="#6366f1" opacity="0.18"/>
    <circle cx="200" cy="100" r="200" fill="#ec4899" opacity="0.12"/>

    <!-- Иконка и бренд -->
    <rect x="80" y="70" width="64" height="64" rx="16" fill="url(#accent)"/>
    <text x="112" y="116" font-family="Arial, sans-serif" font-size="40" font-weight="900" fill="#ffffff" text-anchor="middle">K</text>
    <text x="164" y="105" font-family="Arial, sans-serif" font-size="30" font-weight="900" fill="#ffffff">KARD-PRO.RU</text>
    <text x="164" y="130" font-family="Arial, sans-serif" font-size="16" font-weight="700" fill="#818cf8">AI STUDIO 2026 • OZON • WB • ЯНДЕКС • АВИТО</text>

    <!-- Главный заголовок -->
    <text x="80" y="240" font-family="Arial, sans-serif" font-size="56" font-weight="900" fill="#ffffff">ИИ-ГЕНЕРАТОР</text>
    <text x="80" y="308" font-family="Arial, sans-serif" font-size="56" font-weight="900" fill="#38bdf8">ПРОДАЮЩИХ КАРТОЧЕК</text>

    <!-- Буллиты -->
    <text x="80" y="380" font-family="Arial, sans-serif" font-size="24" font-weight="700" fill="#cbd5e1">✓ Упаковка товара в 1 клик (Заголовки + УТП + SEO)</text>
    <text x="80" y="422" font-family="Arial, sans-serif" font-size="24" font-weight="700" fill="#cbd5e1">✓ ИИ-вырезка фона и генерация студийных 3D-подиумов</text>
    <text x="80" y="464" font-family="Arial, sans-serif" font-size="24" font-weight="700" fill="#cbd5e1">✓ Готовые форматы под все маркетплейсы РФ</text>

    <!-- Плашка призыва -->
    <rect x="80" y="505" width="430" height="64" rx="18" fill="url(#emerald)"/>
    <text x="295" y="546" font-family="Arial, sans-serif" font-size="24" font-weight="900" fill="#06080f" text-anchor="middle">⚡ 5 ГЕНЕРАЦИЙ БЕСПЛАТНО</text>

    <!-- Макет карточки справа -->
    <rect x="780" y="75" width="340" height="480" rx="24" fill="#0f172a" stroke="#3b82f6" stroke-width="4"/>
    <rect x="810" y="105" width="140" height="34" rx="10" fill="#f91155"/>
    <text x="880" y="128" font-family="Arial, sans-serif" font-size="15" font-weight="900" fill="#ffffff" text-anchor="middle">ХИТ ПРОДАЖ</text>
    <text x="810" y="178" font-family="Arial, sans-serif" font-size="24" font-weight="900" fill="#ffffff">ВАШ ТОВАР</text>
    <ellipse cx="950" cy="360" rx="110" ry="24" fill="#3b82f6" opacity="0.5"/>
    <circle cx="950" cy="285" r="65" fill="url(#accent)"/>
    <rect x="810" y="415" width="280" height="42" rx="10" fill="#1e293b" stroke="#3b82f6" stroke-width="2"/>
    <text x="830" y="442" font-family="Arial, sans-serif" font-size="16" font-weight="700" fill="#ffffff">✓ Высокая конверсия CTR</text>
    <rect x="810" y="470" width="280" height="42" rx="10" fill="#1e293b" stroke="#3b82f6" stroke-width="2"/>
    <text x="830" y="497" font-family="Arial, sans-serif" font-size="16" font-weight="700" fill="#ffffff">✓ Готово за 10 секунд</text>
  </svg>`;

  return res.status(200).send(svg);
}
