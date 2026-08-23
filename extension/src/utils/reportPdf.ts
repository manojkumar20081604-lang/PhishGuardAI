/**
 * PhishGuard AI - Scan Report PDF Generator (offline, zero-dependency)
 *
 * Builds a small standards-compliant PDF 1.4 file from a ScanResult using
 * only the PDF base-14 Helvetica fonts, so nothing is bundled and nothing
 * is fetched - consistent with the extension's local-only privacy claim.
 *
 * Limitations by design: WinAnsi/Latin-1 text only (emoji are stripped),
 * simple word-wrap layout, A4 pages.
 */

import type { ScanResult } from '../services/baseApi';

/** Convenience alias for consumers outside popup (e.g. the content script). */
export type ScanResultForReport = ScanResult;

// ============================================================================
// PUBLIC API
// ============================================================================

export function buildScanReportPdf(result: ScanResult): Uint8Array {
  const lines = layoutReport(result);
  return assemblePdf(lines);
}

export function downloadScanReport(result: ScanResult): void {
  const bytes = buildScanReportPdf(result);
  const blob = new Blob([bytes as unknown as BlobPart], { type: 'application/pdf' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = `phishguard-report-${stamp()}.pdf`;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

function stamp(): string {
  return new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
}

// ============================================================================
// LAYOUT
// ============================================================================

const PAGE_W = 595; // A4 pt
const PAGE_H = 842;
const MARGIN = 48;
const TEXT_W = PAGE_W - MARGIN * 2;

const INK = { r: 0.18, g: 0.22, b: 0.28 };
const MUTED = { r: 0.44, g: 0.50, b: 0.59 };
const LINE_GRAY = { r: 0.89, g: 0.91, b: 0.94 };

interface Line {
  text: string;
  size: number;
  bold: boolean;
  color?: typeof INK;
  gapBefore?: number;
}

function verdictTheme(prediction: string): { label: string; color: RGB } {
  switch (String(prediction).toLowerCase()) {
    case 'phishing': return { label: 'PHISHING', color: { r: 0.90, g: 0.24, b: 0.24 } };
    case 'suspicious': return { label: 'SUSPICIOUS', color: { r: 0.85, g: 0.55, b: 0.12 } };
    default: return { label: 'SAFE', color: { r: 0.13, g: 0.62, b: 0.59 } };
  }
}

interface RGB { r: number; g: number; b: number }

/** Rough Helvetica advance-width factor per char at 1pt (good enough to wrap). */
const AVG_CHAR = 0.52;

function wrap(text: string, size: number, maxWidthPt: number): string[] {
  const maxChars = Math.max(8, Math.floor(maxWidthPt / (size * AVG_CHAR)));
  const words = text.split(/\s+/).filter(Boolean);
  const out: string[] = [];
  let current = '';
  for (const word of words) {
    let w = word;
    // Hard-break absurdly long tokens (URLs) at the char limit
    while (w.length > maxChars) {
      if (current) { out.push(current); current = ''; }
      out.push(w.slice(0, maxChars));
      w = w.slice(maxChars);
    }
    if (!current) {
      current = w;
    } else if ((current + ' ' + w).length <= maxChars) {
      current += ' ' + w;
    } else {
      out.push(current);
      current = w;
    }
  }
  if (current) out.push(current);
  return out.length > 0 ? out : [''];
}

function layoutReport(result: ScanResult): Line[][] {
  const theme = verdictTheme(result.prediction);
  const score = Math.round(Number(result.risk_score ?? 0));
  const confidence = Math.round(Number(result.confidence ?? 0) * 100);

  const reasons = Array.isArray(result.reasons) ? result.reasons.filter(Boolean) : [];
  const tips = Array.isArray(result.security_tips) ? result.security_tips.filter(Boolean) : [];
  const summary = typeof result.summary === 'string' ? result.summary.trim() : '';
  const subjectLabel =
    /^(📧|📱)/.test(result.url || '') ? 'Analyzed Message'
    : result.url ? 'Analyzed URL' : 'Subject';

  const metaRows: Array<[string, string]> = [
    [subjectLabel, result.url || '-'],
    ['Verdict', theme.label],
    ['Risk Score', `${score} / 100`],
    ['Confidence', `${confidence}%`],
    ['Analyzed At', formatWhen(result.analyzed_at)],
  ];

  // ---- page 1 header ----
  const page: Line[] = [];
  page.push({ text: 'PhishGuard AI', size: 22, bold: true, gapBefore: 14 });
  page.push({ text: 'Scan Report', size: 13, bold: false, color: MUTED });
  page.push({ text: `Verdict: ${theme.label}`, size: 16, bold: true, color: theme.color, gapBefore: 18 });

  for (const [key, value] of metaRows) {
    const indent = key === subjectLabel ? 0 : 110;
    for (const [i, piece] of wrap(value, 10, TEXT_W - indent).entries()) {
      page.push({
        text: i === 0 && key !== subjectLabel ? `${padKey(key)}${piece}` : `           ${piece}`,
        size: 10,
        bold: false,
        color: key === 'Verdict' && i === 0 ? theme.color : INK,
        gapBefore: i === 0 ? 6 : 1,
      });
    }
  }

  const section = (title: string, items: string[]) => {
    const body = items.length > 0 ? items : ['-'];
    page.push({ text: title.toUpperCase(), size: 11, bold: true, color: MUTED, gapBefore: 16 });
    for (const item of body) {
      for (const [i, piece] of wrap(item, 10, TEXT_W - 14).entries()) {
        page.push({ text: `${i === 0 ? '• ' : '  '}${piece}`, size: 10, bold: false, color: INK, gapBefore: i === 0 ? 4 : 2 });
      }
    }
  };

  section('Summary', summary ? [summary] : []);
  section('Risk Factors', reasons);
  section('Security Tips', tips);

  // Footer note appended to the last page's line list via marker handled below
  page.push({ text: '', size: 9, bold: false, gapBefore: 20 });
  page.push({
    text: `Generated locally by PhishGuard AI v${extensionVersion()} - this analysis never left your device.`,
    size: 9,
    bold: false,
    color: MUTED,
  });

  // Split into pages on demand (simple greedy fill)
  const pages: Line[][] = [];
  let currentPage: Line[] = [];
  let yCursor = MARGIN;
  for (const line of page) {
    const lead = line.size * 1.45;
    const need = (line.gapBefore ?? 0) + lead;
    if (yCursor + need > PAGE_H - MARGIN && currentPage.length > 0) {
      pages.push(currentPage);
      currentPage = [];
      yCursor = MARGIN;
    }
    currentPage.push(line);
    yCursor += need;
  }
  if (currentPage.length > 0) pages.push(currentPage);
  return pages.length > 0 ? pages : [[]];
}

function padKey(key: string): string {
  return key.padEnd(12, ' ');
}

/** Live manifest version; safe fallback outside the extension runtime. */
function extensionVersion(): string {
  try {
    return chrome.runtime.getManifest().version;
  } catch {
    return '3.2';
  }
}

function formatWhen(iso: string | undefined): string {
  if (!iso) return '-';
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? String(iso) : d.toLocaleString('en-GB', { hour12: false });
}

// ============================================================================
// PDF WRITER
// ============================================================================

function pdfEscape(text: string): string {
  // Transliterate pretty punctuation to WinAnsi-safe equivalents
  const mapped = text
    .replace(/[•▪‣]/g, '-')
    .replace(/[–—]/g, '-')
    .replace(/[''`]/g, "'")
    .replace(/[""]/g, '"')
    .replace(/…/g, '...');
  // Drop anything outside Latin-1 (emoji etc.), escape PDF specials
  const latin1 = mapped.replace(/[^\x20-\x7E\xA0-\xFF]/g, '');
  return latin1.replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)');
}

function rgb(color: RGB | undefined): string {
  const c = color ?? INK;
  return `${c.r.toFixed(3)} ${c.g.toFixed(3)} ${c.b.toFixed(3)} rg`;
}

function contentStreamFor(pages: Line[][]): string[] {
  return pages.map((lines) => {
    const parts: string[] = [];
    let y = PAGE_H - MARGIN;
    for (const line of lines) {
      y -= (line.gapBefore ?? 0) + line.size * 1.15;
      if (line.text.trim().length === 0) continue;
      const font = line.bold ? '/F2' : '/F1';
      parts.push(
        'BT',
        `${font} ${line.size} Tf`,
        rgb(line.color),
        `1 0 0 1 ${MARGIN} ${y.toFixed(2)} Tm`,
        `(${pdfEscape(line.text)}) Tj`,
        'ET'
      );
    }
    // subtle divider under the title area of every first page
    parts.push(
      rgb(LINE_GRAY),
      `${MARGIN} ${PAGE_H - MARGIN - 34} ${TEXT_W} 0.8 re f`
    );
    return parts.join('\n');
  });
}

function assemblePdf(pagesOfLines: Line[][]): Uint8Array {
  const streams = contentStreamFor(pagesOfLines);
  const pageCount = Math.max(1, streams.length);

  const objects: string[] = [];
  const add = (body: string): number => {
    objects.push(body);
    return objects.length; // 1-based object number
  };

  const fontRegular = add('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>');
  const fontBold = add('<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>');

  // Emit contents + page dicts first so /Kids can use REAL object numbers
  const pageNums: number[] = [];
  for (let i = 0; i < pageCount; i++) {
    const stream = streams[i] ?? 'BT ET';
    const contentsNum = add(`<< /Length ${byteLength(stream)} >>\nstream\n${stream}\nendstream`);
    pageNums.push(
      add(
        `<< /Type /Page /Parent %PAGES% /MediaBox [0 0 ${PAGE_W} ${PAGE_H}] ` +
        `/Resources << /Font << /F1 ${fontRegular} 0 R /F2 ${fontBold} 0 R >> >> /Contents ${contentsNum} 0 R >>`
      )
    );
  }

  const kids = pageNums.map((n) => `${n} 0 R`).join(' ');
  const pagesPlaceholder = objects.length + 1; // number the Pages object is about to get
  for (let i = 0; i < pageNums.length; i++) {
    const target = pageNums[i];
    objects[target - 1] = objects[target - 1].replace('%PAGES%', String(pagesPlaceholder));
  }
  const pagesObjNum = add(`<< /Type /Pages /Kids [${kids}] /Count ${pageCount} >>`);
  if (pagesObjNum !== pagesPlaceholder) throw new Error('PDF layout invariant broken');

  const catalogNum = add(`<< /Type /Catalog /Pages ${pagesObjNum} 0 R >>`);

  let pdf = '%PDF-1.4\n';
  const offsets: number[] = [];
  objects.forEach((body, index) => {
    offsets.push(byteLength(pdf));
    pdf += `${index + 1} 0 obj\n${body}\nendobj\n`;
  });

  const xrefStart = byteLength(pdf);
  pdf += `xref\n0 ${objects.length + 1}\n`;
  pdf += '0000000000 65535 f \n';
  for (const offset of offsets) {
    pdf += `${String(offset).padStart(10, '0')} 00000 n \n`;
  }
  pdf += `trailer\n<< /Size ${objects.length + 1} /Root ${catalogNum} 0 R >>\nstartxref\n${xrefStart}\n%%EOF`;

  return latin1Bytes(pdf);
}

// Byte accounting MUST match latin1Bytes exactly: every char we emit is a
// single Latin-1 byte (pdfEscape guarantees nothing above U+00FF survives).
function byteLength(text: string): number {
  return text.length;
}

function latin1Bytes(text: string): Uint8Array {
  const bytes = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i++) {
    bytes[i] = text.charCodeAt(i) & 0xff;
  }
  return bytes;
}
