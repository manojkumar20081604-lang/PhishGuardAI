/**
 * PhishGuard AI - Competition Demo Mode
 *
 * One click runs a scripted sequence of attack scenarios through the REAL
 * local analysis pipeline and renders each verdict with the normal popup UI.
 * Built for the inter-college live demo: zero typing, deterministic order,
 * works fully offline (URL scans are pure string math - nothing is fetched).
 */

export type DemoExpectation = 'safe' | 'suspicious' | 'phishing';

export interface DemoStep {
  kind: 'url' | 'message';
  /** Short label shown in the progress banner while the step runs. */
  label: string;
  /** Narration cue: what to SAY while this step is on screen. */
  note: string;
  payload: string;
  expect: DemoExpectation;
}

/**
 * The stage script. Order tells a story:
 * baseline trust -> clever look-alike -> obvious phish -> scam by SMS.
 */
export const DEMO_STEPS: readonly DemoStep[] = [
  {
    kind: 'url',
    label: 'Legitimate site (baseline)',
    note: 'Real sites stay green - no false alarms.',
    payload: 'https://www.google.com',
    expect: 'safe',
  },
  {
    kind: 'url',
    label: 'Homoglyph clone - fake Apple',
    note: 'Every letter LOOKS like apple.com - but it is fake. The detector catches the invisible swap.',
    payload: 'http://www.xn--80ak6aa92e.com/',
    expect: 'suspicious',
  },
  {
    kind: 'url',
    label: 'Phishing page on free hosting',
    note: 'A real credential-harvesting kit from a live phishing feed - flagged before you even visit it.',
    payload: 'http://gilded-baklava-b9e48a.netlify.app/',
    expect: 'phishing',
  },
  {
    kind: 'message',
    label: 'OTP / bank-block scam SMS',
    note: 'Scams also arrive as text - urgency, fake OTP, short link: all caught offline.',
    payload:
      'Dear Customer, Your account will be BLOCKED today. Unusual login detected. ' +
      'Verify your identity immediately: http://sbi-secure-verify.xyz/login ' +
      'OTP: 482913 Do not share this code with anyone. - SBI Security Team',
    expect: 'phishing',
  },
];

/** How long each verdict card stays on screen (ms) - narration pacing. */
const STEP_HOLD_MS = 4200;

export interface DemoResultLike {
  prediction: string;
}

export interface DemoControllerDeps {
  /** Analyze one step through the real pipeline AND render its verdict card. */
  runStep(step: DemoStep): Promise<DemoResultLike>;
  /** Show progress banner for step i (0-based). */
  showProgress(index: number, total: number, step: DemoStep): void;
  /** Called when the sequence ends (or is stopped early). */
  finish(ran: number, total: number, caught: number, stopped: boolean): void;
}

export interface DemoController {
  start(): Promise<void>;
  stop(): void;
  get running(): boolean;
}

export function setupDemoController(deps: DemoControllerDeps): DemoController {
  let running = false;
  let abortRequested = false;

  const wait = (ms: number): Promise<void> =>
    new Promise((resolve) => setTimeout(resolve, ms));

  async function start(): Promise<void> {
    if (running) return;
    running = true;
    abortRequested = false;

    let caught = 0;
    let ran = 0;
    const total = DEMO_STEPS.length;

    try {
      for (const [index, step] of DEMO_STEPS.entries()) {
        if (abortRequested) break;
        deps.showProgress(index, total, step);
        const result = await deps.runStep(step);
        ran += 1;
        if (matches(result?.prediction, step.expect)) caught += 1;
        // Hold the verdict card so it can be narrated; allow mid-hold stop.
        const until = Date.now() + STEP_HOLD_MS;
        while (!abortRequested && Date.now() < until) await wait(120);
      }
    } catch (error) {
      console.error('[Demo] Step failed:', error);
    } finally {
      const stopped = abortRequested;
      running = false;
      deps.finish(ran, total, caught, stopped);
    }
  }

  function stop(): void {
    abortRequested = true;
  }

  return { start, stop, get running() { return running; } };
}

function matches(prediction: string | undefined, expect: DemoExpectation): boolean {
  return String(prediction ?? '').toLowerCase() === expect;
}
