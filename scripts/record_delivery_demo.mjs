// Record only this project's real loopback dashboard in an isolated browser.
// The owner credential is read from stdin, never logged or saved to a file.
// This is a limitation/cleanup walkthrough, not a passed protected Finance demo.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {createRequire} from 'node:module';

async function main() {
const args = process.argv.slice(2);
const packageRoot = args[args.indexOf('--playwright-root') + 1];
if (!args.includes('--playwright-root') || !path.isAbsolute(packageRoot || '')) throw new Error('Supply the reviewed local Playwright package root');
const require = createRequire(import.meta.url);
const {chromium} = require(path.join(packageRoot, 'playwright'));
const owner = fs.readFileSync(0, 'utf8').trim();
if (!/^[A-Za-z0-9_-]{32,256}$/.test(owner)) throw new Error('Supply the local owner credential on stdin');
const run = crypto.randomUUID();
const output = path.resolve('var/demo', run);
fs.mkdirSync(output, {recursive:true});
const checkpoints = [];
const mark = step => checkpoints.push({step, observed_at:new Date().toISOString()});
const browserChannel = args.includes('--browser-channel') ? args[args.indexOf('--browser-channel') + 1] : undefined;
if (browserChannel && !['msedge','chrome'].includes(browserChannel)) throw new Error('Unsupported reviewed browser channel');
const browser = await chromium.launch({headless:true,...(browserChannel?{channel:browserChannel}:{})});
const browserVersion = browser.version();
const context = await browser.newContext({viewport:{width:1440,height:1000}, recordVideo:{dir:output,size:{width:1440,height:1000}}});
await context.route('**/*', route => {
  const url = new URL(route.request().url());
  return url.protocol === 'http:' && url.hostname === '127.0.0.1' && url.port === '8000' ? route.continue() : route.abort();
});
const page = await context.newPage();
page.setDefaultTimeout(90000);
let task;
let created = false;
let cleanup;
const checks = {};
try {
  await page.goto('http://127.0.0.1:8000/', {waitUntil:'networkidle'});
  const credential = page.getByLabel('Owner access token');
  if (await credential.getAttribute('type') !== 'password') throw new Error('Credential field must be masked before recording');
  await credential.fill(owner);
  await page.getByRole('button', {name:'Connect workspace',exact:true}).click();
  await page.getByRole('button', {name:'New task',exact:true}).waitFor({state:'visible'});
  mark('connected_to_real_local_application');
  await page.getByRole('button', {name:'New task',exact:true}).click();
  await page.getByRole('button', {name:'Review permissions',exact:true}).click();
  const createdResponse = page.waitForResponse(response => new URL(response.url()).pathname === '/api/v1/tasks' && response.request().method() === 'POST');
  await page.getByTestId('create-task').click();
  const response = await createdResponse;
  if (response.status() !== 201) throw new Error('Actual task approval failed');
  task = (await response.json()).contract.task_id;
  created = true;
  await page.getByTestId('launch-task').waitFor();
  await page.getByTestId('launch-task').click();
  await page.getByTestId('check-admission').waitFor();
  mark('real_capsule_staged_after_source_subscription_witnesses');
  const admissionResponse = page.waitForResponse(response => new URL(response.url()).pathname === `/api/v1/tasks/${task}/admit` && response.request().method() === 'POST');
  await page.getByTestId('check-admission').click();
  const admission = await admissionResponse;
  const hold = await admission.json();
  checks.actual_admission_request_held = admission.ok() && hold.agent_admitted === false && hold.reasons.length > 0;
  // Verify the real server response independently of the visual label. No mocked
  // API, injected coverage, altered DOM or simulated task data is used.
  const api = async suffix => {
    const response = await context.request.get(`http://127.0.0.1:8000/api/v1/tasks/${task}${suffix}`, {headers:{Authorization:`Bearer ${owner}`}});
    if (!response.ok()) throw new Error('Actual demo verification failed');
    return response.json();
  };
  const current = await api('');
  const result = await api('/result');
  checks.real_agent_remains_unadmitted = current.execution.agent_admitted === false;
  checks.no_report_release_claim = result.reports.length === 0;
  checks.actual_evidence_chain_verified = result.integrity_verified === true;
  if (!Object.values(checks).every(Boolean)) throw new Error('Actual hold checks failed');
  mark('mandatory_admission_hold_and_no_report_confirmed');
  await page.getByRole('tab', {name:/Security checks/}).click();
  await page.getByRole('region', {name:'Monitoring posture'}).scrollIntoViewIfNeeded();
  await page.screenshot({path:path.join(output,'monitoring.png')});
  await page.waitForTimeout(2500);
  await page.getByRole('tab', {name:'Activity',exact:true}).click();
  await page.getByLabel('Review note').fill('Delivery remains blocked: complete source coverage, clock semantics and packet/process attribution require verification. This recording shows real staging, the hold and cleanup.');
  await page.getByRole('button', {name:'Save review note',exact:true}).click();
  mark('limitation_recorded_as_revision_review_note');
  await page.getByRole('tab', {name:'Overview',exact:true}).click();
  await page.getByTestId('stop-task').click();
  await page.getByTestId('revise-task').waitFor();
  const final = await api('');
  checks.actual_channel_revoked_after_cleanup = final.execution.channel_revoked === true;
  checks.actual_interrupted_state = final.state === 'interrupted';
  const ended = await context.request.post(`http://127.0.0.1:8000/api/v1/tasks/${task}/terminate`, {headers:{Authorization:`Bearer ${owner}`},data:{}});
  cleanup = await ended.json();
  checks.actual_descendant_exit_verified = ended.ok() && cleanup.descendants_exited === true;
  await page.getByRole('status').scrollIntoViewIfNeeded();
  await page.screenshot({path:path.join(output,'verified-cleanup.png')});
  await page.waitForTimeout(2500);
  mark('actual_descendants_exited_and_channel_revocation_verified');
} finally {
  if (created) {
    try {
      const ended = await context.request.post(`http://127.0.0.1:8000/api/v1/tasks/${task}/terminate`, {headers:{Authorization:`Bearer ${owner}`},data:{}});
      if (!ended.ok()) checks.final_cleanup_request_acknowledged = false;
    } catch { checks.final_cleanup_request_acknowledged = false; }
  }
  const video = page.video();
  await context.close();
  await video.saveAs(path.join(output,'agentguard-delivery-hold.webm'));
  await browser.close();
}
const filename = path.join(output,'agentguard-delivery-hold.webm');
const manifest = {
  observed_at:new Date().toISOString(), mode:'real-dashboard-limitation-and-cleanup-recording',
  run_id:run, task_id:task, checks, passed:Object.values(checks).every(Boolean),
  video_sha256:crypto.createHash('sha256').update(fs.readFileSync(filename)).digest('hex'),
  video_bytes:fs.statSync(filename).size, checkpoints,
  browser_version:browserVersion, recorder_version:require(path.join(packageRoot,'playwright/package.json')).version,
  artifact_reference:`operator-retained-demo:${run}`, delivery_complete:false,
  full_finance_demo:'blocked by mandatory source-coverage gates',
  publication:'Local recording only; no team upload or Git video binary',
};
fs.writeFileSync('docs/linux/demo_recording.json', JSON.stringify(manifest,null,2)+'\n');
console.log(JSON.stringify({passed:manifest.passed,run_id:run,video_bytes:manifest.video_bytes,delivery_complete:false}));
if (!manifest.passed) process.exitCode=1;
}
main().catch(() => {
  // Playwright diagnostics can embed request headers or fill values. Never
  // forward its exception text when the local owner credential is in scope.
  console.error('Local demo recording failed; credentials and raw browser diagnostics were not printed.');
  process.exitCode=1;
});
