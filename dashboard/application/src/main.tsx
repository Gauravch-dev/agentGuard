import React, {useState, useEffect, useCallback, useRef} from 'react';
import {createRoot} from 'react-dom/client';
import './style.css';

type TaskRow = {task_id:string;version:number;state:string};
type Finding = {classification:string;reason_code:string;explanation:string;evidence_references:string[]};
type Execution = {phase:string;reasons:string[];channel_revoked?:boolean;agent_admitted?:boolean};
type Task = {contract:Record<string,unknown>;state:string;binding:Record<string,unknown>|null;readiness:Record<string,unknown>[];execution:Execution;is_current:boolean;current_version:number};
type Result = {business_outcome:string;findings:Finding[];reports:Record<string,unknown>[];integrity_verified:boolean;simulated:boolean};
type Evidence = {sequence:number;identity:string;kind:string;received_at:string;body:Record<string,unknown>};
type Revision = {version:number;state:string};
type Source = {alive:boolean;fresh:boolean;health_age_seconds:number|null;pending:number|null;gaps:number|null;lost:number|null;export_failures:number|null};
type Posture = {historical:boolean;last_sensor_receipt:string|null;coverage:{status:string;windows:number;gaps:Finding[]};observer:{connected:boolean;reasons:string[];sources:Record<string,Source>}};
const descriptions:Record<string,string>={
 approved:'Ready to request a verified launch.',
 waiting_for_admission:'The bootstrap is staged. Agent code is waiting for verified monitoring and admission.',
 running:'The agent is admitted. Monitoring and deadlines remain enforced.',
 containment_unverified:'Broker access is revoked. Process cleanup still needs verification.',
 awaiting_verified_completion:'A report is stored. Process exit and final monitoring still need verification.',
 awaiting_final_coverage:'Process exit is verified and broker access is revoked. Waiting for final monitoring evidence.',
 completed:'The report and process completion have been verified. Review security findings separately.',
 interrupted:'The run was interrupted and process cleanup was verified.',
 failed:'The task did not meet completion requirements. Review readiness and evidence before creating a revision.'
};
const reasonLabels:Record<string,string>={
 REQUIRED_SENSOR_COVERAGE_UNAVAILABLE:'Required monitoring is missing, stale, incomplete, or reports lost events.',
 LIVE_PLATFORM_ADMISSION_REVIEW_PENDING:'The live Linux profile and monitoring still need verification.',
 ADMISSION_REVIEW_REQUIRED:'Use Check admission to perform the trusted live review.',
 LOCAL_MODEL_DISABLED:'The approved local AI model is disabled.',
 SOURCE_EVIDENCE_CONFLICT:'Sensor records contradict earlier evidence. Admission and report release are held for this revision.',
 CONTINUOUS_SENSOR_SUPERVISION_UNAVAILABLE:'Continuous monitoring is not connected for every required sensor.',
 CONTINUOUS_OBSERVER_UNAVAILABLE:'No live observer is connected to this view.',
 OBSERVER_STATUS_UNAVAILABLE:'The observer status could not be verified.',
 CONTINUOUS_OBSERVER_NOT_REGISTERED:'This capsule has no registered continuous observer.',
 CONTINUOUS_OBSERVER_STOPPED:'The continuous observer has stopped.',
 LIVE_PLATFORM_REVIEW_UNAVAILABLE:'Current Linux platform verification could not be completed.',
 APPROVED_MODEL_DIGEST_UNCONFIGURED:'The approved local model has not been configured.',
 APPROVED_MODEL_NOT_LOADED:'The approved local model is not loaded yet.',
 CURRENT_MODEL_DIGEST_MISMATCH:'The installed model does not match the approved version.',
 BOOTSTRAP_OBSERVATION_START_GAP:'Monitoring does not yet cover the bootstrap from birth.',
 FILE_AND_NETWORK_HOOK_SCOPE_PARTIAL:'Some file and network mechanisms are outside the current sensor scope.',
 NETWORK_PROCESS_ATTRIBUTION_UNAVAILABLE:'Packets cannot yet be reliably linked to their originating process.',
 SOURCE_CLOCK_SEMANTICS_UNVERIFIED:'Source timestamp behavior still needs verification.',
 CHANNEL_REVOKED:'This broker connection has been revoked.'
};
const explain=(code:string)=>reasonLabels[code]||code.replaceAll('_',' ');
const count=(value:number|null)=>value===null?'Unknown':value;
function object(value:unknown):Record<string,unknown>{return value&&typeof value==='object'&&!Array.isArray(value)?value as Record<string,unknown>:{}}
function matches(record:Evidence, reference:string){
 const event=object(record.body.event), receipt=object(object(record.body.response).receipt);
 return [record.identity,record.body.capsule_id,record.body.coverage_id,event.evidence_reference,event.event_id,receipt.evidence_reference,receipt.receipt_id].includes(reference);
}

function App(){
 const [token,setToken]=useState(''),[authorized,setAuthorized]=useState(false);
 const [rows,setRows]=useState<TaskRow[]>([]),[selected,setSelected]=useState(''),[version,setVersion]=useState('');
 const [viewNonce,setViewNonce]=useState(0),[inspecting,setInspecting]=useState(false);
 const [task,setTask]=useState<Task|null>(null),[result,setResult]=useState<Result|null>(null);
 const [evidence,setEvidence]=useState<Evidence[]>([]),[notes,setNotes]=useState<Evidence[]>([]),[revisions,setRevisions]=useState<Revision[]>([]);
 const [posture,setPosture]=useState<Posture|null>(null),[platform,setPlatform]=useState<Record<string,unknown>|null>(null);
 const [error,setError]=useState(''),[busy,setBusy]=useState(false),[launching,setLaunching]=useState(false),[filter,setFilter]=useState('all'),[reference,setReference]=useState(''),[note,setNote]=useState('');
 const epoch=useRef(0);
 const request=useCallback(async(path:string,method='GET',body?:unknown)=>{
  const response=await fetch(path,{method,headers:{Authorization:`Bearer ${token}`,...(body?{'Content-Type':'application/json'}:{})},body:body?JSON.stringify(body):undefined});
  const data=await response.json();
  if(!response.ok)throw new Error(data.detail||`Request failed (${response.status})`);
  return data;
 },[token]);
 const load=useCallback(async(id:string,revision:string,active:()=>boolean=()=>true)=>{
  const started=epoch.current;
  const [t,history]=await Promise.all([request(`/api/v1/tasks/${id}${revision?`?version=${revision}`:''}`),request(`/api/v1/tasks/${id}/revisions`)]);
  const query=`?version=${t.contract.contract_version}`;
  const [r,e,p,n]=await Promise.all([request(`/api/v1/tasks/${id}/result${query}`),request(`/api/v1/tasks/${id}/events${query}&limit=150`),request(`/api/v1/tasks/${id}/posture${query}`),request(`/api/v1/tasks/${id}/notes${query}`)]);
  if(!active()||started!==epoch.current)return;
  setTask(t);setResult(r);setEvidence(e);setPosture(p);setNotes(n);setRevisions(history);
  setRows(current=>current.map(row=>row.task_id===id?{...row,state:history[0].state,version:t.current_version}:row));
 },[request]);
 async function action(work:()=>Promise<void>){setError('');setBusy(true);try{await work()}catch(e){setError(e instanceof Error?e.message:'Request failed')}finally{setBusy(false)}}
 function select(id:string,revision=''){
  epoch.current++;setViewNonce(value=>value+1);setInspecting(false);setSelected(id);setVersion(revision);setTask(null);setResult(null);setPosture(null);setEvidence([]);setNotes([]);setNote('');setReference('');setFilter('all');
 }
 async function refresh(){
  const started=epoch.current;
  const [data,p]=await Promise.all([request('/api/v1/tasks'),request('/api/v1/platform')]);
  if(started!==epoch.current)return;
  setRows(data);setPlatform(p);setAuthorized(true);
  if(selected)await load(selected,version);
 }
 useEffect(()=>{
  if(!selected||!authorized)return;
  let active=true;
  void load(selected,version,()=>active).catch(e=>{if(active)setError(e instanceof Error?e.message:'Request failed')});
  return()=>{active=false};
 },[selected,version,viewNonce,authorized,load]);
 useEffect(()=>{
  if(!authorized||!selected||!task?.is_current||!['launch_requested','running'].includes(task.state)||busy||inspecting||reference||note)return;
  let active=true;
  let timer:ReturnType<typeof setTimeout>;
  async function poll(){
   try{await load(selected,version,()=>active)}catch(e){if(active)setError(e instanceof Error?e.message:'Refresh failed')}
   if(active)timer=setTimeout(()=>void poll(),5000);
  }
  timer=setTimeout(()=>void poll(),5000);
  return()=>{active=false;clearTimeout(timer)};
 },[authorized,selected,version,viewNonce,task?.state,task?.is_current,busy,inspecting,reference,note,load]);
 const view=evidence.filter(e=>(filter==='all'||e.kind===filter)&&(!reference||matches(e,reference))).slice().reverse();
 const mutable=task?.is_current===true;
 const cleanupVerified=task?.execution.channel_revoked===true&&['interrupted','completed'].includes(task.state);
 const query=task?`?version=${task.contract.contract_version}`:'';
 async function mutate(endpoint:string){try{await request(`/api/v1/tasks/${selected}/${endpoint}`,'POST',{})}finally{await load(selected,version)}}
 return <div className="shell">
  <header><a className="brand" href="/">A<span>G</span><b>AgentGuard<small>2.0 / TASK EVIDENCE</small></b></a><div className="local">LOCAL WORKSPACE <i/> SYNTHETIC DATA</div></header>
  <main><div className="intro"><div><div className="eyebrow">FINANCE CONTROL PLANE</div><h1>Every action.<br/><em>Accounted for.</em></h1><p>Approved tasks, trusted receipts, and independent evidence.<br/>See what completed, what was denied, and what is still unknown.</p></div><div className="boundary"><span>TRUST BOUNDARY</span><strong>Evidence before assurance.</strong><p>Missing, partial, or uncertain monitoring stays visible. Admission requires a trusted live review.</p></div></div>
  <section className="access"><label>Owner access <input aria-label="Owner access token" type="password" disabled={busy} placeholder="Enter local owner token" value={token} onChange={e=>{select('');setToken(e.target.value);setAuthorized(false);setRows([]);setPlatform(null)}} autoComplete="off"/></label><button disabled={busy||!token} onClick={()=>void action(refresh)}>{authorized?'Refresh evidence':'Connect'}</button><small>Token stays in this tab's memory.</small></section>
  {platform&&<details><summary>Platform preflight · protected execution remains gated</summary><pre>{JSON.stringify(platform,null,2)}</pre></details>}
  {error&&<div className="error" role="alert">{error}</div>}
  <div className="workspace"><aside><div className="sectionline"><h2>Tasks</h2><button className="quiet" disabled={!authorized||busy} onClick={()=>void action(async()=>{const t=await request('/api/v1/tasks','POST',{template_id:'finance_summary_v1'});setRows(await request('/api/v1/tasks'));select(t.contract.task_id)})}>+ New</button></div>{!rows.length&&<p className="empty">Connect and create an approved synthetic Finance task.</p>}{rows.map((r,i)=><button disabled={busy} className={`taskrow ${selected===r.task_id?'active':''}`} key={`${r.task_id}:${r.version}`} onClick={()=>select(r.task_id)}><span>FINANCE / {String(rows.length-i).padStart(2,'0')}</span><b>Department summary</b><small>{r.state} · v{r.version}</small></button>)}</aside>
  <article>{!authorized||!task||!result||task.contract.task_id!==selected?<div className="welcome"><span>01 / SELECT A TASK</span><h2>A clear record of the run.</h2><p>Your task contract, business result, and security findings will appear here.</p></div>:<>
  <div className="sectionline"><div><div className="eyebrow">APPROVED FINANCE TASK</div><h2>Department summary</h2><code>{selected}</code></div><label>Revision <select aria-label="Contract revision" disabled={busy} value={version} onChange={e=>select(selected,e.target.value)}><option value="">Current · v{task.current_version}</option>{revisions.map(r=><option key={r.version} value={r.version}>v{r.version} · {r.state}</option>)}</select></label><span className="state">{task.state}</span></div>
  {!mutable&&<div className="execution">Historical revision · execution controls are disabled. Evidence and review notes remain available.</div>}
  {result.simulated&&<div className="error">SIMULATED TEST DATA · No live host evidence</div>}
  <div className="execution" role="status" aria-live="polite"><strong>{launching?'Preparing restricted environment':task.execution.phase.replaceAll('_',' ')}</strong><p>{launching?'Installing required monitoring before startup. This can take up to two minutes. The AI agent has not been admitted.':descriptions[task.execution.phase]||'Review runtime readiness and task evidence.'}</p>{!launching&&task.execution.reasons.map((r,i)=><p key={i}>{explain(r)}</p>)}</div>
  <div className="controls"><button disabled={busy||!mutable||task.state!=='approved'} onClick={()=>void action(async()=>{setLaunching(true);try{await mutate('launch')}finally{setLaunching(false)}})}>{launching?'Preparing environment…':'Request verified launch'}</button>
  {mutable&&task.execution.phase==='waiting_for_admission'&&<button disabled={busy} onClick={()=>void action(()=>mutate('admit'))}>Check admission</button>}
  <button className="quiet" disabled={busy||!mutable||!task.binding||!['launch_requested','running','failed'].includes(task.state)} onClick={()=>void action(()=>mutate('terminate'))}>{cleanupVerified?'Cleanup verified':task.execution.channel_revoked?'Retry cleanup':'Cancel and verify cleanup'}</button>
  {mutable&&['failed','interrupted','completed'].includes(task.state)&&<button className="quiet" disabled={busy} onClick={()=>void action(async()=>{await request(`/api/v1/tasks/${selected}/revisions`,'POST');select(selected);setRows(await request('/api/v1/tasks'))})}>New approved revision</button>}</div>
  <div className="metrics"><div><span>BUSINESS OUTCOME</span><strong>{result.business_outcome}</strong></div><div><span>EVIDENCE INTEGRITY</span><strong>{result.integrity_verified?'Verified chain':'Unverified'}</strong></div><div><span>RUNTIME IDENTITY</span><strong>{task.binding?'Registered':'Not connected'}</strong></div></div>
  <details><summary>Effective permissions & approval</summary><pre>{JSON.stringify(task.contract,null,2)}</pre></details>
  <details><summary>Readiness & runtime mapping</summary><pre>{JSON.stringify({binding:task.binding,readiness:task.readiness},null,2)}</pre></details>
  {posture&&<section aria-label="Monitoring posture"><h3>Monitoring & coverage</h3><p className="muted">{posture.historical?'Historical evidence summary. Live observer state is not used for this revision.':`Last sensor receipt: ${posture.last_sensor_receipt?new Date(posture.last_sensor_receipt).toLocaleString():'None received'}`}</p><p>{posture.coverage.windows} coverage windows · {posture.coverage.gaps.length} required-scope gaps. {posture.coverage.status==='covered_interval'?'Records span the assessed interval; this does not grant admission.':'Complete coverage has not been established.'}</p>
   {Object.entries(posture.observer.sources).length>0&&<div className="source-grid">{Object.entries(posture.observer.sources).map(([kind,s])=><div className="source" key={kind}><strong>{kind}</strong><p>{s.alive&&s.fresh?'Fresh heartbeat':'Unavailable or stale'}</p><dl><dt>Heartbeat age</dt><dd>{s.health_age_seconds===null?'Unknown':`${s.health_age_seconds}s`}</dd><dt>Pending export</dt><dd>{count(s.pending)}</dd><dt>Source gaps</dt><dd>{count(s.gaps)}</dd><dt>Lost events</dt><dd>{count(s.lost)}</dd><dt>Export failures</dt><dd>{count(s.export_failures)}</dd></dl></div>)}</div>}
   {posture.observer.reasons.map(reason=><p className="muted" key={reason}>{explain(reason)}</p>)}
  </section>}
  <section><div className="sectionline"><h3>Security findings</h3><small>{result.findings.length} EVIDENCE ASSESSMENTS</small></div><div className="findings">{result.findings.map((f,i)=><div className={`finding ${f.classification.toLowerCase()}`} key={i}><span className="badge">{f.classification}</span><h4>{f.reason_code.replaceAll('_',' ')}</h4><p>{f.explanation}</p><div className="refs">{f.evidence_references.map(ref=><a key={ref} href="#timeline" onClick={()=>{setFilter('all');setReference(ref)}}>{ref}</a>)}</div></div>)}</div></section>
  <section><h3>Internal business report</h3>{result.reports.length?result.reports.map((r,i)=><pre key={i}>{JSON.stringify(r.report,null,2)}</pre>):<p className="empty">No verified report has been released.</p>}</section>
  <section><h3>Human review notes</h3><p className="muted">Notes annotate this revision. They cannot change permissions, findings, or admission.</p><form onSubmit={e=>{e.preventDefault();void action(async()=>{await request(`/api/v1/tasks/${selected}/notes${query}`,'POST',{text:note});setNote('');setNotes(await request(`/api/v1/tasks/${selected}/notes${query}`))})}}><textarea aria-label="Review note" disabled={busy} maxLength={2000} value={note} onChange={e=>setNote(e.target.value)} placeholder="Record an investigation note"/><button disabled={busy||!note.trim()}>Save review note</button></form>{notes.map(n=><div className="review-note" key={n.sequence}><time>{new Date(n.received_at).toLocaleString()}</time><p>{String(n.body.text)}</p></div>)}</section>
  <section id="timeline"><div className="sectionline"><h3>Evidence timeline</h3><select aria-label="Evidence filter" value={filter} onChange={e=>{setFilter(e.target.value);setReference('')}}><option value="all">All sources</option>{[...new Set(evidence.map(e=>e.kind))].map(k=><option key={k}>{k}</option>)}</select></div><p className="muted">{evidence.length} loaded records · observation and receipt times remain separate.</p>
   {reference&&<div className="execution"><code>{reference}</code><button className="quiet" onClick={()=>setReference('')}>Show all loaded evidence</button>{!view.length&&<p>Reference not in this page. Load earlier evidence to continue.</p>}</div>}
   {view.map(e=><details className="event" id={`evidence-${e.sequence}`} key={e.sequence}><summary><span className="eventkind">{e.kind}</span><time>{new Date(e.received_at).toLocaleTimeString()}</time><code>{e.identity}</code></summary><pre>{JSON.stringify(e.body,null,2)}</pre></details>)}
   <button className="quiet" disabled={busy||evidence.length===0||evidence.length>=2000} onClick={()=>void action(async()=>{setInspecting(true);const earlier=await request(`/api/v1/tasks/${selected}/events${query}&limit=150&before=${evidence[0].sequence}`);setEvidence(current=>[...earlier,...current]);if(!earlier.length)setError('No earlier records for this revision.')})}>Load earlier evidence</button>
   {inspecting&&<button className="quiet" disabled={busy} onClick={()=>void action(async()=>{setInspecting(false);await load(selected,version)})}>Return to latest evidence</button>}
  </section>
  </>}</article></div></main><footer>AgentGuard 2.0<span>Synthetic Finance MVP · Live platform acceptance pending</span></footer>
 </div>
}
createRoot(document.getElementById('root')!).render(<App/>);
