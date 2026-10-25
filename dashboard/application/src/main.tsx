import React, {useState, useEffect, useCallback} from 'react';
import {createRoot} from 'react-dom/client';
import './style.css';

type TaskRow = {task_id:string; version:number; state:string};
type Finding = {classification:string;reason_code:string;explanation:string;evidence_references:string[]};
type Execution = {phase:string;reasons:string[];channel_revoked?:boolean;agent_admitted?:boolean};
type Task = {contract:Record<string,unknown>;state:string;binding:Record<string,unknown>|null;readiness:Record<string,unknown>[];execution:Execution};
type Result = {business_outcome:string;findings:Finding[];reports:Record<string,unknown>[];integrity_verified:boolean;simulated:boolean};
type Evidence = {sequence:number;identity:string;kind:string;received_at:string;body:Record<string,unknown>};
const descriptions:Record<string,string>={
 approved:'Ready to request a verified launch.',
 waiting_for_admission:'The container bootstrap is staged. Agent code is waiting for verified monitoring and admission.',
 running:'The agent is admitted. Monitoring and deadlines remain enforced.',
 containment_unverified:'Broker access is revoked. Process cleanup has not yet been verified; retry cleanup.',
 awaiting_verified_completion:'A report is stored. Process exit and final monitoring still need verification.',
 awaiting_final_coverage:'Process exit is verified and broker access is revoked. Waiting briefly for final monitoring evidence.',
 completed:'The report and process completion have been verified. Review security findings separately.',
 interrupted:'The run was interrupted and process cleanup was verified.',
 failed:'The task did not meet completion requirements. Review readiness and evidence before creating a new revision.'
};
const reasonLabels:Record<string,string>={
 REQUIRED_SENSOR_COVERAGE_UNAVAILABLE:'Required file, process, and network monitoring is missing, stale, or reports lost events.',
 LIVE_PLATFORM_ADMISSION_REVIEW_PENDING:'The live Linux profile and monitoring integration still need platform verification.',
 LOCAL_MODEL_DISABLED:'The approved local AI model is disabled.',
 SOURCE_EVIDENCE_CONFLICT:'Sensor records contradict earlier evidence. Admission and report release are held; review the evidence before starting a new revision.',
 CONTINUOUS_SENSOR_SUPERVISION_UNAVAILABLE:'Continuous monitoring is not yet connected for every required sensor.',
 LIVE_PLATFORM_REVIEW_UNAVAILABLE:'Current Linux platform verification could not be completed.',
 APPROVED_MODEL_DIGEST_UNCONFIGURED:'The approved local model has not been configured.',
 APPROVED_MODEL_NOT_LOADED:'The approved local model is not loaded yet.',
 CURRENT_MODEL_DIGEST_MISMATCH:'The installed local model does not match the approved version.',
 CHANNEL_REVOKED:'This broker connection has been revoked.'
};

function App(){
 const [token,setToken]=useState(''),[authorized,setAuthorized]=useState(false);
 const [rows,setRows]=useState<TaskRow[]>([]),[selected,setSelected]=useState('');
 const [task,setTask]=useState<Task|null>(null),[result,setResult]=useState<Result|null>(null),[evidence,setEvidence]=useState<Evidence[]>([]);
 const [platform,setPlatform]=useState<Record<string,unknown>|null>(null);
 const [error,setError]=useState(''),[busy,setBusy]=useState(false),[filter,setFilter]=useState('all');
 const request=useCallback(async(path:string,method='GET',body?:unknown)=>{
  const response=await fetch(path,{method,headers:{Authorization:`Bearer ${token}`,...(body?{'Content-Type':'application/json'}:{})},body:body?JSON.stringify(body):undefined});
  if(!response.ok){const data=await response.json();throw new Error(data.detail||`Request failed (${response.status})`)}
  return response.json();
 },[token]);
 const load=useCallback(async(id:string,active:()=>boolean=()=>true)=>{
  const [t,r,e]=await Promise.all([request(`/api/v1/tasks/${id}`),request(`/api/v1/tasks/${id}/result`),request(`/api/v1/tasks/${id}/events`)]);
  if(!active())return;
  setTask(t);setResult(r);setEvidence(e);setRows(current=>current.map(row=>row.task_id===id?{...row,state:t.state,version:t.contract.contract_version}:row));
 },[request]);
 async function action(work:()=>Promise<void>){setError('');setBusy(true);try{await work()}catch(e){setError(e instanceof Error?e.message:'Request failed')}finally{setBusy(false)}}
 async function refresh(){const data=await request('/api/v1/tasks');setPlatform(await request('/api/v1/platform'));setRows(data);setAuthorized(true);if(selected)await load(selected)}
 useEffect(()=>{if(!selected)return;setTask(null);setResult(null);setEvidence([]);void action(()=>load(selected));},[selected,load]);
 useEffect(()=>{
  if(!authorized||!selected||!task||!['launch_requested','running'].includes(task.state)||busy)return;
  let cancelled=false;
  const timer=setInterval(()=>{void load(selected,()=>!cancelled).catch(e=>{if(!cancelled)setError(e instanceof Error?e.message:'Refresh failed')})},5000);
  return()=>{cancelled=true;clearInterval(timer)};
 },[authorized,selected,task?.state,busy,load]);
 const view=evidence.filter(e=>filter==='all'||e.kind===filter).slice(-150).reverse();
 return <div className="shell">
  <header><a className="brand" href="/">A<span>G</span><b>AgentGuard<small>2.0 / TASK EVIDENCE</small></b></a><div className="local">LOCAL WORKSPACE <i/> SYNTHETIC DATA</div></header>
  <main><div className="intro"><div><div className="eyebrow">FINANCE CONTROL PLANE</div><h1>Every action.<br/><em>Accounted for.</em></h1><p>Approved tasks, trusted receipts, and independent evidence.<br/>See what completed, what was denied, and what is still unknown.</p></div><div className="boundary"><span>TRUST BOUNDARY</span><strong>Evidence before assurance.</strong><p>Linux isolation requires Member 2's verified runtime. Missing sensors remain visible as Unverified findings.</p></div></div>
  <section className="access"><label>Owner access <input aria-label="Owner access token" type="password" placeholder="Enter local owner token" value={token} onChange={e=>{setToken(e.target.value);setAuthorized(false);setTask(null);setResult(null);setEvidence([]);setRows([]);setPlatform(null)}} autoComplete="off"/></label><button disabled={busy||!token} onClick={()=>void action(refresh)}>{authorized?'Refresh evidence':'Connect'}</button><small>Token stays in this tab's memory.</small></section>
  {platform&&<details><summary>Member 2 platform preflight · protected execution remains gated</summary><pre>{JSON.stringify(platform,null,2)}</pre></details>}
  {error&&<div className="error" role="alert">{error}</div>}
  <div className="workspace"><aside><div className="sectionline"><h2>Tasks</h2><button className="quiet" disabled={!authorized||busy} onClick={()=>void action(async()=>{const t=await request('/api/v1/tasks','POST',{template_id:'finance_summary_v1'});setSelected(t.contract.task_id);await refresh()})}>+ New</button></div>{!rows.length&&<p className="empty">Connect and create an approved synthetic Finance task.</p>}{rows.map((r,i)=><button className={`taskrow ${selected===r.task_id?'active':''}`} key={`${r.task_id}:${r.version}`} onClick={()=>setSelected(r.task_id)}><span>FINANCE / {String(rows.length-i).padStart(2,'0')}</span><b>Department summary</b><small>{r.state} · v{r.version}</small></button>)}</aside>
  <article>{!authorized||!task||!result||task.contract.task_id!==selected?<div className="welcome"><span>01 / SELECT A TASK</span><h2>A clear record of the run.</h2><p>Your task contract, business result, and security findings will appear here.</p></div>:<>
  <div className="sectionline"><div><div className="eyebrow">APPROVED FINANCE TASK</div><h2>Department summary</h2><code>{selected}</code></div><span className="state">{task.state}</span></div>
  {result.simulated&&<div className="error">SIMULATED TEST DATA · No live host evidence</div>}
  <div className="execution" role="status"><strong>{task.execution.phase.replaceAll('_',' ')}</strong><p>{descriptions[task.execution.phase]||'Review runtime readiness and task evidence.'}</p>{task.execution.reasons.map((r,i)=><p key={i}>{reasonLabels[r]||r}</p>)}</div>
  <div className="controls"><button disabled={busy||task.state!=='approved'} onClick={()=>void action(async()=>{try{await request(`/api/v1/tasks/${selected}/launch`,'POST')}finally{await load(selected)}})}>Request verified launch</button>
  {task.execution.phase==='waiting_for_admission'&&<button disabled={busy} onClick={()=>void action(async()=>{try{await request(`/api/v1/tasks/${selected}/admit`,'POST',{})}finally{await load(selected)}})}>Check admission</button>}
  <button className="quiet" disabled={busy||!task.binding||!['launch_requested','running','failed'].includes(task.state)} onClick={()=>void action(async()=>{try{await request(`/api/v1/tasks/${selected}/terminate`,'POST')}finally{await load(selected)}})}>{task.execution.channel_revoked?'Retry cleanup':'Cancel and verify cleanup'}</button>
  {['failed','interrupted','completed'].includes(task.state)&&<button className="quiet" disabled={busy} onClick={()=>void action(async()=>{await request(`/api/v1/tasks/${selected}/revisions`,'POST');await refresh()})}>New approved revision</button>}</div>
  <div className="metrics"><div><span>BUSINESS OUTCOME</span><strong>{result.business_outcome}</strong></div><div><span>EVIDENCE INTEGRITY</span><strong>{result.integrity_verified?'Verified chain':'Unverified'}</strong></div><div><span>RUNTIME IDENTITY</span><strong>{task.binding?'Registered':'Not connected'}</strong></div></div>
  <details><summary>Effective permissions & approval</summary><pre>{JSON.stringify(task.contract,null,2)}</pre></details>
  <details><summary>Readiness & runtime mapping</summary><pre>{JSON.stringify({binding:task.binding,readiness:task.readiness},null,2)}</pre></details>
  <section><div className="sectionline"><h3>Security findings</h3><small>{result.findings.length} EVIDENCE ASSESSMENTS</small></div><div className="findings">{result.findings.map((f,i)=><div className={`finding ${f.classification.toLowerCase()}`} key={i}><span className="badge">{f.classification}</span><h4>{f.reason_code.replaceAll('_',' ')}</h4><p>{f.explanation}</p><div className="refs">{f.evidence_references.map(ref=><a key={ref} href="#timeline" onClick={()=>setFilter('all')}>{ref}</a>)}</div></div>)}</div></section>
  <section><h3>Internal business report</h3>{result.reports.length?result.reports.map((r,i)=><pre key={i}>{JSON.stringify(r.report,null,2)}</pre>):<p className="empty">No verified report has been released.</p>}</section>
  <section id="timeline"><div className="sectionline"><h3>Evidence timeline</h3><select aria-label="Evidence filter" value={filter} onChange={e=>setFilter(e.target.value)}><option value="all">All sources</option>{[...new Set(evidence.map(e=>e.kind))].map(k=><option key={k}>{k}</option>)}</select></div><p className="muted">Latest 150 records · observation and receipt times remain separate.</p>{view.map(e=><details className="event" key={e.sequence}><summary><span className="eventkind">{e.kind}</span><time>{new Date(e.received_at).toLocaleTimeString()}</time><code>{e.identity}</code></summary><pre>{JSON.stringify(e.body,null,2)}</pre></details>)}</section>
  </>}</article></div></main><footer>AgentGuard 2.0<span>Application prototype · Live platform validation pending</span></footer>
 </div>
}
createRoot(document.getElementById('root')!).render(<App/>);
