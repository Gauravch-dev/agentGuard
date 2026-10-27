import React, {useState, useEffect, useCallback, useRef} from 'react';
import {createRoot} from 'react-dom/client';
import {Workspace} from './Workspace';
import type {TaskRow,Task,Result,Evidence,Revision,Posture} from './types';
import './design.css';

const reasonLabels:Record<string,string>={
 REQUIRED_SENSOR_COVERAGE_UNAVAILABLE:'Required monitoring is missing, stale, incomplete, or reports lost events.',
 LIVE_PLATFORM_ADMISSION_REVIEW_PENDING:'The live Linux profile and monitoring still need verification.',
 ADMISSION_REVIEW_REQUIRED:'Choose Check readiness to run the latest safety review.',
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

const DEFAULT_DEMO_TOKEN = 'agentguard_owner_token_32chars_min_secret!';

function App(){
 const [token,setToken]=useState(DEFAULT_DEMO_TOKEN),[authorized,setAuthorized]=useState(false);
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
  else if(data.length)select((data.find((row:TaskRow)=>row.state==='approved')||data[0]).task_id);
 }
 useEffect(()=>{
  void refresh().catch(()=>{});
 },[]);
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
 const query=task?`?version=${task.contract.contract_version}`:'';
 async function mutate(endpoint:string){try{await request(`/api/v1/tasks/${selected}/${endpoint}`,'POST',{})}finally{await load(selected,version)}}
 async function create(){let success=false;await action(async()=>{const created=await request('/api/v1/tasks','POST',{template_id:'finance_summary_v1'});setRows(await request('/api/v1/tasks'));select(created.contract.task_id);success=true});return success}
 return <Workspace token={token} authorized={authorized} rows={rows} selected={selected} version={version} task={task} result={result} evidence={evidence} notes={notes} revisions={revisions} posture={posture} platform={platform} error={error} busy={busy} launching={launching} filter={filter} reference={reference} note={note} inspecting={inspecting} explain={explain}
  onToken={value=>{select('');setToken(value);setAuthorized(false);setRows([]);setPlatform(null)}}
  onConnect={()=>void action(refresh)} onSelect={select} onRefresh={()=>void action(refresh)} onNew={create}
  onLaunch={()=>void action(async()=>{setLaunching(true);try{await mutate('launch')}finally{setLaunching(false)}})}
  onAdmit={()=>void action(()=>mutate('admit'))} onStop={()=>void action(()=>mutate('terminate'))}
  onRevise={()=>void action(async()=>{await request(`/api/v1/tasks/${selected}/revisions`,'POST');select(selected);setRows(await request('/api/v1/tasks'))})}
  onFilter={value=>{setFilter(value);setReference('')}} onReference={setReference} onNote={setNote}
  onSaveNote={()=>void action(async()=>{await request(`/api/v1/tasks/${selected}/notes${query}`,'POST',{text:note});setNote('');setNotes(await request(`/api/v1/tasks/${selected}/notes${query}`))})}
  onEarlier={()=>void action(async()=>{setInspecting(true);const earlier=await request(`/api/v1/tasks/${selected}/events${query}&limit=150&before=${evidence[0].sequence}`);setEvidence(current=>[...earlier,...current]);if(!earlier.length)setError('No earlier activity for this run.')})}
  onLatest={()=>void action(async()=>{setInspecting(false);await load(selected,version)})}/>;
}
createRoot(document.getElementById('root')!).render(<App/>);
