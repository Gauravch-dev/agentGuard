import React, {useEffect, useRef} from 'react';

export function Icon({name, size=20}:{name:string;size?:number}) {
 const paths:Record<string,React.ReactNode>={
  shield:<><path d="M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6l-8-3Z"/><path d="m8 12 3 3 5-6"/></>,
  grid:<><rect x="3" y="3" width="7" height="7" rx="2"/><rect x="14" y="3" width="7" height="7" rx="2"/><rect x="3" y="14" width="7" height="7" rx="2"/><rect x="14" y="14" width="7" height="7" rx="2"/></>,
  plus:<path d="M12 5v14M5 12h14"/>,
  arrow:<path d="M5 12h14m-6-6 6 6-6 6"/>,
  check:<path d="m5 12 4 4L19 6"/>,
  clock:<><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></>,
  activity:<path d="M2 12h5l3-8 4 16 3-8h5"/>,
  file:<><path d="M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9l-6-6Z"/><path d="M14 3v6h6M8 13h8M8 17h5"/></>,
  lock:<><rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3M12 14v3"/></>,
  globe:<><circle cx="12" cy="12" r="9"/><ellipse cx="12" cy="12" rx="4" ry="9"/><path d="M3 12h18"/></>,
  help:<><circle cx="12" cy="12" r="9"/><path d="M9 8a3 3 0 0 1 6 1c0 2-3 2-3 5M12 17h.01"/></>,
  refresh:<><path d="M20 7v5h-5M4 17v-5h5"/><path d="M6 7a7 7 0 0 1 12-1l2 6M4 12l2 6a7 7 0 0 0 12-1"/></>,
  close:<path d="m6 6 12 12M6 18 18 6"/>,
  alert:<><path d="m12 3 10 18H2L12 3Z"/><path d="M12 9v5M12 17h.01"/></>,
  search:<><circle cx="10.5" cy="10.5" r="6.5"/><path d="m16 16 5 5"/></>,
  stop:<rect x="5" y="5" width="14" height="14" rx="3"/>,
  chat:<path d="M21 11a8 8 0 0 1-8 8H7l-5 3V11a9 9 0 0 1 19 0Z"/>,
 };
 return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{paths[name]||paths.file}</svg>;
}

export function Modal({title,children,onClose,busy=false}:{title:string;children:React.ReactNode;onClose:()=>void;busy?:boolean}){
 const ref=useRef<HTMLDialogElement>(null);
 useEffect(()=>{const dialog=ref.current;dialog?.showModal();return()=>{dialog?.close()}},[]);
 return <dialog ref={ref} className="modal" aria-label={title} onCancel={e=>{e.preventDefault();if(!busy)onClose()}}><div className="modal-heading"><h2>{title}</h2><button className="icon-button" aria-label="Close dialog" disabled={busy} onClick={onClose}><Icon name="close"/></button></div>{children}</dialog>;
}

export function Raw({title='Technical details',value}:{title?:string;value:unknown}){
 return <details className="raw"><summary>{title}</summary><pre>{JSON.stringify(value,null,2)}</pre></details>;
}

export const stateLabel:Record<string,string>={approved:'Ready to start',launch_requested:'Safety checks',running:'Running',completed:'Completed',interrupted:'Stopped',failed:'Needs review'};
export const phaseCopy:Record<string,{title:string;description:string;icon:string;tone:string}>={
 approved:{title:'Ready when you are.',description:'Start by preparing an isolated environment. The AI can begin only after the required safety checks pass.',icon:'arrow',tone:'ready'},
 waiting_for_admission:{title:'Waiting for safety checks',description:'The isolated environment is ready. The AI has not started because monitoring still needs verification.',icon:'shield',tone:'waiting'},
 running:{title:'Your agent is working',description:'The AI is admitted for this task. Monitoring, permissions and execution limits remain enforced.',icon:'activity',tone:'working'},
 containment_unverified:{title:'Cleanup needs attention',description:'Data access has been revoked. We still need to verify that every process has stopped.',icon:'alert',tone:'warning'},
 awaiting_verified_completion:{title:'Checking the final result',description:'A report is stored. Process completion and monitoring evidence still need verification.',icon:'clock',tone:'waiting'},
 awaiting_final_coverage:{title:'Waiting for final evidence',description:'The processes have stopped and access is revoked. Final monitoring evidence is still needed.',icon:'clock',tone:'waiting'},
 completed:{title:'Task completed',description:'The report and process completion are verified. Review the security findings separately.',icon:'check',tone:'complete'},
 interrupted:{title:'This run was stopped',description:'The run ended and process cleanup was verified. You can create a fresh approved run to try again.',icon:'stop',tone:'stopped'},
 failed:{title:'This run needs a review',description:'The task did not meet completion requirements. Review the activity and cleanup status before trying again.',icon:'alert',tone:'warning'},
};
