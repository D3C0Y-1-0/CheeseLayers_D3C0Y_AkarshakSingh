// Visualisation consumes server observations. No generated traffic or synthetic verdicts.
let livePrimed=false,liveSeen=new Set(),liveEvents=[],flowGeneration=0,liveRefreshing=false,policyDirty=false;
const requestLabel=o=>o.kind==='login'?'POST /login · '+o.username:o.kind==='document'?'GET /document · '+o.name:(o.method||'HTTP')+' '+(o.path||'/');
function flowEvent(o,replay=false){
  el('flowPeer').textContent=o.peer_ip;el('flowService').textContent=o.sensor==='apache'?'Owned Apache / relay':'District portal :8010';
  el('flowDetection').textContent=o.finding?o.finding.label:o.status===429?'Restriction enforced':'No rule fired';
  el('flowResponse').textContent='HTTP '+o.status;el('flowCaption').textContent=(replay?'RECORDED REPLAY':'NEW OBSERVATION')+' · '+ist(o.at)+' · '+requestLabel(o)+' · '+o.event_id;
  const color=o.status===429?'#f5b544':o.finding?'#ff6b6b':'#77dfcf';
  if(!matchMedia('(prefers-reduced-motion: reduce)').matches){
    const svg=el('trafficSvg'),dot=document.createElementNS('http://www.w3.org/2000/svg','circle');dot.setAttribute('r','6');dot.setAttribute('fill',color);
    const motion=document.createElementNS('http://www.w3.org/2000/svg','animateMotion');motion.setAttribute('dur','1.2s');motion.setAttribute('path','M100 80 L360 80 L620 80 L880 80');dot.append(motion);svg.append(dot);motion.beginElement();setTimeout(()=>dot.remove(),1400);
  }
}
function renderLive(portal,apache){
  const events=[...portal.observations.map(o=>({...o,sensor:'portal'})),...(apache.observations||[]).map(o=>({...o,sensor:'apache',kind:'request',at:o.observed_at,method:o.method||'HTTP',finding:o.rule_id?{rule_id:o.rule_id,label:'Apache traversal attempt',reason:'Signature in independent access log; response alone does not prove disclosure'}:null}))].sort((a,b)=>Date.parse(b.at)-Date.parse(a.at));
  const fresh=events.filter(o=>!liveSeen.has(o.event_id));
  liveEvents=events;for(const o of events)liveSeen.add(o.event_id);if(liveSeen.size>2000)liveSeen=new Set(events.map(o=>o.event_id));
  el('liveCounts').textContent=events.length+' retained observations · '+events.filter(o=>o.finding).length+' rule findings · '+events.filter(o=>o.status===429).length+' restricted responses · '+new Set(events.map(o=>o.peer_ip)).size+' observed peers';
  el('liveConnection').textContent='Updated '+ist(new Date().toISOString())+' · polls every 2s · up to 100 portal + 30 Apache records';
  el('liveFeed').replaceChildren();for(const o of events.slice(0,12)){
    const button=document.createElement('button');button.type='button';button.className='live-event '+(o.status===429?'retry':o.finding?'detected':'ordinary');
    button.textContent=ist(o.at)+' · '+o.peer_ip+' → '+requestLabel(o)+' · HTTP '+o.status+' · '+(o.finding?.label|| (o.status===429?'Blocked retry':'No rule fired'));
    button.onclick=()=>{flowEvent(o,true);if(o.sensor==='portal'){selected=o;show('evidence',o);renderEvidence(o);updateSelected();}else{show('apacheEvidence',o);}};el('liveFeed').append(button);
  }
  if(livePrimed&&fresh.length&&!el('pauseTraffic').checked&&!liveRefreshing){
    const generation=flowGeneration;const sample=fresh.slice(0,20).reverse();
    sample.forEach((o,i)=>setTimeout(()=>{if(generation===flowGeneration&&!el('pauseTraffic').checked)flowEvent(o);},i*65));
    if(fresh.length>20)el('liveConnection').textContent+=' · animation samples latest 20 of '+fresh.length+' new records';
  }
  if(!livePrimed)el('flowCaption').textContent='Waiting for new requests. Existing history is listed below; Replay retained events is explicitly recorded playback.';
  livePrimed=true;
  const policy=portal.response_policy;
  if(!policyDirty){el('autoBlock').checked=!!policy.auto_block;el('renewRetry').checked=!!policy.renew_on_retry;}
  const now=Date.now();el('blockCountdown').textContent=portal.actions.filter(a=>a.kind==='block'&&['applied','verified'].includes(a.state)&&Date.parse(a.expires_at)>now).map(a=>a.peer_ip+': '+Math.ceil((Date.parse(a.expires_at)-now)/1000)+'s remaining · '+(a.renewal_count||0)+' retries observed').join(' | ')||'No active custom-portal restriction';
}
el('pauseTraffic').onchange=()=>{flowGeneration++;el('flowCaption').textContent=el('pauseTraffic').checked?'Animation paused; collection and evidence polling continue.':'Listening for new observations.';};
el('replayTraffic').onclick=()=>{
  if(!liveEvents.length){el('flowCaption').textContent='No retained traffic to replay.';return;}
  el('pauseTraffic').checked=false;const generation=++flowGeneration;liveRefreshing=true;const events=liveEvents.slice(0,20).reverse();
  events.forEach((o,i)=>setTimeout(()=>{if(generation===flowGeneration)flowEvent(o,true);},i*350));
  setTimeout(()=>{liveRefreshing=false;if(generation===flowGeneration)el('flowCaption').textContent='Recorded replay finished. Listening for new observations.';},events.length*350+1400);
};
for(const id of ['autoBlock','renewRetry'])el(id).onchange=()=>{policyDirty=true;};
el('savePolicy').onclick=()=>run(async()=>{await api('/api/lab/policy','PUT',{auto_block:el('autoBlock').checked,renew_on_retry:el('renewRetry').checked,ttl_seconds:300,reason:el('reason').value});policyDirty=false;});
let assistantProposal=null;
el('assistantForm').onsubmit=async e=>{e.preventDefault();assistantProposal=null;el('executeProposal').hidden=true;el('assistantSubmit').disabled=true;show('assistantReply','Reading stored records…');try{const r=await api('/api/lab/assistant','POST',{message:el('assistantQuestion').value});show('assistantReply',r.message);el('assistantLinks').replaceChildren();for(const link of r.links){const a=document.createElement('a');a.href=link.href;a.textContent=link.label;a.style.marginRight='12px';el('assistantLinks').append(a);}if(r.proposal){assistantProposal=r.proposal;show('assistantReply',r.message+'\n'+r.proposal.scope+'\n'+JSON.stringify(r.proposal.body,null,2));el('executeProposal').hidden=false;}}catch(e){show('assistantReply',e.message);}finally{el('assistantSubmit').disabled=false;}};
el('executeProposal').onclick=()=>{const proposal=assistantProposal;if(!proposal)return;assistantProposal=null;el('executeProposal').hidden=true;run(async()=>{const result=await api('/api/lab/actions','POST',proposal.body);show('assistantReply','Action applied, not yet verified.\n'+JSON.stringify(result.action,null,2));});};
