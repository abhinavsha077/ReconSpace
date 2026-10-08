/* Guided review state stays in this tab's memory; exports are plans, never execution. */
const CareFlow=(()=>{
  const modules={
    cleanup:{title:'Cleanup',action:'Review storage candidates',groups:[['safe','Lower-risk review','findings'],['manual','Manual review','findings'],['protected','Protected & intentional','findings']]},
    protection:{title:'Protection',action:'Review protection evidence',groups:[['trust','Signature evidence','binary_trust'],['startup','Startup indicators','startup'],['permissions','Permissions','permissions']]},
    performance:{title:'Performance',action:'Review system activity',groups:[['processes','Running processes','processes'],['startup','Startup entries','startup'],['services','Services','services']]},
    applications:{title:'Applications',action:'Manage application review',groups:[['apps','Installed applications','applications'],['ownership','Related footprints','application_footprints']]},
    clutter:{title:'My Clutter',action:'Review my files',groups:[['duplicates','Duplicate groups','duplicates'],['files','Large files','top_files'],['folders','Folders','top_directories']]}
  };
  const selected=new Map(), remembered=new Map();
  let activeModule='cleanup',category='safe',query='',offset=0,inspected=0,reportIdentity=null,pendingReview=null,scanDestination='home',priorReport=null,receipt=null;
  function rows(module,id){
    const group=modules[module]?.groups.find(group=>group[0]===id);if(!group)return[];
    const source=Array.isArray(REPORT?.[group[2]])?REPORT[group[2]]:[];
    return source.map((item,index)=>({item,index,key:module+':'+id+':'+index,module,category:id})).filter(row=>{
      if(!row.item||typeof row.item!=='object'||Array.isArray(row.item))return false;
      if(module!=='cleanup')return true;
      const disposition=row.item.disposition;
      return id==='safe'?disposition==='probably_safe_cleanup':id==='manual'?disposition==='manual_review':!['probably_safe_cleanup','manual_review'].includes(disposition);
    });
  }
  const title=row=>String(row.item.title||row.item.name||row.item.display_name||row.item.task_name||(Array.isArray(row.item.paths)&&row.item.paths.length?String(row.item.paths[0]).split(/[\\/]/).at(-1)+' · '+row.item.paths.length+' paths':null)||row.item.path||row.item.sha256||'Evidence item');
  const path=row=>String(row.item.path||row.item.install_location||row.item.executable_path||row.item.path_name||row.item.command||(Array.isArray(row.item.paths)?row.item.paths.join(' · '):''));
  const estimate=row=>Math.max(0,Number(row.item.estimated_reclaimable_bytes||row.item.reclaimable_bytes||row.item.wasted_bytes||row.item.size_bytes||row.item.estimated_size_bytes||row.item.installed_size_bytes||0));
  const selectable=row=>!(row.module==='cleanup'&&row.category==='protected');
  function syncReport(){if(REPORT&&reportIdentity!==REPORT){reportIdentity=REPORT;selected.clear();remembered.clear();receipt=null;}}
  function navigation(stage){
    document.body.dataset.flowStage=stage;
    const bar=document.querySelector('#flowNavigation');
    if(!modules[currentPage]||!REPORT){bar.classList.add('hidden');return;}
    bar.classList.remove('hidden');
    bar.innerHTML=`<button class="secondary" onclick="CareFlow.back()">← ${stage==='overview'?'Audit overview':modules[currentPage].title+' summary'}</button><span class="flow-crumb">${esc(modules[currentPage].title)}${stage==='review'?' / Review':stage==='raw'?' / Advanced evidence':stage==='receipt'?' / Plan prepared':''}</span><button class="secondary" onclick="CareFlow.setup('${currentPage}')">Start over</button>`;
  }
  function overview(module){
    activeModule=module;navigation('overview');
    const definition=modules[module],groups=definition.groups;
    document.querySelector('#flowContent').innerHTML=`<section class="flow-overview"><div class="flow-illustration" data-parallax><div class="parallax-object">${careArtwork(module)}</div></div><div class="flow-overview-copy"><span class="smart-eyebrow">Your audit, made useful</span><h2>${esc(definition.title)}. A closer look.</h2><p>Review the evidence in focused groups. Choose what belongs in your review plan. Nothing is removed or changed.</p><div class="flow-group-cards">${groups.map(([id,label])=>`<button class="flow-group-card" onclick="CareFlow.review('${id}')"><b>${rows(module,id).length.toLocaleString()}</b><span>${esc(label)}</span><small>Review →</small></button>`).join('')}</div><div class="flow-primary"><button onclick="CareFlow.review('${groups[0][0]}')">${esc(definition.action)} →</button><button class="secondary" onclick="CareFlow.advanced()">Advanced evidence</button></div><p class="small">${esc(REPORT.profile||'Imported')} audit · ${esc(REPORT.stats?.root||'root not recorded')} · counts are retained evidence, not a PC health score.</p></div></section>`;
    document.querySelector('#flowContent').classList.remove('hidden');
  }
  function enterPage(module){
    syncReport();
    const content=document.querySelector('#flowContent');content.classList.add('hidden');
    if(!REPORT||!modules[module]){document.body.dataset.flowStage='raw';document.querySelector('#flowNavigation').classList.add('hidden');return false;}
    activeModule=module;
    if(pendingReview===module){pendingReview=null;review(remembered.get(module)?.category||modules[module].groups[0][0]);}else overview(module);
    return true;
  }
  function openModule(module,direct=false){if(direct)pendingReview=module;navigatePage(module);}
  function review(id){
    const previous=remembered.get(activeModule);
    category=modules[activeModule].groups.some(group=>group[0]===id)?id:modules[activeModule].groups[0][0];
    query=previous?.category===category?previous.query:'';offset=0;inspected=0;
    renderReview();
    CareMotion.animate(document.querySelector('.flow-manager'),[{opacity:0,transform:'translateY(8px)'},{opacity:1,transform:'none'}],{duration:260,easing:'ease-out'});
  }
  function filtered(){return rows(activeModule,category).filter(row=>(title(row)+' '+path(row)).toLowerCase().includes(query.toLowerCase()));}
  function renderReview(focusSearch=false){
    navigation('review');remembered.set(activeModule,{category,query});
    const definition=modules[activeModule],all=filtered();offset=Math.min(offset,Math.max(0,Math.floor((all.length-1)/60)*60));
    const visible=all.slice(offset,offset+60);inspected=Math.min(inspected,Math.max(0,visible.length-1));
    document.querySelector('#flowContent').classList.remove('hidden');
    document.querySelector('#flowContent').innerHTML=`<section class="flow-manager"><aside class="flow-categories" aria-label="Review categories"><h3>${esc(definition.title)}</h3>${definition.groups.map(([id,label])=>`<button class="${id===category?'active':''}" aria-pressed="${id===category}" onclick="CareFlow.review('${id}')"><span>${esc(label)}</span><small>${rows(activeModule,id).length}</small></button>`).join('')}<p class="small">Plan only.<br>No automatic removal.</p></aside><div class="flow-items"><div class="flow-items-head"><label for="flowSearch">Search this group<input id="flowSearch" type="search" placeholder="Name or path" value="${esc(query)}"></label><span>${all.length.toLocaleString()} items</span></div><div class="flow-item-list">${visible.map((row,index)=>`<div class="flow-item ${index===inspected?'inspected':''}">${selectable(row)?`<input type="checkbox" aria-label="Include ${esc(title(row))} in review plan" ${selected.has(row.key)?'checked':''} data-select-index="${index}">`:'<span class="flow-held" title="Protected: inspect only">◇</span>'}<button class="flow-item-open" data-inspect-index="${index}"><b>${esc(title(row))}</b><small>${esc(path(row)||'Recorded evidence')}</small></button><span class="flow-item-size">${Number.isFinite(estimate(row))&&estimate(row)>0?bytes(estimate(row)):'—'}</span></div>`).join('')||'<div class="flow-empty"><h3>No matching records</h3><p>Try another category or search. An empty inventory does not prove a healthy or threat-free system.</p></div>'}</div><div class="flow-pagination"><button class="secondary" onclick="CareFlow.page(-1)" ${offset===0?'disabled':''}>Previous</button><span>${all.length?offset+1:0}–${Math.min(offset+60,all.length)} of ${all.length}</span><button class="secondary" onclick="CareFlow.page(1)" ${offset+60>=all.length?'disabled':''}>Next</button></div></div><aside class="flow-inspector" id="flowInspector" aria-label="Selected item details"></aside><footer class="flow-review-footer"><div><b>${selected.size} items in your review plan</b><small>Estimates may overlap. Selection is not removal authorization.</small></div><button onclick="CareFlow.confirmPlan()" ${selected.size?'':'disabled'}>Prepare review plan →</button></footer></section>`;
    document.querySelector('#flowSearch').addEventListener('input',event=>{query=event.target.value;offset=0;inspected=0;renderReview(true);});
    document.querySelectorAll('[data-inspect-index]').forEach(button=>button.onclick=()=>inspect(Number(button.dataset.inspectIndex)));
    document.querySelectorAll('[data-select-index]').forEach(input=>input.onchange=()=>{const row=visible[Number(input.dataset.selectIndex)];if(!row||!selectable(row))return;if(input.checked)selected.set(row.key,row);else selected.delete(row.key);renderReview();document.querySelector(`[data-select-index="${input.dataset.selectIndex}"]`)?.focus();});
    inspect(inspected);
    if(focusSearch){const search=document.querySelector('#flowSearch');search.focus();}
  }
  function inspect(index){
    const row=filtered().slice(offset,offset+60)[index];inspected=index;
    document.querySelectorAll('.flow-item').forEach((element,i)=>element.classList.toggle('inspected',i===index));
    const inspector=document.querySelector('#flowInspector');
    if(!row){inspector.innerHTML='<span class="smart-eyebrow">Item details</span><p>Select an item to inspect the evidence and recommendation.</p>';return;}
    const item=row.item;
    inspector.innerHTML=`<span class="smart-eyebrow">Item details</span><h3>${esc(title(row))}</h3><p class="pathcell">${esc(path(row))}</p><dl><dt>Recorded size / estimate</dt><dd>${Number.isFinite(estimate(row))&&estimate(row)>0?bytes(estimate(row)):'Not recorded'}</dd><dt>Interpretation</dt><dd>${esc(item.disposition||item.classification||item.status||item.risk_hint&&'Review indicator'||'Evidence, not a removal recommendation')}</dd></dl><p>${esc(item.why_it_exists||item.review_note||item.reason||'Check ownership and audit coverage before making changes.')}</p><p class="flow-recommendation">${esc(item.recommendation||'Review this evidence in context. ReconSpace has not changed the item.')}</p><details><summary>Recorded fields</summary><pre>${esc(JSON.stringify(item,null,2).slice(0,6000))}</pre></details>`;
  }
  function page(direction){offset=Math.max(0,offset+direction*60);inspected=0;renderReview();}
  function advanced(){switchTab(modules[activeModule].groups[0][0]==='safe'?'findings':modules[activeModule].groups[0][0]==='folders'?'dirs':modules[activeModule].groups[0][0]);}
  function raw(){if(modules[currentPage]&&REPORT){activeModule=currentPage;navigation('raw');document.querySelector('#flowContent').classList.add('hidden');}}
  function back(){if(document.body.dataset.flowStage==='overview')navigatePage('home');else overview(currentPage);}
  function dialog(html){const target=document.querySelector('#flowDialog');if(target.open)target.close();target.innerHTML=html;target.showModal();return target;}
  function setup(module='home'){
    const label=modules[module]?.title||'Smart Audit';
    dialog(`<form id="flowSetup"><span class="smart-eyebrow">${REPORT?'Start over':'Ready when you are'}</span><h2>Scan for ${esc(label)}</h2><p>Filesystem evidence follows this root. Application, process and persistence inventory can describe the wider host.</p><label for="flowRoot">Scan root<input id="flowRoot" required value="${esc(document.querySelector('#root').value)}"></label><label for="flowDepth">Audit depth<select id="flowDepth">${Array.from(document.querySelector('#profile').options).map(option=>`<option value="${esc(option.value)}" ${option.selected?'selected':''}>${esc(option.textContent)}</option>`).join('')}</select></label><p class="small">This is the shared read-only audit, focused back on ${esc(label)} when ready.${REPORT?' A successful new report replaces current review selections.':''}</p><div class="flow-dialog-actions"><button type="button" class="secondary" onclick="document.querySelector('#flowDialog').close()">Cancel</button><button type="submit">Start read-only scan</button></div></form>`);
    document.querySelector('#flowSetup').onsubmit=event=>{event.preventDefault();const root=document.querySelector('#flowRoot').value.trim();if(!root)return;document.querySelector('#root').value=root;document.querySelector('#profile').value=document.querySelector('#flowDepth').value;scanDestination=modules[module]?module:'home';priorReport=REPORT;document.querySelector('#flowDialog').close();document.querySelector('#scan').click();};
  }
  function scanStarted(){if(!priorReport)priorReport=REPORT;}
  function scanFailed(){if(priorReport){REPORT=priorReport;renderCareResults();renderMetrics();}const destination=scanDestination;scanDestination='home';priorReport=null;return destination;}
  function scanFinished(current){const destination=current==='home'?scanDestination:current;scanDestination='home';priorReport=null;syncReport();return destination;}
  function cancelled(){if(!priorReport)return false;REPORT=priorReport;priorReport=null;renderCareResults();renderMetrics();const destination=currentPage==='home'?scanDestination:currentPage;scanDestination='home';navigatePage(destination);return true;}
  function failed(){if(!priorReport)return false;const destination=currentPage==='home'?scanDestination:currentPage;scanFailed();navigatePage(destination);return true;}
  function planText(){return ['# ReconSpace selected-item review plan','','PLAN ONLY — NO EXECUTION. No files or system settings were changed.','',`Audit root: ${String(REPORT?.stats?.root||'not recorded').replaceAll('\n',' ')}`,`Selected items: ${selected.size}`,'Estimates may overlap and are not summed or promised as recovered space.','',...[...selected.values()].flatMap(row=>[`## ${modules[row.module].title}: ${title(row)}`,`Path: ${path(row)}`,`Recorded bytes / estimate: ${Number.isFinite(estimate(row))?estimate(row):'not recorded'}`,`Disposition: ${row.item.disposition||row.item.classification||'Review evidence'}`,`Recommendation: ${row.item.recommendation||row.item.review_note||'Confirm ownership, current use and coverage before any action.'}`,''])].join('\n');}
  function confirmPlan(){if(!selected.size)return;dialog(`<span class="smart-eyebrow">Confirm your review selection</span><h2>Prepare a plan for ${selected.size} items?</h2><p>This creates a local Markdown review document. It does not delete files, uninstall apps, stop processes or change Windows settings.</p><p class="small">Sizes can overlap. No combined recovery total is promised.</p><div class="flow-dialog-actions"><button class="secondary" onclick="document.querySelector('#flowDialog').close()">Keep reviewing</button><button onclick="CareFlow.prepare()">Prepare & download</button></div>`);}
  function download(){if(!receipt)return;const url=URL.createObjectURL(new Blob([receipt.text],{type:'text/markdown;charset=utf-8'})),link=document.createElement('a');link.href=url;link.download=receipt.filename;link.click();setTimeout(()=>URL.revokeObjectURL(url),20000);}
  function prepare(){if(!selected.size)return;receipt={text:planText(),filename:'reconspace-selected-review.md',count:selected.size};document.querySelector('#flowDialog').close();download();navigation('receipt');document.querySelector('#flowContent').innerHTML=`<section class="flow-receipt"><span class="flow-receipt-mark">✓</span><span class="smart-eyebrow">Ready for your decision</span><h2>Your review plan is prepared.</h2><p>${receipt.count} evidence items. No files or system settings were changed.</p><p class="small">The download was requested. Your browser controls the save location.</p><div class="flow-primary"><button onclick="CareFlow.review('${category}')">Back to review</button><button class="secondary" onclick="CareFlow.download()">Download again</button></div></section>`;}
  return {enterPage,openModule,review,inspect,page,advanced,raw,back,setup,scanStarted,scanFailed,scanFinished,cancelled,failed,confirmPlan,prepare,download};
})();
