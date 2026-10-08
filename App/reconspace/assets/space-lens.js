/* Bounded report evidence, not an invented filesystem hierarchy. */
let lensRoot='', lensTrail=[], lensRows=[], lensSelected=0;
const lensPath=path=>String(path||'').replaceAll('\\','/').replace(/\/+$/,'').toLowerCase();
function lensChildren(path){
  const parent=lensPath(path), unique=new Map();
  for(const row of REPORT?.top_directories||[]){
    if(typeof row.path!=='string')continue;
    const key=lensPath(row.path), size=Number(row.size_bytes);
    if(key!==parent&&key.startsWith(parent+'/')&&Number.isFinite(size)&&size>=0)unique.set(key,row);
  }
  const rows=[...unique.values()];
  return rows.filter(row=>{let key=lensPath(row.path);while(key.includes('/')){key=key.slice(0,key.lastIndexOf('/'));if(unique.has(key))return false;}return true;}).sort((a,b)=>b.size_bytes-a.size_bytes);
}
function spaceLens(){
  const root=String(REPORT?.stats?.root||'');
  if(root!==lensRoot){lensRoot=root;lensTrail=[root];lensSelected=0;}
  lensRows=lensChildren(lensTrail.at(-1)).slice(0,8);
  lensSelected=Math.min(lensSelected,Math.max(0,lensRows.length-1));
  const largest=Math.max(1,...lensRows.map(row=>row.size_bytes));
  return `<section class="space-lens"><div class="lens-heading"><div><span class="smart-eyebrow">Explore your storage</span><h3>Space Lens</h3></div><button class="secondary" onclick="switchTab('dirs')">All folder evidence →</button></div><nav class="lens-crumbs" aria-label="Folder trail">${lensTrail.map((path,index)=>`<button class="secondary" onclick="lensBack(${index})">${esc(path.split(/[\\/]/).filter(Boolean).at(-1)||path||'Scan root')}</button>`).join('<span>›</span>')}</nav><div class="lens-layout"><div class="lens-canvas"><svg viewBox="0 0 640 350" role="group" aria-label="Folder sizes"><defs><radialGradient id="lensGlass" cx="35%" cy="25%"><stop stop-color="#d1f4ee" stop-opacity=".38"/><stop offset="1" stop-color="#568991" stop-opacity=".2"/></radialGradient></defs>${lensRows.map((row,index)=>{const radius=74*Math.sqrt(row.size_bytes/largest),x=80+(index%4)*160,y=80+Math.floor(index/4)*170;return `<g class="lens-bubble" data-lens-index="${index}" tabindex="0" role="button" aria-label="${esc(row.path)}: ${bytes(row.size_bytes)}"><circle class="lens-hit" cx="${x}" cy="${y}" r="${Math.max(18,radius)}"/><circle class="lens-disc" cx="${x}" cy="${y}" r="${radius}"/><text x="${x}" y="${y+92}" text-anchor="middle">${esc((row.path.split(/[\\/]/).filter(Boolean).at(-1)||row.path).slice(0,18))}</text></g>`;}).join('')}</svg>${!lensRows.length?'<p class="lens-empty">No retained child-folder evidence for this location.</p>':''}</div><div class="lens-list">${lensRows.map((row,index)=>`<button class="lens-list-item" data-lens-index="${index}"><span>${esc(row.path.split(/[\\/]/).filter(Boolean).at(-1)||row.path)}</span><b>${bytes(row.size_bytes)}</b></button>`).join('')}<div class="lens-detail"><p id="lensSelectedPath" class="pathcell"></p><button class="secondary" id="lensExplore" onclick="lensExplore()">Explore retained folders</button></div></div></div><p class="small lens-disclosure">Circle area reflects recorded bytes. Up to eight non-overlapping retained folders are shown; this bounded report is not a complete disk tree. Hover or focus links the map and list. No files are changed.</p></section>`;
}
function lensSelect(index){
  if(!lensRows[index])return;
  lensSelected=index;
  document.querySelectorAll('[data-lens-index]').forEach(el=>{const selected=Number(el.dataset.lensIndex)===index;el.classList.toggle('is-selected',selected);el.setAttribute('aria-pressed',String(selected));});
  document.querySelector('#lensSelectedPath').textContent=lensRows[index].path;
  document.querySelector('#lensExplore').textContent=lensChildren(lensRows[index].path).length?'Explore retained folders →':'Inspect folder evidence →';
}
function bindSpaceLens(){
  document.querySelectorAll('[data-lens-index]').forEach(el=>{
    const select=()=>lensSelect(Number(el.dataset.lensIndex));
    el.addEventListener('pointerenter',select);el.addEventListener('focus',select);el.addEventListener('click',select);
    if(el.tagName.toLowerCase()==='g')el.addEventListener('keydown',event=>{if(['Enter',' '].includes(event.key)){event.preventDefault();select();}});
  });
  if(lensRows.length)lensSelect(lensSelected);else document.querySelector('#lensExplore').disabled=true;
}
function lensExplore(){
  const row=lensRows[lensSelected];if(!row)return;
  if(!lensChildren(row.path).length){switchTab('dirs');return;}
  lensTrail.push(row.path);lensSelected=0;render();
  CareMotion.animate(document.querySelector('.lens-canvas'),[{opacity:.1,transform:'scale(.94)'},{opacity:1,transform:'scale(1)'}],{duration:420,easing:'cubic-bezier(.22,1,.36,1)'});
}
function lensBack(index){if(index<0||index>=lensTrail.length)return;lensTrail=lensTrail.slice(0,index+1);lensSelected=0;render();CareMotion.animate(document.querySelector('.lens-canvas'),[{opacity:.2,transform:'scale(1.04)'},{opacity:1,transform:'scale(1)'}],{duration:360,easing:'ease-out'});}
