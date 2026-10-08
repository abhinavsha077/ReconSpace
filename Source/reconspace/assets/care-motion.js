/* One motion controller for navigation, artwork, micro-interactions and accessibility. */
const CareMotion = (() => {
  const systemMotion = matchMedia('(prefers-reduced-motion: reduce)');
  const precisePointer = matchMedia('(hover: hover) and (pointer: fine)');
  let preference='system', pointerFrame=0, pendingPointer=null, tiltedElement=null;
  const animations=new Set();
  try{const saved=localStorage.getItem('rs_motion');if(['system','full','reduced'].includes(saved))preference=saved;}catch{}
  const reduced=()=>preference==='reduced'||systemMotion.matches;
  function resetTilt(){
    if(tiltedElement){for(const [key,value] of Object.entries({'--tilt-x':'0deg','--tilt-y':'0deg','--lift-x':'0px','--lift-y':'0px'}))tiltedElement.style.setProperty(key,value);}
    tiltedElement=null;
  }
  function cancel(){for(const animation of animations)animation.cancel();animations.clear();if(pointerFrame)cancelAnimationFrame(pointerFrame);pointerFrame=0;pendingPointer=null;resetTilt();}
  function animate(element,frames,options){
    if(!element||reduced()||document.hidden)return null;
    const animation=element.animate(frames,options);animations.add(animation);
    animation.finished.then(()=>animations.delete(animation),()=>animations.delete(animation));return animation;
  }
  function sync(){
    document.body.dataset.motion=reduced()?'reduced':'full';
    document.body.dataset.paused=document.hidden?'true':'false';
    const select=document.querySelector('#motionPreference');if(select)select.value=preference;
    if(reduced()||document.hidden)cancel();
  }
  function setPreference(value){
    preference=['system','full','reduced'].includes(value)?value:'system';
    try{localStorage.setItem('rs_motion',preference);}catch{}
    sync();
  }
  function marker(){
    const active=document.querySelector('.rail-nav .rail-item.active'), marker=document.querySelector('#railSelection');
    if(!active||!marker)return;
    marker.style.height=active.offsetHeight+'px';marker.style.transform=`translateY(${active.offsetTop}px)`;
    marker.style.opacity='1';
  }
  function reveal(){
    sync();marker();
    const page=document.body.dataset.page;
    const panel=page==='home'?document.querySelector('#careResults:not(.hidden), #scanComposer:not(.hidden)'):document.querySelector('#moduleIntro:not(.hidden)');
    if(!panel)return;
    const objects=[...panel.querySelectorAll('.result-card,.care-tile,.module-welcome,.smart-copy,.care-visual')].slice(0,8);
    objects.forEach((element,index)=>animate(element,[{opacity:0,transform:'translateY(12px)'},{opacity:1,transform:'translateY(0)'}],{duration:390,delay:index*45,easing:'cubic-bezier(.22,1,.36,1)'}));
  }
  function phaseArtwork(name){
    const target=document.querySelector('#scanOrbitIcon');
    if(!target||target.dataset.art===name)return;
    target.dataset.art=name;target.innerHTML=careArtwork(name,'scan-art');
    animate(target,[{opacity:0,transform:'scale(.92)'},{opacity:1,transform:'scale(1)'}],{duration:360,easing:'cubic-bezier(.22,1,.36,1)'});
  }
  function stage(update,direction){
    const element=document.querySelector('.workspace');let skipped=false,incoming=null;
    const outgoing=animate(element,[{opacity:1},{opacity:0,transform:'translateY(-3px) scale(.995)'}],{duration:100,easing:'ease-out',fill:'forwards'});
    const finished=(async()=>{
      if(outgoing)await outgoing.finished.catch(()=>{});
      if(skipped)return;
      try{update();}finally{outgoing?.cancel();}
      incoming=animate(element,[{opacity:0,transform:direction==='back'?'scale(1.014)':'translateY(8px) scale(.987)'},{opacity:1,transform:'none'}],{duration:320,easing:'cubic-bezier(.22,1,.36,1)'});
      if(incoming)await incoming.finished.catch(()=>{});
    })();
    return {ready:Promise.resolve(),finished,skipTransition(){skipped=true;outgoing?.cancel();incoming?.cancel();}};
  }
  document.addEventListener('pointermove',event=>{
    if(reduced()||!precisePointer.matches||document.hidden)return;
    const element=event.target instanceof Element?event.target.closest('[data-parallax]'):null;
    if(!element){resetTilt();return;}
    pendingPointer={element,x:event.clientX,y:event.clientY};
    if(pointerFrame)return;
    pointerFrame=requestAnimationFrame(()=>{
      pointerFrame=0;const input=pendingPointer;pendingPointer=null;
      if(!input||!input.element.isConnected||reduced())return;
      if(tiltedElement!==input.element)resetTilt();
      tiltedElement=input.element;const bounds=tiltedElement.getBoundingClientRect();
      const x=Math.max(-.5,Math.min(.5,(input.x-bounds.left)/bounds.width-.5));
      const y=Math.max(-.5,Math.min(.5,(input.y-bounds.top)/bounds.height-.5));
      tiltedElement.style.setProperty('--tilt-x',(-y*8)+'deg');tiltedElement.style.setProperty('--tilt-y',(x*10)+'deg');
      tiltedElement.style.setProperty('--lift-x',(x*7)+'px');tiltedElement.style.setProperty('--lift-y',(y*5)+'px');
      tiltedElement.style.setProperty('--light-x',(50+x*55)+'%');tiltedElement.style.setProperty('--light-y',(50+y*55)+'%');
    });
  },{passive:true});
  document.addEventListener('pointerout',event=>{if(tiltedElement&&!(event.relatedTarget instanceof Node&&tiltedElement.contains(event.relatedTarget)))resetTilt();},{passive:true});
  document.addEventListener('visibilitychange',sync);systemMotion.addEventListener('change',sync);
  window.addEventListener('resize',marker,{passive:true});sync();
  return {reduced,setPreference,sync,cancel,reveal,marker,animate,phaseArtwork,stage};
})();

function careArtwork(name,extraClass=''){
  const art={cleanup:'storage',clean:'storage',storage:'storage',protection:'protection',performance:'performance',applications:'applications',clutter:'clutter',smart:'desktop',home:'desktop'}[name];
  if(!art)return cmmIcon(name,64);
  return `<img class="care-art ${extraClass}" src="/assets/care-${art}.png" width="240" height="240" alt="" decoding="async" draggable="false">`;
}
