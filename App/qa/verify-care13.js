async page => {
  const errors=[],failed=[];
  page.on('pageerror',error=>errors.push(error.message));
  page.on('response',response=>{if(response.status()>=400)failed.push(response.status()+' '+response.url());});
  await page.reload();
  await page.waitForFunction(()=>!document.querySelector('#scan').disabled);
  await page.screenshot({path:'output/playwright/care-13-landing.png'});
  const nav=page.getByRole('navigation',{name:'Main navigation'});
  const menus=['Smart Audit','Cleanup','Protection','Performance','Applications','My Clutter','Reports','AI Advisor'];
  for(const name of menus){await nav.getByRole('button',{name,exact:true}).click();await page.waitForFunction(()=>document.getAnimations().filter(a=>a.effect?.target?.classList?.contains('module-welcome')).length===0);}
  await nav.getByRole('button',{name:'Protection',exact:true}).click();
  await page.screenshot({path:'output/playwright/care-13-protection.png'});
  await page.locator('#motionPreference').selectOption('reduced');
  const reduced=await page.evaluate(()=>({mode:document.body.dataset.motion,active:document.getAnimations().filter(a=>a.playState==='running').length}));
  await nav.getByRole('button',{name:'Smart Audit',exact:true}).click();
  await page.getByRole('button',{name:'Change scope',exact:false}).click();
  await page.locator('#root').fill('T:/ArcX/Archive Win - PC Cleaner/Source');
  await page.locator('#profile').selectOption('quick');
  await page.locator('#scan').click();
  await page.waitForFunction(()=>!document.querySelector('#careResults').classList.contains('hidden'),null,{timeout:90000});
  await page.screenshot({path:'output/playwright/care-13-results.png'});
  const cards=await page.locator('.result-card').count();
  let tabs=0;
  for(const name of menus.slice(1)){
    await nav.getByRole('button',{name,exact:true}).click();
    const buttons=page.locator('.tab:not(.hidden)');const count=await buttons.count();
    for(let index=0;index<count;index++){await buttons.nth(index).click();tabs++;}
  }
  await nav.getByRole('button',{name:'My Clutter',exact:true}).click();
  const bubbles=await page.locator('.lens-bubble').count();
  await page.locator('.lens-list-item').first().focus();
  const linked=await page.locator('.lens-bubble.is-selected').count();
  await page.screenshot({path:'output/playwright/care-13-space-lens.png'});
  await page.locator('#lensExplore').click();
  const drill=await page.locator('.lens-crumbs button').count();
  if(drill>1)await page.locator('.lens-crumbs button').first().click();
  await page.locator('#motionPreference').selectOption('full');
  await nav.getByRole('button',{name:'Smart Audit',exact:true}).click();
  const pacing=await page.evaluate(()=>new Promise(resolve=>{const deltas=[];let previous=performance.now();function frame(now){deltas.push(now-previous);previous=now;if(deltas.length<120)requestAnimationFrame(frame);else resolve({samples:deltas.length,p95:deltas.sort((a,b)=>a-b)[Math.floor(deltas.length*.95)],over32:deltas.filter(x=>x>32).length});}requestAnimationFrame(frame);}));
  await page.setViewportSize({width:390,height:844});
  await page.screenshot({path:'output/playwright/care-13-mobile-results.png'});
  const overflow=await page.evaluate(()=>({viewport:innerWidth,width:document.documentElement.scrollWidth}));
  await page.setViewportSize({width:1440,height:900});
  return {menus:menus.length,tabs,cards,reduced,bubbles,linked,drill,pacing,overflow,errors,failed};
}
