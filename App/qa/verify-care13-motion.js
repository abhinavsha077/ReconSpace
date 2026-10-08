async page => {
  const nav=page.getByRole('navigation',{name:'Main navigation'});
  if(!await page.locator('.result-card').first().isVisible()){
    await nav.getByRole('button',{name:'Reports',exact:true}).click();
    await page.getByLabel('Import report JSON',{exact:true}).setInputFiles('output/playwright/care-13-export.json');
    await nav.getByRole('button',{name:'Smart Audit',exact:true}).click();
    await page.locator('.result-card').first().waitFor({state:'visible'});
  }
  await page.locator('#motionPreference').selectOption('full');
  await page.evaluate(()=>{window.careFrameSample=new Promise(resolve=>{const samples=[];let last=performance.now();const tick=now=>{samples.push(now-last);last=now;if(samples.length<240)requestAnimationFrame(tick);else resolve({samples:240,p95:samples.sort((a,b)=>a-b)[228],over32:samples.filter(x=>x>32).length});};requestAnimationFrame(tick);});});
  for(const name of ['Cleanup','Protection','Performance','Applications','Smart Audit','My Clutter','Reports','Smart Audit']){await nav.getByRole('button',{name,exact:true}).click();await page.evaluate(async()=>{if(pageTransition)await pageTransition.finished.catch(()=>{});});}
  await page.locator('.result-card').first().waitFor({state:'visible'});
  await page.evaluate(async()=>{if(pageTransition)await pageTransition.finished.catch(()=>{});});
  const frames=await page.evaluate(()=>window.careFrameSample);
  const box=await page.locator('.result-card').first().boundingBox();
  await page.mouse.move(box.x+box.width*.8,box.y+box.height*.2);
  await page.waitForFunction(()=>document.querySelector('.result-card').style.getPropertyValue('--tilt-x')!=='');
  const parallax=await page.locator('.result-card').first().evaluate(el=>({x:el.style.getPropertyValue('--tilt-x'),y:el.style.getPropertyValue('--tilt-y')}));
  return {frames,parallax};
}
