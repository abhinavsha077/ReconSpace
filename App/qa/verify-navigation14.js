async page=>{
  const errors=[],failures=[];page.on('pageerror',error=>errors.push(error.message));
  page.on('response',response=>{if(response.status()>=400)failures.push(response.status());});
  await page.setViewportSize({width:1440,height:900});
  const nav=page.getByRole('navigation',{name:'Main navigation'}), routes=[];let tabs=0;
  for(const label of ['Cleanup','Protection','Performance','Applications','My Clutter']){
    await nav.getByRole('button',{name:label,exact:true}).click();
    await page.locator('.flow-overview').waitFor({state:'visible'});
    await page.getByRole('button',{name:'Advanced evidence',exact:true}).click();
    const buttons=page.locator('.tab:not(.hidden)');
    for(let index=0;index<await buttons.count();index++){await buttons.nth(index).click();tabs++;}
    await page.locator('#flowNavigation').getByRole('button',{name:label+' summary',exact:false}).click();
    await page.locator('.flow-overview').waitFor({state:'visible'});routes.push(label);
  }
  for(const label of ['Reports','AI Advisor']){
    await nav.getByRole('button',{name:label,exact:true}).click();
    const buttons=page.locator('.tab:not(.hidden)');
    for(let index=0;index<await buttons.count();index++){await buttons.nth(index).click();tabs++;}routes.push(label);
  }
  await page.getByRole('button',{name:'Scan settings',exact:true}).first().click();routes.push('Settings');
  await nav.getByRole('button',{name:'Smart Audit',exact:true}).click();routes.push('Smart Audit');
  await page.locator('.result-card').first().click();await page.locator('.flow-manager').waitFor({state:'visible'});
  const directReview=await page.locator('.flow-manager').isVisible();
  await page.locator('#motionPreference').selectOption('full');
  await nav.getByRole('button',{name:'Protection',exact:true}).click();
  await page.locator('.flow-overview').waitFor({state:'visible'});
  await page.screenshot({path:'output/playwright/care-14-protection.png'});
  await page.getByRole('button',{name:'Zoom in',exact:true}).click();const zoom=await page.getByRole('button',{name:'Reset zoom',exact:true}).textContent();
  await page.getByRole('button',{name:'Reset zoom',exact:true}).click();
  await page.locator('#motionPreference').selectOption('reduced');
  const reduced=await page.evaluate(()=>({mode:document.body.dataset.motion,running:document.getAnimations().filter(animation=>animation.playState==='running').length}));
  return {routes,tabs,directReview,zoom,reduced,errors,failures,hash:await page.evaluate(()=>location.hash)};
}
