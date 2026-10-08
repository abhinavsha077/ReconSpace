async page=>{
  const errors=[];page.on('pageerror',error=>errors.push(error.message));
  await page.setViewportSize({width:1440,height:900});
  await page.locator('#motionPreference').selectOption('reduced');
  const version=await page.getByRole('heading',{name:'ReconSpace v1.4.0',exact:true}).textContent();
  const nav=page.getByRole('navigation',{name:'Main navigation'});
  await nav.getByRole('button',{name:'Cleanup',exact:true}).click();
  await page.getByRole('button',{name:'Scan & review',exact:false}).click();
  const dialog=await page.getByRole('dialog').isVisible();
  await page.keyboard.press('Escape');
  const dismissed=!(await page.getByRole('dialog').isVisible());
  await nav.getByRole('button',{name:'Smart Audit',exact:true}).click();
  const assets=[];
  for(const module of ['desktop','storage','protection','performance','applications','clutter']){
    assets.push((await page.request.get(new URL('/assets/care-'+module+'.png',page.url()).href)).status());
  }
  await page.locator('#motionPreference').selectOption('system');
  return {version,dialog,dismissed,assets,errors};
}
