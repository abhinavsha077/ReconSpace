async page=>{
  const nav=page.getByRole('navigation',{name:'Main navigation'}), errors=[];
  page.on('pageerror',error=>errors.push(error.message));
  await page.locator('#motionPreference').selectOption('reduced');
  await page.getByRole('button',{name:'Scan settings',exact:true}).first().click();
  await page.locator('#autoAiReview').uncheck();await page.locator('#noProcesses').check();
  await nav.getByRole('button',{name:'Applications',exact:true}).click();
  await page.getByRole('button',{name:'Manage application review',exact:false}).click();
  await page.locator('[data-select-index]').first().check();
  await page.getByRole('button',{name:'Start over',exact:true}).click();
  await page.locator('#flowRoot').fill('T:/ArcX/Archive Win - PC Cleaner/Source');
  await page.locator('#flowDepth').selectOption('deep');
  const submitted=page.waitForResponse(response=>response.url().endsWith('/api/scan')&&response.request().method()==='POST');
  await page.getByRole('button',{name:'Start read-only scan',exact:true}).click();
  const status=(await submitted).status();
  await page.locator('#cancelSpotlight').click();
  await page.waitForFunction(()=>document.body.dataset.page==='applications'&&document.body.dataset.flowStage==='overview',null,{timeout:90000});
  await page.getByRole('button',{name:'Manage application review',exact:false}).click();
  const retained=await page.locator('[data-select-index]').first().isChecked();
  const hash=await page.evaluate(()=>location.hash);
  await page.getByRole('button',{name:'Start over',exact:true}).click();
  await page.locator('#flowRoot').fill('T:/ReconSpace-path-that-does-not-exist');
  await page.getByRole('button',{name:'Start read-only scan',exact:true}).click();
  await page.locator('.flow-overview').waitFor({state:'visible'});
  await page.getByRole('button',{name:'Manage application review',exact:false}).click();
  const failureRetained=await page.locator('[data-select-index]').first().isChecked();
  return {status,retained,failureRetained,hash,errors};
}
