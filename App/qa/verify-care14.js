async page=>{
  const errors=[],httpFailures=[];page.on('pageerror',error=>errors.push(error.message));page.on('response',response=>{if(response.status()>=400)httpFailures.push(response.status());});
  await page.setViewportSize({width:1440,height:900});await page.reload();await page.locator('#motionPreference').selectOption('reduced');
  const nav=page.getByRole('navigation',{name:'Main navigation'});
  await nav.getByRole('button',{name:'Reports',exact:true}).click();
  const fixture={profile:'UI fixture',stats:{root:'T:/FlowFixture',files_seen:5,bytes_seen:4096},findings:[
    {title:'Cache <script> fixture',path:'T:/FlowFixture/cache',disposition:'probably_safe_cleanup',estimated_reclaimable_bytes:1024,recommendation:'Review cache ownership',why_it_exists:'Synthetic QA data'},
    {title:'Project archive',path:'T:/FlowFixture/project',disposition:'manual_review',estimated_reclaimable_bytes:2048,recommendation:'Confirm backup'},
    {title:'Protected environment',path:'T:/FlowFixture/env',disposition:'intentional_tooling',size_bytes:4096}
  ],applications:Array.from({length:67},(_,index)=>({name:'Fixture App '+index,install_location:'T:/FlowFixture/app'+index,estimated_size_bytes:1024*(index+1)})),top_directories:[],top_files:[],duplicates:[],audit_health:{coverage_score:0}};
  await page.getByLabel('Import report JSON',{exact:true}).setInputFiles({name:'ui-fixture.json',mimeType:'application/json',buffer:Buffer.from(JSON.stringify(fixture))});
  await nav.getByRole('button',{name:'Cleanup',exact:true}).click();
  await page.locator('.flow-overview').waitFor({state:'visible'});
  await page.screenshot({path:'output/playwright/care-14-summary.png'});
  await page.getByRole('button',{name:'Review storage candidates',exact:false}).click();
  await page.locator('[data-select-index]').first().check();
  await page.getByRole('button',{name:'Manual review',exact:false}).click();
  await page.locator('[data-select-index]').first().check();
  await page.getByRole('button',{name:'Protected & intentional',exact:false}).click();
  const protectedSelectable=await page.locator('[data-select-index]').count();
  await page.getByRole('button',{name:'Lower-risk review',exact:false}).click();
  const retainedSelection=await page.locator('[data-select-index]').first().isChecked();
  await page.locator('#flowSearch').fill('no match');await page.locator('.flow-empty').waitFor({state:'visible'});
  await page.locator('#flowSearch').fill('Cache');
  await page.locator('.flow-item-open').first().click();
  const escaped=await page.locator('#flowInspector h3').textContent();
  await page.screenshot({path:'output/playwright/care-14-review.png'});
  await page.getByRole('button',{name:'Prepare review plan',exact:false}).click();
  await page.getByRole('button',{name:'Keep reviewing',exact:true}).click();
  await page.getByRole('button',{name:'Prepare review plan',exact:false}).click();
  const downloading=page.waitForEvent('download');await page.getByRole('button',{name:'Prepare & download',exact:true}).click();const download=await downloading;
  await page.screenshot({path:'output/playwright/care-14-receipt.png'});
  await page.getByRole('button',{name:'Back to review',exact:true}).click();
  await page.setViewportSize({width:390,height:844});
  await page.screenshot({path:'output/playwright/care-14-narrow.png'});
  const width=await page.evaluate(()=>({viewport:innerWidth,width:document.documentElement.scrollWidth}));await page.setViewportSize({width:1440,height:900});
  await nav.getByRole('button',{name:'Applications',exact:true}).click();await page.getByRole('button',{name:'Manage application review',exact:false}).click();
  const pageOne=await page.locator('.flow-item').count();await page.getByRole('button',{name:'Next',exact:true}).click();const pageTwo=await page.locator('.flow-item').count();
  await page.getByRole('button',{name:'Applications summary',exact:false}).click();await page.getByRole('button',{name:'Advanced evidence',exact:true}).click();
  const tabs=await page.locator('.tab:not(.hidden)').count();
  await page.getByRole('button',{name:'Applications summary',exact:false}).click();
  await page.getByRole('button',{name:'Scan settings',exact:true}).first().click();await page.locator('#autoAiReview').uncheck();await nav.getByRole('button',{name:'Applications',exact:true}).click();
  await page.getByRole('button',{name:'Start over',exact:true}).click();
  await page.locator('#flowRoot').fill('T:/ArcX/Archive Win - PC Cleaner/Source/examples');await page.locator('#flowDepth').selectOption('quick');
  await page.getByRole('button',{name:'Start read-only scan',exact:true}).click();
  await page.waitForFunction(()=>document.body.dataset.page==='applications'&&document.body.dataset.flowStage==='overview',null,{timeout:90000});
  const scanReturn=await page.locator('#pageTitle').textContent();
  await page.getByRole('button',{name:'Manage application review',exact:false}).click();await page.locator('[data-select-index]').first().check();
  await page.getByRole('button',{name:'Scan settings',exact:true}).first().click();await page.locator('#noProcesses').check();await nav.getByRole('button',{name:'Applications',exact:true}).click();
  await page.getByRole('button',{name:'Start over',exact:true}).click();await page.locator('#flowDepth').selectOption('deep');
  await page.getByRole('button',{name:'Start read-only scan',exact:true}).click();await page.waitForFunction(()=>!document.querySelector('#cancelSpotlight').disabled);await page.locator('#cancelSpotlight').click();
  await page.waitForFunction(()=>document.body.dataset.page==='applications'&&document.body.dataset.flowStage==='overview',null,{timeout:90000});
  await page.getByRole('button',{name:'Manage application review',exact:false}).click();
  const cancelRetained=await page.locator('[data-select-index]').first().isChecked();
  return {errors,httpFailures,protectedSelectable,retainedSelection,escaped,download:download.suggestedFilename(),width,pageOne,pageTwo,tabs,scanReturn,cancelRetained};
}
