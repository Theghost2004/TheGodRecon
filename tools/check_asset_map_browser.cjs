/* Offline-only map checks. Usage: node tools/check_asset_map_browser.cjs MAP.html NEW_DIRECTORY */
const fs=require('node:fs'),path=require('node:path'),assert=require('node:assert/strict');
const {chromium}=require(process.env.RECONMAP_PLAYWRIGHT_MODULE||'playwright');
(async()=>{
 const [file,directory]=process.argv.slice(2);assert(file&&directory);
 fs.mkdirSync(path.dirname(path.resolve(directory)),{recursive:true});fs.mkdirSync(directory);
 const browser=await chromium.launch({headless:true,...(process.env.RECONMAP_CHROMIUM?{executablePath:process.env.RECONMAP_CHROMIUM}:{})});
 const checks=[],errors=[],network=[];
 try{
  const page=await browser.newPage({viewport:{width:1600,height:1050}});
  page.on('pageerror',e=>errors.push(String(e)));
  page.on('console',m=>{if(m.type()==='error')errors.push(m.text());});
  await page.route(/https?:\/\//,r=>{network.push(r.request().url());return r.abort();});
  await page.setContent(fs.readFileSync(file,'utf8'));
  async function check(name,fn){await fn();checks.push(name);}
  await check('offline map loads',async()=>{assert.match(await page.title(),/Asset map/);assert(await page.locator('#results details').count()>0);});
  await check('bounded DOM pagination',async()=>{assert(await page.locator('#results > details').count()<=60);assert(await page.locator('#next').isEnabled());await page.locator('#next').click();assert.match(await page.locator('#result-count').innerText(),/Page 2/);await page.locator('#previous').click();});
  await page.screenshot({path:path.join(directory,'asset-map-overview.png')});
  await check('API filtering retains inferred states',async()=>{await page.locator('#type').selectOption('api_endpoint');await page.locator('#state').selectOption('javascript-inferred');assert(await page.locator('#results > details').count()>0);});
  await check('expand inspect and relationship navigation',async()=>{const item=page.locator('#results > details').first();await item.locator('summary').click();await item.getByRole('button',{name:'Inspect relationships'}).click();assert.match(await page.locator('#inspector').innerText(),/Relationships/);const relation=page.locator('#inspector > details').nth(2);await relation.locator('summary').click();assert(await relation.locator('button').isVisible());await relation.locator('button').click();assert(await page.locator('#inspector h2').innerText());});
  await check('search and empty state',async()=>{await page.locator('#reset').click();await page.locator('#search').fill('no-such-endpoint-79ef');assert.equal(await page.locator('#results > details').count(),0);assert.match(await page.locator('#result-count').innerText(),/0 matching/);});
  await check('source filter',async()=>{await page.locator('#reset').click();const options=await page.locator('#source option').allTextContents();assert(options.length>1);await page.locator('#source').selectOption(options[1]);assert(await page.locator('#results > details').count()>0);});
  await check('stable report and export links',async()=>{assert.equal(await page.getByRole('link',{name:'Investigation report',exact:true}).getAttribute('href'),'../reports/index.html');assert.equal(await page.getByRole('link',{name:'Endpoint tree',exact:true}).getAttribute('href'),'endpoint-tree.txt');});
  await page.locator('#reset').click();await page.locator('#type').selectOption('javascript_resource');
  const js=page.locator('#results > details').first();await js.locator('summary').click();await js.getByRole('button',{name:'Inspect relationships'}).click();
  await page.screenshot({path:path.join(directory,'javascript-relationships.png')});
  await check('untrusted labels remain text',async()=>{await page.evaluate(()=>{const n=graph.nodes[0];n.label='<img src=https://bad.test onerror=window.injected=true>';document.getElementById('reset').click();});assert.equal(await page.locator('img').count(),0);assert.equal(await page.evaluate(()=>window.injected),undefined);});
  await check('mobile layout',async()=>{await page.setViewportSize({width:390,height:844});assert(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth));});
  await check('no external requests or browser errors',async()=>{assert.deepEqual(network,[]);assert.deepEqual(errors,[]);});
  fs.writeFileSync(path.join(directory,'verification.json'),JSON.stringify({passed:checks,errors,network},null,2));
  console.log(JSON.stringify({passed:checks.length,screenshots:directory,errors,network},null,2));
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
