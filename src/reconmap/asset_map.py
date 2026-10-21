"""Self-contained, paginated asset map. Text-only DOM, hash-pinned script, no network."""
import base64
import hashlib
import html
import json

from . import __version__

SCRIPT = r'''
'use strict';
const graph=JSON.parse(document.getElementById('graph-data').textContent);
const order=['domain','subdomain','origin','path_group','webpage','api_endpoint','javascript_resource','static_resource','form_action','external_reference','historical_url','http_request'];
graph.nodes.sort((a,b)=>(order.includes(a.type)?order.indexOf(a.type):99)-(order.includes(b.type)?order.indexOf(b.type):99)||a.label.localeCompare(b.label)||a.id.localeCompare(b.id));
const readable=value=>({javascript_resource:'JavaScript resource',http_request:'HTTP request',api_endpoint:'API endpoint','live-observed':'HTTP observed','path_group':'Path prefix (structural)'}[value]||value.replaceAll('_',' ').replaceAll('-',' '));
const nodes=new Map(graph.nodes.map(n=>[n.id,n]));
const adjacency=new Map();
for(const e of graph.edges){for(const id of new Set([e.source,e.destination])){if(!adjacency.has(id))adjacency.set(id,[]);adjacency.get(id).push(e);}}
const searchIndex=new Map(graph.nodes.map(n=>[n.id,(n.label+' '+n.type+' '+n.sources.join(' ')).toLowerCase()]));
const $=id=>document.getElementById(id);
let page=0, selected=null, relationPage=0;
const pageSize=60, relationSize=40;
function text(tag,value){const el=document.createElement(tag);el.textContent=value;return el;}
function button(label,action){const el=text('button',label);el.type='button';el.addEventListener('click',action);return el;}
for(const [id,values] of [['type',graph.nodes.map(n=>n.type)],['source',graph.nodes.flatMap(n=>n.sources)],['state',graph.nodes.flatMap(n=>n.states)]]){
 for(const value of [...new Set(values)].sort()){const opt=text('option',id==='source'?value:readable(value));opt.value=value;$(id).append(opt);}
 $(id).addEventListener('change',()=>{page=0;render();});
}
$('search').addEventListener('input',()=>{page=0;render();});
$('previous').addEventListener('click',()=>{page--;render();});
$('next').addEventListener('click',()=>{page++;render();});
$('reset').addEventListener('click',()=>{for(const id of ['search','type','source','state'])$(id).value='';page=0;render();});
function inspect(id){
 selected=id;relationPage=0;drawDetails();
}
function drawDetails(){
 const n=nodes.get(selected);if(!n)return;
 const panel=$('inspector');panel.replaceChildren(text('h2',n.label),text('p',readable(n.type)+' · '+n.states.map(readable).join(', ')));
 panel.append(text('p','Sources: '+(n.sources.join(', ')||'URL structure')));
 if(n.status!=null)panel.append(text('p','HTTP status: '+n.status+' · '+(n.reachability||'observed')));
 if(n.review_priority)panel.append(text('p','Review priority: '+n.review_priority+' · Evidence confidence: '+n.evidence_confidence));
 if(n.observation_note)panel.append(text('p',n.observation_note));
 const details=document.createElement('details');details.append(text('summary','Node metadata'));
 const summary={...n};delete summary.evidence;
 details.append(text('pre',JSON.stringify(summary,null,2)));panel.append(details);
 const evidence=document.createElement('details');evidence.append(text('summary','Supporting evidence ('+(Array.isArray(n.evidence)?n.evidence.length:1)+')'));
 evidence.append(text('pre',JSON.stringify(Array.isArray(n.evidence)?n.evidence.slice(0,100):n.evidence,null,2)));
 evidence.append(text('p','First 100 references shown; complete references are preserved in asset-graph.json and SQLite.'));panel.append(evidence);
 const edges=adjacency.get(selected)||[];panel.append(text('h3','Relationships · '+edges.length));
 const controls=document.createElement('div');
 const prev=button('Previous relationships',()=>{relationPage--;drawDetails();});prev.disabled=relationPage===0;
 const next=button('Next relationships',()=>{relationPage++;drawDetails();});next.disabled=(relationPage+1)*relationSize>=edges.length;
 controls.append(prev,next);panel.append(controls);
 for(const e of edges.slice(relationPage*relationSize,(relationPage+1)*relationSize)){
  const other=e.source===selected?e.destination:e.source;
  const box=document.createElement('details');
  box.append(text('summary',(e.source===selected?'→ ':'← ')+readable(e.type)+' · '+readable(e.semantics)));
  box.append(button(nodes.get(other).label,()=>inspect(other)));
  box.append(text('pre',JSON.stringify({...e,evidence:e.evidence.slice(0,30)},null,2)));panel.append(box);
 }
}
function render(){
 const q=$('search').value.toLowerCase(),type=$('type').value,source=$('source').value,state=$('state').value;
 const filtered=graph.nodes.filter(n=>(!q||searchIndex.get(n.id).includes(q))&&(!type||n.type===type)&&(!source||n.sources.includes(source))&&(!state||n.states.includes(state)));
 page=Math.min(Math.max(0,page),Math.max(0,Math.ceil(filtered.length/pageSize)-1));
 $('results').replaceChildren();
 for(const n of filtered.slice(page*pageSize,(page+1)*pageSize)){
  const item=document.createElement('details');item.className='node';
  item.append(text('summary',n.label));
  item.append(text('p',readable(n.type)+' · '+(n.states.map(readable).join(', ')||'provenance')));
  item.append(text('small','Sources: '+(n.sources.join(', ')||'structural grouping')));
  item.append(document.createElement('br'));
  item.append(button('Inspect relationships',()=>inspect(n.id)));$('results').append(item);
 }
 $('result-count').textContent=filtered.length+' matching nodes · Page '+(page+1)+' / '+Math.max(1,Math.ceil(filtered.length/pageSize));
 $('previous').disabled=page===0;$('next').disabled=(page+1)*pageSize>=filtered.length;
}
render();
const first=graph.nodes.find(n=>n.type==='domain');if(first)inspect(first.id);
'''


def render_map(graph, report_href="../reports/index.html"):
    payload=json.dumps(graph,ensure_ascii=True).replace('<','\\u003c').replace('>','\\u003e').replace('&','\\u0026')
    digest=base64.b64encode(hashlib.sha256(SCRIPT.encode()).digest()).decode()
    summary=graph['summary']
    title=next((n['label'] for n in graph['nodes'] if n['type']=='domain'),'Application surface')
    return f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'sha256-{digest}'; style-src 'unsafe-inline'; connect-src 'none'; img-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'">
<title>TheGodRecon · Asset map · {html.escape(title)}</title><style>
:root{{color-scheme:dark}}*{{box-sizing:border-box}}body{{margin:0;background:#0c1323;color:#e7edf9;font:15px system-ui;overflow-wrap:anywhere}}header{{padding:2rem 3vw;background:#13213a;border-bottom:1px solid #2c4165}}h1{{margin:.4rem 0;font-size:2rem}}.eyebrow{{color:#81dfc2;letter-spacing:.12em;font-size:.75rem}}a{{color:#9ccaff}}.cards{{display:flex;gap:1rem;flex-wrap:wrap;margin-top:1.4rem}}.card{{background:#1b2c48;border:1px solid #344b70;border-radius:9px;padding:.8rem 1.4rem}}.card strong{{font-size:1.7rem;display:block}}.card small,small{{color:#b6c8e4}}main{{display:grid;grid-template-columns:minmax(190px,230px) minmax(260px,1fr) minmax(280px,1fr);gap:1.3rem;padding:1.5rem 3vw}}aside,section{{min-width:0}}label{{display:block;margin-bottom:1rem;color:#b9cbe6}}input,select,button{{font:inherit;color:inherit;background:#152641;border:1px solid #46618a;border-radius:5px;padding:.55rem;max-width:100%}}input,select{{width:100%;margin-top:.3rem}}button{{cursor:pointer;margin:.3rem .35rem .3rem 0}}button:hover{{border-color:#81dfc2}}button:disabled{{opacity:.4;cursor:default}}details{{border:1px solid #2c4165;border-radius:7px;padding:.75rem;margin:.5rem 0;background:#101e34}}summary{{cursor:pointer}}details p{{margin:.6rem 0}}pre{{font-size:.78rem;white-space:pre-wrap;overflow-wrap:anywhere}}#inspector{{padding:0 1rem;border-left:1px solid #2c4165}}#inspector h2{{font-size:1.1rem}}.note{{color:#afc1dc;font-size:.85rem;line-height:1.6}}.toolbar{{display:flex;gap:.3rem}}@media(max-width:850px){{main{{grid-template-columns:1fr}}#inspector{{border:0;padding:0}}}}
</style></head><body><header><div class="eyebrow">THEGODRECON {__version__} / OBSERVABLE APPLICATION SURFACE</div><h1>{html.escape(title)}</h1>
<p>Endpoint hierarchy &amp; evidence relationships</p><nav><a href="{html.escape(report_href, quote=True)}">Investigation report</a> · <a href="endpoint-tree.txt">Endpoint tree</a> · <a href="asset-graph.json" download>Graph JSON</a> · <a href="asset-graph.dot" download>Graphviz DOT</a></nav>
<div class="cards">{''.join(f'<div class="card"><strong>{summary[key]}</strong><small>{label}</small></div>' for key,label in [('hosts','Hosts'),('urls','URLs discovered'),('tested_urls','URLs observed'),('api_candidates','API route candidates'),('nodes','Graph nodes'),('edges','Relationships')])}</div></header>
<main><aside><h2>Explore evidence</h2><label>Search endpoints<input id="search" type="search" placeholder="/api, app.js, login…"></label><label>Node type<select id="type"><option value="">All types</option></select></label><label>Evidence source<select id="source"><option value="">All sources</option></select></label><label>Observation state<select id="state"><option value="">All states</option></select></label><button id="reset">Reset filters</button><p class="note">Expand a node to inspect its relationships. Following a relationship navigates locally, including cycles and shared resources.</p><p class="note">Path groups describe URL structure. They do not prove that directories exist. Historical and inferred references are distinct from current HTTP observations.</p><p class="note">No target resource is loaded. Exports are redacted; raw evidence remains in the run folder.</p></aside>
<section aria-label="Graph nodes"><h2>Application inventory</h2><p id="result-count" role="status" aria-live="polite"></p><div class="toolbar"><button id="previous">Previous</button><button id="next">Next</button></div><div id="results"></div></section>
<section id="inspector" aria-label="Selected node relationships"><h2>Inspect a node</h2><p>Select a node to view evidence and relationships.</p></section></main>
<script id="graph-data" type="application/json">{payload}</script><script>{SCRIPT}</script></body></html>'''
