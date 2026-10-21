"""Reviewed active-tool adapters sharing the existing scheduler/evidence store."""
import asyncio
import hashlib
import json
import time
from urllib.parse import urlsplit, urlunsplit

from .adapters import capture, parse_records
from .analysis import basic_checks
from .config import normalize_url, request_url
from .execution_boundary import BACKEND, TEMPLATE_HASHES, execution_requirement, run_contained
from .integrations import invocation_directory
from .orchestrator import record_execution
from .security import redact, redact_data
from .storage import artifact_path


def arguments(name, config):
    timeout = str(max(1,int(config.budgets.timeout)))
    rate = str(max(1,int(min(config.budgets.overall_rps,config.budgets.per_host_rps))))
    common = ['-l','/inputs.txt','-silent','-duc','-rl',rate]
    if name=='dnsx':
        return common+['-json','-a','-aaaa','-cname','-r','127.0.0.1:1053','-t','1','-retry','1','-timeout',timeout+'s']
    if name=='httpx':
        return common+['-json','-sc','-ct','-title','-td','-location','-irh','-nfs','-x','GET',
            '-proxy','http://127.0.0.1:18080','-r','/resolvers.txt','-t','1','-retries','0',
            '-timeout',timeout,'-rstr',str(config.budgets.response_bytes)]
    if name=='katana':
        return common+['-jsonl','-proxy','http://127.0.0.1:18080','-r','/resolvers.txt',
            '-d',str(max(1,config.budgets.depth)),'-jc','-fx','-c','1','-p','1','-retry','0',
            '-timeout',timeout,'-mrs',str(config.budgets.response_bytes),'-ob']
    if name=='nuclei':
        return common+['-jsonl','-t','/templates/git-head.yaml','-t','/templates/environment.yaml',
            '-ni','-dr','-proxy','http://127.0.0.1:18080','-pi','-r','/resolvers.txt',
            '-c','1','-bs','1','-retries','0','-timeout',timeout,'-rsr','4096','-or','-ot']
    raise ValueError('No reviewed active adapter: '+name)


def checkpoint(name, value):
    return 'contained-input:'+name+':'+hashlib.sha256(value.encode()).hexdigest()


def inputs_for(scanner, name):
    if name=='dnsx':
        values=[r['host'] for r in scanner.store.rows('hosts') if scanner.policy.host_allowed(r['host'])]
    elif name=='nuclei':
        values=sorted({urlunsplit(urlsplit(r['url'])._replace(path='',query='',fragment=''))
                       for r in scanner.store.rows('urls') if r['status'] is not None and scanner.policy.decision(r['url'])[0]})
    else:
        values=[r['url'] for r in scanner.store.rows('jobs') if r['state']=='queued' or name=='katana' and r['state']=='completed']
    return [v for v in values if not scanner.store.meta(checkpoint(name,v),False)]


def completed_inputs(scanner,name,inputs):
    kind='dns-response' if name=='dnsx' else 'external-response-delivered'
    completed=[]
    for value in inputs:
        subjects=[value+path for path in ('/.git/HEAD','/.env')] if name=='nuclei' else [value]
        if all(scanner.store.conn.execute('SELECT 1 FROM observations WHERE subject=? AND kind=? AND source=?',
                                          (subject,kind,name)).fetchone() for subject in subjects):
            completed.append(value)
    return completed


def ingest(scanner, name, records, artifact):
    count=0
    for record in records:
        try:
            value=record['host'] if name=='dnsx' else record['request']['endpoint'] if name=='katana' else record['matched-at'] if name=='nuclei' else record['url']
            subject=value if name=='dnsx' else normalize_url(value)
            scanner.store.observed(subject,'external-tool-output',{'record':redact_data(record),'artifact':artifact,
                'backend':BACKEND,'validation':'Tool metadata; only broker observations establish current reachability'},name,
                identity=hashlib.sha256(json.dumps([name,record],sort_keys=True).encode()).hexdigest())
            if name=='dnsx':
                # Broker DNS responses already contain all records (including
                # partial successes), with timestamps and wire evidence hashes.
                count+=1
                continue
            parent=''
            depth=0
            if name=='katana':
                request=record['request']
                parent=request.get('source','')
                if not isinstance(parent,str) or not parent.startswith(('http://','https://')):
                    parent=''
                parent_job=scanner.store.conn.execute('SELECT depth FROM jobs WHERE url=?',(request_url(parent),)).fetchone() if parent else None
                depth=parent_job[0]+1 if parent_job else scanner.config.budgets.depth+1
                method=request.get('method','UNKNOWN')
                scanner.store.observed(subject,'inferred_endpoint',{'method':method,'source_url':parent,
                    'artifact':artifact,'state':'Tool-discovered reference; reachability requires broker evidence'},'katana')
                scanner.add_url(subject,'katana',parent,depth,fetch=method=='GET')
            else:
                scanner.add_url(subject,name,fetch=False)
            if name=='nuclei':
                template=record.get('template-id')
                rule={'reconmap-git-head-v1':'git-head','reconmap-environment-v1':'environment-config'}.get(template)
                delivered=scanner.store.conn.execute("SELECT 1 FROM observations WHERE subject=? AND kind='external-response-delivered' AND source='nuclei'",(subject,)).fetchone()
                response=scanner.store.conn.execute("SELECT data FROM observations WHERE subject=? AND kind='http' ORDER BY rowid DESC LIMIT 1",(subject,)).fetchone()
                if rule and delivered and response:
                    data=json.loads(response[0])
                    row=scanner.store.conn.execute('SELECT path FROM artifacts WHERE hash=?',(data['hash'],)).fetchone()
                    if row:
                        body=artifact_path(scanner.run,row[0]).read_bytes()
                        if hashlib.sha256(body).hexdigest()!=data['hash']:
                            raise ValueError('Nuclei evidence artifact hash mismatch')
                        basic_checks(scanner.store,subject,body.decode('utf-8',errors='replace'),data['headers'],data['hash'],data['status'],
                            source='nuclei',only_rules={rule},extra_evidence={'template_id':template,'template_hashes':TEMPLATE_HASHES,'artifact':artifact})
            count+=1
        except (ValueError, TypeError, KeyError) as exc:
            scanner.store.observed(name,'tool-output-error',{'error':str(exc),'artifact':artifact},name)
    return count


async def run_active(scanner, name):
    """Return True only when the selected external adapter handled its inputs."""
    if name not in scanner.tools:
        return False
    if scanner.config.execution_engines.get(name)=='native' and not scanner.config.strict_tools:
        return False
    info=scanner.tools[name]
    reason=execution_requirement(scanner.config,name,info,getattr(scanner,'boundary',None),scanner.manifest['target'])
    if reason:
        state='unavailable' if not info.available else 'incompatible' if not info.supported else 'blocked-by-policy'
        scanner.store.stage(name,state,reason)
        record_execution(scanner,name,state=state,reason=reason,limitations=[reason])
        return False
    inputs=inputs_for(scanner,name)
    if not inputs:
        if not scanner.store.meta('executed:'+name,False):
            scanner.store.stage(name,'skipped','No eligible inputs; external process not started')
            record_execution(scanner,name,state='skipped',reason='No eligible inputs; external process not started')
        return True
    cwd=invocation_directory(scanner,name)
    started=time.monotonic()
    state,detail='failed',''
    result,broker=None,None
    interrupted=False
    records=[]
    record_execution(scanner,name,state='running',inputs=['recon.sqlite:hosts' if name=='dnsx' else 'recon.sqlite:jobs'])
    try:
        result,broker=await run_contained(scanner,info,cwd,arguments(name,scanner.config),inputs)
    except (asyncio.CancelledError, KeyboardInterrupt) as exc:
        result,broker=getattr(exc,'result',None),getattr(exc,'broker',None)
        interrupted=True
        detail='Contained process interrupted; completed broker evidence retained'
        raise
    except (OSError,ValueError,TimeoutError) as exc:
        result,broker=getattr(exc,'result',None),getattr(exc,'broker',None)
        detail=redact(str(exc))
    finally:
        actual=bool(result and 'RECONMAP_TOOL_STARTED' in result.stderr)
        if result:
            capture(result,cwd)
            records,errors=parse_records(name,result.stdout)
            if actual:
                scanner.store.set_meta('executed:'+name,True)
            if errors:
                detail=detail or '; '.join(errors[:10])
            if result.code:
                detail=detail or f'Process exit {result.code}: '+redact(result.stderr[-2000:])
            if not actual:
                detail=detail or 'Execution boundary did not confirm child process start'
            if broker and broker.failures:
                detail=detail or '; '.join(broker.failures)
            completed=completed_inputs(scanner,name,inputs)
            if len(completed)!=len(inputs):
                detail=detail or f'{len(inputs)-len(completed)} assigned inputs have no completed broker observation'
            state='interrupted' if interrupted else 'partial' if detail else 'completed'
        else:
            completed=[]
            if interrupted:state='interrupted'
        count=ingest(scanner,name,records,str(cwd.relative_to(scanner.run)))
        if state=='completed':
            for value in inputs:
                scanner.store.set_meta(checkpoint(name,value),True)
        scanner.store.stage(name,state,detail or 'External executable completed inside '+BACKEND)
        record_execution(scanner,name,engine=name if actual else None,state=state,reason=detail,
            count=count,seconds=time.monotonic()-started,outputs=[str(cwd.relative_to(scanner.run))],
            accounting={'backend':BACKEND,**(broker.metrics if broker else {})},
            process={'executable':info.path,'sha256':info.sha256,'version':info.version,'executed':actual,
                     'exit_code':result.code if result else None,'input_count':len(inputs),'output_count':len(records),
                     'completed_inputs':len(completed),
                     'duration_seconds':round(time.monotonic()-started,6),'backend':BACKEND},
            limitations=[detail] if detail else [])
    return state=='completed'
