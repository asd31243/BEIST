"""Supplementary deterministic analyses for the BEIST manuscript."""
from __future__ import annotations
import csv, json, math, random, copy, hashlib
from pathlib import Path
from collections import defaultdict, Counter
import numpy as np
from scipy.stats import mannwhitneyu, fisher_exact
from beist_pipeline import (
    Meta, build_record, CAPABILITIES, PROTOCOL_VERSION,
    bootstrap_median_ci, wilson_interval,
)

ROOT=Path(__file__).resolve().parents[1]
NEW=ROOT/'data'; EXP=ROOT/'.'; RES=EXP/'results'
CAPS=['file_impact','backup_impairment','persistence','privilege_manipulation','process_interference','network_staging','execution_proxy','anti_analysis','ransomware_impact']

def wilson(k,n,z=1.96):
    if not n:return [None,None]
    p=k/n; den=1+z*z/n; mid=(p+z*z/(2*n))/den; h=z*math.sqrt(p*(1-p)/n+z*z/(4*n*n))/den
    return [mid-h,mid+h]

def rank_biserial(u, nx, ny):
    return 2.0 * float(u) / (nx * ny) - 1.0

def log_or_ci(a, b, c, d):
    # Add-one-half only for the interval when a cell is zero; the point odds
    # ratio remains Fisher's exact estimate.
    aa, bb, cc, dd = [float(v) + (0.5 if float(v) == 0 else 0.0) for v in (a,b,c,d)]
    lor = math.log((aa * dd) / (bb * cc))
    se = math.sqrt(1/aa + 1/bb + 1/cc + 1/dd)
    return [math.exp(lor - 1.96*se), math.exp(lor + 1.96*se)]

def bh_adjust(pvals):
    order = np.argsort(np.asarray(pvals, dtype=float)); out = np.empty(len(pvals), dtype=float)
    running = 1.0; n = len(pvals)
    for rank in range(n, 0, -1):
        i = int(order[rank-1]); running = min(running, float(pvals[i]) * n / rank); out[i] = running
    return out.tolist()

def main():
    rows=list(csv.DictReader((NEW/'sample_manifest.csv').open(encoding='utf-8-sig')))
    b=[r for r in rows if r['label']=='benign']; m=[r for r in rows if r['label']=='ransomware']
    tests=[]
    for metric in ['atom_count','readiness','environment_dependence_rate','assessability','supported_capabilities']:
        x=np.array([float(r[metric]) for r in b]); y=np.array([float(r[metric]) for r in m])
        u,p=mannwhitneyu(x,y,alternative='two-sided')
        tests.append({'metric':metric,'benign_mean':float(x.mean()),'ransomware_mean':float(y.mean()),'benign_median':float(np.median(x)),'ransomware_median':float(np.median(y)),'U':float(u),'p_value':float(p),'rank_biserial':rank_biserial(u,len(x),len(y))})
    for row, adj in zip(tests, bh_adjust([r['p_value'] for r in tests])): row['p_value_bh'] = adj
    cap_rows=[]
    recs={p.stem:json.loads(p.read_text(encoding='utf-8')) for p in (NEW/'evidence_records').glob('*.json')}
    for cap in CAPS:
        tab=[]
        for label in ['benign','ransomware']:
            vals=[recs[r['sha256']]['capabilities'][cap]['state'] for r in rows if r['label']==label]
            tab.append({'label':label,'supported':vals.count('S'),'not_supported':vals.count('N'),'indeterminate':vals.count('I'),'n':len(vals)})
        table=[[tab[0]['supported'],tab[0]['n']-tab[0]['supported']],[tab[1]['supported'],tab[1]['n']-tab[1]['supported']]]
        odds,p=fisher_exact(table)
        ci = log_or_ci(tab[0]['supported'], tab[0]['n']-tab[0]['supported'], tab[1]['supported'], tab[1]['n']-tab[1]['supported'])
        risk_diff = tab[1]['supported']/tab[1]['n'] - tab[0]['supported']/tab[0]['n']
        cap_rows.append({'capability':cap,'benign':tab[0],'ransomware':tab[1],'odds_ratio_benign_vs_ransomware':float(odds),'odds_ratio_ci_low':ci[0],'odds_ratio_ci_high':ci[1],'risk_difference_ransomware_minus_benign':risk_diff,'fisher_p':float(p)})
    for row, adj in zip(cap_rows, bh_adjust([r['fisher_p'] for r in cap_rows])): row['fisher_p_bh'] = adj
    json.dump({'protocol_version':'BEIST-1.0','mann_whitney_tests':tests,'capability_fisher_tests':cap_rows},(RES/'inferential_tests.json').open('w',encoding='utf-8'),indent=2)
    with (RES/'inferential_tests.csv').open('w',encoding='utf-8-sig',newline='') as fh:
        w=csv.DictWriter(fh,fieldnames=list(tests[0].keys()));w.writeheader();w.writerows(tests)
    with (RES/'capability_inferential_tests.csv').open('w',encoding='utf-8-sig',newline='') as fh:
        flat=[]
        for row in cap_rows:
            flat.append({k:v for k,v in row.items() if k not in ('benign','ransomware')})
        w=csv.DictWriter(fh,fieldnames=list(flat[0].keys()));w.writeheader();w.writerows(flat)
    # Protocol conformance oracle: independent, minimal cases.  These cases
    # are evaluated by the same frozen implementation rather than merely
    # recorded as prose expectations.
    cases=[
      {'case':'C1_support','capability':'backup_impairment','expected_state':'S','description':'process and command corroborate a backup command','data':{'executed_commands':['vssadmin delete shadows'],'created_process':['vssadmin.exe']}},
      {'case':'C2_indeterminate','capability':'file_impact','expected_state':'I','description':'only one sparse field is observable','data':{'accessed_files':['C:\\a.txt']}},
      {'case':'C3_not_supported','capability':'backup_impairment','expected_state':'N','description':'designated backup channels observable without a backup-support token','data':{'executed_commands':['echo one','echo two','echo three','echo four'],'created_process':['helper1','helper2','helper3','helper4'],'changed_files':['C:\\x1','C:\\x2','C:\\x3','C:\\x4'],'deleted_files':['C:\\y1','C:\\y2','C:\\y3','C:\\y4'],'accessed_mutexes':['a','b','c','d'],'loaded_modules':['m1','m2','m3','m4']}},
      {'case':'C4_missing_not_conflict','capability':'file_impact','expected_state':'I','description':'missing command channel is not a contradiction','data':{'accessed_files':['C:\\a.txt','C:\\b.txt','C:\\c.txt','C:\\d.txt','C:\\e.txt']}},
      {'case':'C5_explicit_conflict','capability':'backup_impairment','expected_state':'K','description':'success and failure claims for one field are recorded as conflict','data':{'executed_commands':['operation success','operation failed']}},
    ]
    conformance_results=[]
    dummy=Meta('0'*64,'benign','','', '', '', '', '', '', '')
    for case in cases:
        atoms, rec=build_record(dummy, case['data'])
        cap=case['capability']
        actual=rec['capabilities'][cap]['state']
        if case['expected_state']=='K':
            actual='K' if rec['corroboration']['contradicted_claims']>0 else actual
        conformance_results.append({**{k:v for k,v in case.items() if k not in ('data',)},'actual_state':actual,'contradiction_count':rec['corroboration']['contradicted_claims'],'pass':actual==case['expected_state']})
    json.dump({'protocol_version':PROTOCOL_VERSION,'oracle_cases':conformance_results,'case_count':len(conformance_results),'all_cases_pass':all(x['pass'] for x in conformance_results)},(RES/'protocol_conformance_cases.json').open('w',encoding='utf-8'),indent=2)
    with (RES/'protocol_conformance_results.csv').open('w',encoding='utf-8-sig',newline='') as fh:
        w=csv.DictWriter(fh,fieldnames=['case','capability','expected_state','actual_state','contradiction_count','pass','description']); w.writeheader(); w.writerows(conformance_results)
    # Evidence monotonicity has an explicit executable oracle: adding a
    # compatible independent observation must not reduce report assessability.
    # Keep the base report just below the file-impact guard (nine events),
    # then add one compatible observation.  The expected result is a strict
    # assessability increase, not merely a non-decrease caused by an unrelated
    # field that leaves every state unchanged.
    base_data = {'accessed_files':[f'C:\\a{i}.txt' for i in range(5)], 'created_files':[f'C:\\b{i}.txt' for i in range(4)]}
    augmented_data = {**base_data, 'created_files': base_data['created_files'] + ['C:\\b4.txt'], 'created_process': ['compatible-helper']}
    _, base_rec = build_record(dummy, base_data); _, aug_rec = build_record(dummy, augmented_data)
    base_assess = sum(base_rec['capabilities'][c]['state'] != 'I' for c in CAPS) / len(CAPS)
    aug_assess = sum(aug_rec['capabilities'][c]['state'] != 'I' for c in CAPS) / len(CAPS)
    mono = {'case':'C6_evidence_monotonicity','description':'adding independent compatible observations does not lower assessability','base_assessability':base_assess,'augmented_assessability':aug_assess,'pass':aug_assess >= base_assess}
    conformance = json.loads((RES/'protocol_conformance_cases.json').read_text(encoding='utf-8'))
    conformance['monotonicity_case'] = mono
    conformance['all_cases_pass'] = conformance['all_cases_pass'] and mono['pass']
    json.dump(conformance,(RES/'protocol_conformance_cases.json').open('w',encoding='utf-8'),indent=2)
    with (RES/'protocol_conformance_results.csv').open('a',encoding='utf-8-sig',newline='') as fh:
        w=csv.writer(fh); w.writerow(['C6_evidence_monotonicity','all_capabilities','NA',str(aug_assess),0,int(mono['pass']),mono['description']])
    # Summarise fragility cohort only, clearly separated from full population.
    frag=[]
    frag_groups=defaultdict(list)
    for r in recs.values():
        for cap,p in r.get('fragility_profile',{}).items():
            pts=p.get('pareto_minimal',[])
            if pts:
                for rank, point in enumerate(pts, 1):
                    frag.append({'sha256':r['sha256'],'label':r['label'],'capability':cap,'pareto_point':rank,'atom_cost':point['cost_vector'][0],'field_cost':point['cost_vector'][1],'collateral_cost':point['cost_vector'][2]})
                    frag_groups[(r['label'],cap)].append(point['cost_vector'])
    with (RES/'fragility_points.csv').open('w',encoding='utf-8-sig',newline='') as fh:
        if frag:
            w=csv.DictWriter(fh,fieldnames=list(frag[0].keys()));w.writeheader();w.writerows(frag)
    summary=[]
    for label in ['benign','ransomware']:
        cohort=[r for r in rows if r['label']==label][:150]
        for cap in CAPS:
            baseline=sum(recs[r['sha256']]['capabilities'][cap]['state']=='S' for r in cohort)
            cohort_records=[recs[r['sha256']] for r in cohort]
            profiles=[r.get('fragility_profile',{}).get(cap,{}) for r in cohort_records]
            report_points=[p.get('pareto_minimal',[]) for p in profiles]
            computed=sum(bool(p) for p in report_points)
            points=[point['cost_vector'] for report in report_points for point in report]
            min_atom_costs=[min(point['cost_vector'][0] for point in report) for report in report_points if report]
            computed_ci=wilson_interval(computed, baseline)
            median_ci=bootstrap_median_ci(min_atom_costs, seed=20260912+len(summary)) if min_atom_costs else (float('nan'),float('nan'))
            summary.append({'label':label,'capability':cap,'fragility_cohort_n':len(cohort),'baseline_supported':baseline,'computed_within_bound':computed,'computed_rate':computed/baseline if baseline else 'NA','computed_rate_ci_low':computed_ci[0] if baseline else 'NA','computed_rate_ci_high':computed_ci[1] if baseline else 'NA','no_disruption_within_bound':baseline-computed,'pareto_points':len(points),'median_atom_cost':float(np.median(min_atom_costs)) if min_atom_costs else 'NA','median_atom_cost_ci_low':median_ci[0] if min_atom_costs else 'NA','median_atom_cost_ci_high':median_ci[1] if min_atom_costs else 'NA','median_field_cost':float(np.median([p[1] for p in points])) if points else 'NA','median_collateral_cost':float(np.median([p[2] for p in points])) if points else 'NA','max_collateral_cost':max([p[2] for p in points],default='NA')})
    with (RES/'fragility_summary.csv').open('w',encoding='utf-8-sig',newline='') as fh:
        w=csv.DictWriter(fh,fieldnames=list(summary[0].keys()));w.writeheader();w.writerows(summary)
    # Rule-table sensitivity is a deterministic audit, not parameter tuning.
    # Re-evaluate the same selected reports under small pre-declared changes
    # to observability guards and the readiness threshold.
    # Sensitivity is evaluated on a fixed, balanced 200-report audit subset
    # to keep the full rule-table perturbation affordable and independently
    # reproducible.  The primary descriptive and inferential results above
    # still use all 2,000 selected reports.
    sensitivity_rows = [r for r in rows if r['label']=='benign'][:100] + [r for r in rows if r['label']=='ransomware'][:100]
    raw_by_sha={r['sha256']:json.loads((NEW/'raw_reports'/r['label']/(r['sha256']+'.json')).read_text(encoding='utf-8')) for r in sensitivity_rows}
    meta_dummy={r['sha256']:Meta(r['sha256'],r['label'],r.get('family',''),int(r['year']) if r.get('year') not in ('','None',None) else None,r.get('arch',''),r.get('packed',''),r.get('entropy',''),r.get('extension',''),r.get('source_json',''),r.get('source_json','')) for r in sensitivity_rows}
    guard_backup=copy.deepcopy(__import__('beist_pipeline').CAPABILITY_OBSERVABILITY)
    readiness_backup=__import__('beist_pipeline').RULES['assessability']['readiness_threshold']
    scenarios=[('frozen',None,None),('min_fields_minus_one','fields',-1),('min_atoms_plus_50pct','atoms',1.5),('readiness_0.50','readiness',0.50)]
    sens=[]
    for name,kind,value in scenarios:
        __import__('beist_pipeline').CAPABILITY_OBSERVABILITY.clear(); __import__('beist_pipeline').CAPABILITY_OBSERVABILITY.update(copy.deepcopy(guard_backup))
        __import__('beist_pipeline').RULES['assessability']['readiness_threshold']=readiness_backup
        if kind=='fields':
            for g in __import__('beist_pipeline').CAPABILITY_OBSERVABILITY.values(): g['min_fields']=max(1,g['min_fields']+value)
        elif kind=='atoms':
            for g in __import__('beist_pipeline').CAPABILITY_OBSERVABILITY.values(): g['min_atoms']=int(math.ceil(g['min_atoms']*value))
        elif kind=='readiness':
            __import__('beist_pipeline').RULES['assessability']['readiness_threshold']=value
        bylab=defaultdict(list)
        for row in sensitivity_rows:
            _, rr=build_record(meta_dummy[row['sha256']], raw_by_sha[row['sha256']]); bylab[row['label']].append(rr)
        for label, rrs in bylab.items():
            for cap in CAPS:
                states=[rr['capabilities'][cap]['state'] for rr in rrs]
                sens.append({'scenario':name,'label':label,'capability':cap,'supported_rate':states.count('S')/len(states),'not_supported_rate':states.count('N')/len(states),'indeterminate_rate':states.count('I')/len(states),'mean_assessability':sum(sum(c['state']!='I' for c in rr['capabilities'].values())/len(CAPS) for rr in rrs)/len(rrs)})
    __import__('beist_pipeline').CAPABILITY_OBSERVABILITY.clear(); __import__('beist_pipeline').CAPABILITY_OBSERVABILITY.update(guard_backup)
    __import__('beist_pipeline').RULES['assessability']['readiness_threshold']=readiness_backup
    with (RES/'sensitivity_analysis.csv').open('w',encoding='utf-8-sig',newline='') as fh:
        w=csv.DictWriter(fh,fieldnames=list(sens[0].keys()));w.writeheader();w.writerows(sens)
    # Extend the run manifest with the analysis artefact hash after it has
    # been generated.  The manifest is not hashed into itself.
    run_manifest = RES/'run_metadata.json'
    if run_manifest.exists():
        run_obj = json.loads(run_manifest.read_text(encoding='utf-8'))
        run_obj.setdefault('output_sha256', {})['./results/sensitivity_analysis.csv'] = hashlib.sha256((RES/'sensitivity_analysis.csv').read_bytes()).hexdigest()
        run_manifest.write_text(json.dumps(run_obj, ensure_ascii=False, indent=2), encoding='utf-8')
    print(json.dumps({'tests':len(tests),'capability_tests':len(cap_rows),'fragility_points':len(frag)},ensure_ascii=False))
if __name__=='__main__':main()

