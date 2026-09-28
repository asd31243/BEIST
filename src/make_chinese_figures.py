"""Render Chinese-language scientific figures from the frozen BEIST outputs.

The data and binning follow beist_pipeline.make_figures; only figure text and
font settings change.  No reports are reselected or reanalysed.
"""
from __future__ import annotations
import csv, json
from pathlib import Path
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib import font_manager

ROOT = Path(__file__).resolve().parents[1]
EXP = ROOT / '.'
PAPER_FIG = ROOT / 'figures'
PAPER_FIG.mkdir(parents=True, exist_ok=True)
RESULT = EXP / 'results'
MANIFEST = ROOT / 'data' / 'sample_manifest.csv'
RECORDS = ROOT / 'data' / 'evidence_records'
CAPS = ['file_impact','backup_impairment','persistence','privilege_manipulation','process_interference','network_staging','execution_proxy','anti_analysis','ransomware_impact']
CAP_LABELS = ['文件影响','备份破坏','持久化','权限操纵','进程干扰','网络筹备','代理执行','反分析','影响链']

def configure_cjk_font():
    candidates = [Path(r'C:\Windows\Fonts\msyh.ttc'), Path(r'C:\Windows\Fonts\simhei.ttf'), Path(r'C:\Windows\Fonts\NotoSansSC-VF.ttf')]
    for candidate in candidates:
        if candidate.is_file():
            font_manager.fontManager.addfont(str(candidate))
            family = font_manager.FontProperties(fname=str(candidate)).get_name()
            plt.rcParams.update({'font.family':family, 'font.sans-serif':[family, 'DejaVu Sans'], 'axes.unicode_minus':False})
            return
    plt.rcParams.update({'font.sans-serif':['DejaVu Sans'], 'axes.unicode_minus':False})

def load_manifest():
    with MANIFEST.open(encoding='utf-8-sig', newline='') as f:
        return list(csv.DictReader(f))

def load_records(manifest):
    out=[]
    for row in manifest:
        with (RECORDS / f"{row['sha256']}.json").open(encoding='utf-8') as f:
            out.append(json.load(f))
    return out

def save(fig, stem):
    fig.savefig(PAPER_FIG / f'{stem}_zh.svg', bbox_inches='tight')
    fig.savefig(PAPER_FIG / f'{stem}_zh_svg-raw.pdf', format='pdf', bbox_inches='tight')
    fig.savefig(PAPER_FIG / f'{stem}_zh.png', dpi=220, bbox_inches='tight')
    plt.close(fig)

def main():
    configure_cjk_font()
    plt.rcParams.update({'font.size':10, 'axes.titlesize':11, 'axes.labelsize':10})
    manifest=load_manifest(); records=load_records(manifest)
    colors={'benign':'#2F6B9A','ransomware':'#C4553D'}
    # Figure 1: ECDF for the readiness point mass and a broken-axis boxplot
    # for the central and tail ranges of environment dependence.
    fig=plt.figure(figsize=(10.6,4.2),constrained_layout=True)
    outer=fig.add_gridspec(1,2,width_ratios=[1.03,1.17])
    ax_ready=fig.add_subplot(outer[0,0])
    env_grid=outer[0,1].subgridspec(1,2,width_ratios=[3.5,1.25],wspace=.06)
    ax_env=fig.add_subplot(env_grid[0,0]); ax_tail=fig.add_subplot(env_grid[0,1],sharey=ax_env)
    env_by_label={}
    names={'benign':'良性','ransomware':'勒索软件'}
    for lab in ['benign','ransomware']:
        vals=np.asarray([float(m['readiness']) for m in manifest if m['label']==lab])
        ax_ready.ecdf(vals,label=f"{names[lab]}（n={len(vals):,}）",color=colors[lab],linewidth=2.2)
        env_by_label[lab]=np.asarray([float(m['environment_dependence_rate']) for m in manifest if m['label']==lab])
    ax_ready.set_xlim(.48,1.005); ax_ready.set_ylim(0,1.02)
    ax_ready.set_xlabel('观测覆盖度'); ax_ready.set_ylabel('报告累计比例')
    ax_ready.set_title('已记录证据覆盖度（ECDF）'); ax_ready.legend(frameon=False,loc='upper left'); ax_ready.grid(alpha=.22)
    full_b=np.mean(np.asarray([float(m['readiness']) for m in manifest if m['label']=='benign'])==1.0)
    full_r=np.mean(np.asarray([float(m['readiness']) for m in manifest if m['label']=='ransomware'])==1.0)
    ax_ready.text(.51,.82,f"覆盖度 = 1\n良性：{full_b:.1%}\n勒索软件：{full_r:.1%}",transform=ax_ready.transAxes,va='top',fontsize=9,
                  bbox={'boxstyle':'round,pad=.35','facecolor':'white','edgecolor':'#CBD5E1','alpha':.95})
    box_data=[env_by_label['benign'],env_by_label['ransomware']]
    for axis in [ax_env,ax_tail]:
        bp=axis.boxplot(box_data,positions=[1,2],orientation='horizontal',widths=.52,patch_artist=True,whis=(5,95),showfliers=True,
                        medianprops={'color':'#17324D','linewidth':1.6},
                        flierprops={'marker':'o','markersize':2.5,'markerfacecolor':'none','markeredgecolor':'#6E7B87','alpha':.55})
        for patch,lab in zip(bp['boxes'],['benign','ransomware']):
            patch.set_facecolor(colors[lab]);patch.set_alpha(.68);patch.set_edgecolor(colors[lab])
        axis.grid(axis='x',alpha=.22);axis.xaxis.set_major_formatter(matplotlib.ticker.PercentFormatter(1.0,decimals=0))
    ax_env.set_xlim(0,.25);ax_tail.set_xlim(.25,.95)
    ax_env.set_yticks([1,2],['良性\n（n=1,000）','勒索软件\n（n=1,000）'])
    ax_tail.tick_params(axis='y',labelleft=False,left=False)
    ax_env.spines['right'].set_visible(False);ax_tail.spines['left'].set_visible(False)
    ax_env.set_title('环境依赖行为原子率');ax_env.set_xlabel('主体区间');ax_tail.set_xlabel('长尾')
    d=.018;kwargs=dict(transform=ax_env.transAxes,color='#24313D',clip_on=False,linewidth=1.0)
    ax_env.plot((1-d,1+d),(-d,+d),**kwargs);ax_env.plot((1-d,1+d),(1-d,1+d),**kwargs)
    kwargs.update(transform=ax_tail.transAxes)
    ax_tail.plot((-d,+d),(-d,+d),**kwargs);ax_tail.plot((-d,+d),(1-d,1+d),**kwargs)
    ax_tail.text(.98,.98,f"最大值\n良性 {env_by_label['benign'].max():.1%}\n勒索 {env_by_label['ransomware'].max():.1%}",transform=ax_tail.transAxes,ha='right',va='top',fontsize=8)
    save(fig,'fig1_audit_distributions')
    # Figure 2
    by_sha={r['sha256']:r for r in records}; x=np.arange(len(CAPS)); width=.35
    fig, ax=plt.subplots(figsize=(10,4.6),constrained_layout=True)
    for j,lab in enumerate(['benign','ransomware']):
        rs=[by_sha[m['sha256']] for m in manifest if m['label']==lab]
        rates=[sum(r['capabilities'][c]['state']=='S' for r in rs)/len(rs) for c in CAPS]
        ax.bar(x+(j-.5)*width,rates,width,label=('良性' if lab=='benign' else '勒索软件'),color=colors[lab])
    ax.set_xticks(x,CAP_LABELS,rotation=35,ha='right'); ax.set_ylim(0,1)
    ax.set_ylabel('记录支持率'); ax.set_title('按标签划分的能力证据支持率'); ax.legend(frameon=False); ax.grid(axis='y',alpha=.2)
    save(fig,'fig2_capability_support')
    # Figure 3: the cost is discrete, so show grouped proportions and counts.
    fragility={lab:[] for lab in ['benign','ransomware']}
    for lab in fragility:
        for m in manifest:
            if m['label']!=lab: continue
            r=by_sha[m['sha256']]
            for c in CAPS:
                pts=r.get('fragility_profile',{}).get(c,{}).get('pareto_minimal',[])
                if pts: fragility[lab].append(min(p['cost_vector'][0] for p in pts))
    costs=sorted({v for vals in fragility.values() for v in vals});x=np.arange(len(costs));width=.34
    fig,ax=plt.subplots(figsize=(8.1,4.6),constrained_layout=True)
    for j,lab in enumerate(['benign','ransomware']):
        vals=fragility[lab];total=len(vals);counts=[vals.count(cost) for cost in costs];rates=[n/total for n in counts]
        bars=ax.bar(x+(j-.5)*width,rates,width,label=f"{names[lab]}（n={total} 项主张）",color=colors[lab])
        for bar,count,rate in zip(bars,counts,rates):
            ax.text(bar.get_x()+bar.get_width()/2,bar.get_height()+.018,f"{count}/{total}\n{rate:.1%}",ha='center',va='bottom',fontsize=9)
    tick_labels=['1 个原子\n（丢失一个事件）','2 个原子\n（丢失两个事件）'] if costs==[1,2] else [str(c) for c in costs]
    ax.set_xticks(x,tick_labels);ax.set_ylim(0,.72);ax.yaxis.set_major_formatter(matplotlib.ticker.PercentFormatter(1.0,decimals=0))
    ax.set_ylabel('已计算主张画像占比');ax.set_xlabel('最小原子扰动成本（越低越脆弱）');ax.set_title('能力级证据脆弱性')
    ax.legend(frameon=False);ax.grid(axis='y',alpha=.22)
    save(fig,'fig3_fragility_cost')

if __name__=='__main__': main()


