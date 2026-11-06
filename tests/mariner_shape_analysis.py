# SPDX-License-Identifier: MIT-0
"""Offline finite-sample Mariner experiments; requires numpy2.3.4/sklearn1.7.2.

No keys, graph descriptions, packet IDs or capture names enter the learners.
Public capture files are read as data only and are never replayed.
"""
import base64
import hashlib
import json
import math
from pathlib import Path
import sys
import warnings

import numpy as np
from sklearn.ensemble import ExtraTreesClassifier
from sklearn.exceptions import ConvergenceWarning
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, roc_auc_score
from sklearn.neural_network import MLPClassifier
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

warnings.filterwarnings('ignore',category=ConvergenceWarning)
root=Path(sys.argv[1]);result={'environment':{'numpy':np.__version__,'sklearn':__import__('sklearn').__version__},'shape':[],'family':[],'notes':['Research learners are finite and not an optimal-observer or security test.','Density18, wire length512, direction0 and equal session sample counts for password classification.','Public reference captures are small, capture-held-out rather than a representative production mix.','False-positive target is 1%; sample counts do not support 1e-4 FPR certification.']}


def interval(k,n):
    if not n:return [0.,1.]
    z=1.96;p=k/n;d=1+z*z/n;center=(p+z*z/(2*n))/d;radius=z*math.sqrt((p*(1-p)+z*z/(4*n))/n)/d
    return [max(0,center-radius),min(1,center+radius)]


def save():
    (root/'shape-analysis.json').write_text(json.dumps(result,indent=2)+'\n')


data={}
with (root/'shape.jsonl').open() as f:
    for line in f:
        row=json.loads(line);key=(row['mode'],row['password_id'],row['session'])
        data.setdefault(key,[]).append(base64.b64decode(row['wire']))


def features(payloads,kind):
    if kind=='histogram':return np.asarray([np.bincount(np.frombuffer(p,np.uint8),minlength=256)/len(p) for p in payloads],dtype=np.float32)
    if kind=='length':return np.asarray([[len(p)/1232] for p in payloads],dtype=np.float32)
    # Pad to512 for matched-length family data; use full512 bytes for shape.
    return np.asarray([np.frombuffer((p+bytes(512))[:512],np.uint8) for p in payloads],dtype=np.float32)/127.5-1


def shape_matrix(mode,sessions,kind,window):
    xs=[];ys=[]
    for password in range(4):
        for session in sessions:
            raw=features(data[(mode,password,session)],kind)
            for pos in range(0,len(raw)-window+1,window):
                block=raw[pos:pos+window]
                xs.append(block.mean(axis=0) if kind=='histogram' else block.reshape(-1));ys.append(password)
    return np.asarray(xs),np.asarray(ys)


for mode in sorted({k[0] for k in data}):
    for window in (1,8):
        for kind in ('histogram','raw-mlp'):
            x,y=shape_matrix(mode,(0,1),kind,window);xt,yt=shape_matrix(mode,(3,),kind,window)
            if kind=='histogram':model=make_pipeline(StandardScaler(),LogisticRegression(C=.1,max_iter=200,random_state=42))
            else:model=MLPClassifier(hidden_layer_sizes=(64,32),max_iter=40,batch_size=128,alpha=.1,random_state=42,tol=0)
            model.fit(x,y);pred=model.predict(xt);correct=int((pred==yt).sum())
            result['shape'].append({'mode':mode,'window_packets':window,'features':kind,'train_n':len(y),'test_n':len(yt),'train_accuracy':float(accuracy_score(y,model.predict(x))),'test_accuracy':correct/len(yt),'test_wilson95':interval(correct,len(yt)),'chance':.25,'train_sessions':[0,1],'unused_session':2,'test_sessions':[3]});save()
            print('shape',mode,window,kind,correct/len(yt),flush=True)


# Unseen-password discrimination against exact same-length random / AEAD controls.
for control in ('random','random-padding','raw-aead'):
    for kind in ('histogram','raw-mlp'):
        train=[];labels=[];test=[];test_labels=[]
        for password in range(12):
            for label,mode in [(1,'mixed'),(0,control)]:
                destination=train if password<6 else test;target=labels if password<6 else test_labels
                rows=data[(mode,password,0 if password<6 else 3)][:128]
                destination.extend(rows);target.extend([label]*len(rows))
        x,y=features(train,kind),np.asarray(labels);xt,yt=features(test,kind),np.asarray(test_labels)
        model=make_pipeline(StandardScaler(),LogisticRegression(C=.1,max_iter=200)) if kind=='histogram' else MLPClassifier(hidden_layer_sizes=(64,32),max_iter=40,alpha=.1,random_state=42,tol=0)
        model.fit(x,y);scores=model.predict_proba(xt)[:,1];pred=scores>=.5
        result.setdefault('same_length_controls',[]).append({'control':control,'features':kind,'train_passwords':list(range(6)),'test_passwords':list(range(6,12)),'train_n':len(y),'test_n':len(yt),'accuracy':float(accuracy_score(yt,pred)),'auc':float(roc_auc_score(yt,scores))});save()


controls=[json.loads(line) for line in (root/'other-udp.jsonl').read_text().splitlines()]
control_payloads=[base64.b64decode(x['wire']) for x in controls]
positive=[json.loads(line) for line in (root/'family.jsonl').read_text().splitlines()]
train_sources={'dns.cap','sip-rtp-g711.pcap','quic-fragmented-handshakes.pcapng.gz'}
val_sources={'sip-rtp-g722.pcap','quic-double-retry.pcapng.gz'}
test_sources={x['source'] for x in controls}-train_sources-val_sources
part=lambda source:0 if source in train_sources else 1 if source in val_sources else 2
datasets=[([],[],[]) for _ in range(3)]
for row,payload in zip(controls,control_payloads):
    index=part(row['source']);datasets[index][0].append(payload);datasets[index][1].append(0);datasets[index][2].append(row['source'])
for row in positive:
    password=row['password_id'];index=0 if password<6 else 1 if password<9 else 2
    if part(row['source'])!=index:continue
    datasets[index][0].append(base64.b64decode(row['wire']));datasets[index][1].append(1);datasets[index][2].append(row['source'])

for kind in ('length','histogram','raw-bytes'):
    x,y=features(datasets[0][0],kind),np.asarray(datasets[0][1]);xv,yv=features(datasets[1][0],kind),np.asarray(datasets[1][1]);xt,yt=features(datasets[2][0],kind),np.asarray(datasets[2][1])
    # A nonlinear raw-byte tree learner also sees conjunctions of positions.
    model=ExtraTreesClassifier(n_estimators=128,min_samples_leaf=3,max_features=.5,class_weight='balanced',random_state=42,n_jobs=1)
    model.fit(x,y);validation=model.predict_proba(xv)[:,1];scores=model.predict_proba(xt)[:,1]
    negatives=np.sort(validation[yv==0]);threshold=float(negatives[max(0,math.ceil(.99*len(negatives))-1)])
    pred=scores>threshold;negative=yt==0;positive_mask=yt==1;fp=int(pred[negative].sum());tp=int(pred[positive_mask].sum());nneg=int(negative.sum());npos=int(positive_mask.sum())
    row={'features':kind,'learner':'ExtraTrees128','train_passwords':list(range(6)),'validation_passwords':[6,7,8],'test_passwords':[9,10,11],'train_capture_files':sorted(train_sources),'validation_capture_files':sorted(val_sources),'test_capture_files':sorted(test_sources),'train_n':len(y),'validation_negatives':len(negatives),'test_negatives':nneg,'test_positives':npos,'calibration_target_fpr':.01,'threshold_strict_greater':threshold,'test_false_positives':fp,'test_fpr':fp/nneg,'test_fpr_wilson95':interval(fp,nneg),'test_tpr':tp/npos,'test_tpr_wilson95':interval(tp,npos),'auc':float(roc_auc_score(yt,scores)),'by_capture':{}}
    for source in sorted(test_sources):
        selected=negative&np.asarray([s==source for s in datasets[2][2]]);count=int(selected.sum());row['by_capture'][source]={'negative_samples':count,'false_positives':int(pred[selected].sum())}
    result['family'].append(row);save();print('family',kind,'FPR',row['test_fpr'],'TPR',row['test_tpr'],flush=True)

result['input_sha256']={name:hashlib.sha256((root/name).read_bytes()).hexdigest() for name in ('shape.jsonl','other-udp.jsonl','family.jsonl')};save()
