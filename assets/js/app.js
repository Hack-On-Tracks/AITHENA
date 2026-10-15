const $=s=>document.querySelector(s),H3=3600e3;
let seed=11;const rnd=()=>(seed=(seed*16807)%2147483647)/2147483647,pick=a=>a[Math.floor(rnd()*a.length)];
const cl=(v,a=0,b=1)=>Math.min(b,Math.max(a,v));
// cyber city art (blue palette)
function pat(id,sd){let s=sd;const R=()=>(s=(s*16807)%2147483647)/2147483647;let r="";for(let i=0;i<3;i++)for(let j=0;j<4;j++)if(R()<.38)r+=`<rect x="${3+i*6}" y="${3+j*6}" width="3" height="3.6" fill="#a9c0e6" opacity="${.5+R()*.5}"/>`;return`<pattern id="${id}" width="18" height="24" patternUnits="userSpaceOnUse">${r}</pattern>`}
function city(a,b,h0,h1,fill,sd,skip){let s=sd;const R=()=>(s=(s*16807)%2147483647)/2147483647;let x=a,o="",i=0;while(x<b){const w=40+R()*70,h=h0+R()*(h1-h0),y=600-h;if(!skip||!(x>skip[0]&&x<skip[1])){o+=`<rect x="${x}" y="${y}" width="${w}" height="${h}" fill="${fill}"/><rect x="${x}" y="${y}" width="${w}" height="${h}" fill="url(#p${i%3})"/>`;if(R()>.7)o+=`<line x1="${x+w/2}" y1="${y}" x2="${x+w/2}" y2="${y-40}" stroke="${fill}" stroke-width="2"/><circle cx="${x+w/2}" cy="${y-42}" r="3" fill="#8fb0e8" class="bk"/>`;i++}x+=w+R()*6}return o}
const sign=(x,y,t)=>`<rect x="${x+20}" y="${y+36}" width="150" height="${600-y-36}" fill="#0f1a2e"/><rect x="${x}" y="${y}" width="190" height="46" fill="#131614" stroke="#768FB2" stroke-width="2"/><text x="${x+95}" y="${y+30}" text-anchor="middle" font-family="Space Mono,monospace" font-weight="700" font-size="20" fill="#8fb0e8" style="filter:drop-shadow(0 0 5px #8fb0e8)">${t}</text>`;
const defs=`<defs>${pat("p0",3)}${pat("p1",8)}${pat("p2",21)}</defs>`,vb=c=>`<svg viewBox="0 0 1600 600" preserveAspectRatio="xMidYMax slice">${defs}${c}</svg>`;
const A1=vb(city(0,1600,120,320,"#1d3359",5)),A2=vb(city(0,1600,170,400,"#14243D",12)+sign(250,170,"ZERO TRUST")+sign(1050,130,"TLS 1.3")+sign(640,200,"NO DECRYPT")),A3=vb(city(0,520,380,590,"#0c100f",31)+city(1080,1600,380,590,"#0c100f",47));
$("#l1").innerHTML=A1;$("#l2").innerHTML=A2;$("#l3").innerHTML=A3;
$("#r1").innerHTML="<div>"+A1+"</div>";$("#r2").innerHTML="<div>"+A2+"</div>";
$("#ring").innerHTML=`<svg viewBox="0 0 400 400" fill="none" stroke="#768FB2"><circle cx="200" cy="200" r="190" stroke-dasharray="2 8" opacity=".6"/><circle cx="200" cy="200" r="150" stroke-width="2" stroke-dasharray="60 20 10 20" opacity=".5"/><circle cx="200" cy="200" r="100" opacity=".4"/><path d="M200 5v30M200 365v30M5 200h30M365 200h30" stroke-width="2"/></svg>`;
$("#ds").innerHTML=Array.from({length:40},()=>`<i style="left:${rnd()*100}%;height:${60+rnd()*140}px;opacity:${.15+rnd()*.35};animation-duration:${3+rnd()*5}s;animation-delay:${-rnd()*8}s"></i>`).join("");
$("#pt").innerHTML=Array.from({length:36},()=>{const z=3+rnd()*7;return`<i style="left:${rnd()*100}%;width:${z}px;height:${rnd()>.5?z:z*3}px;--dx:${(rnd()-.5)*20}vw;animation-duration:${14+rnd()*20}s;animation-delay:${-rnd()*30}s"></i>`}).join("");
// title + shards
const ttl=$("#ttl");const TT=ttl&&TechText(ttl,{text:"LEAKLENS",fontFamily:'"Big Shoulders Display","Arial Narrow",Impact,sans-serif',fontWeight:600,fontSize:400,letterSpacing:.02,color:"#e8eef8",accentColor:"#8fb0e8",reveal:"letter",dashLength:4,dashGap:2,specks:15});

const SH=Array.from({length:38},()=>{const w=30+rnd()*90,i=document.createElement("i");i.style.width=w+"px";i.style.height=w*(.6+rnd()*.8)+"px";i.style.clipPath=`polygon(${Array.from({length:3+Math.floor(rnd()*2)},(_,k)=>`${Math.round(50+45*Math.cos(k*6.28/4+rnd()))}% ${Math.round(50+45*Math.sin(k*6.28/4+rnd()))}%`).join(",")})`;$("#sh").appendChild(i);return{el:i,v:[(rnd()-.5)*2.2,(rnd()-.7)*1.6,(rnd()-.5)*4]}});
// scroll camera
/* multi-page: each page owns one slice of the original scroll camera, so the city looks the same as at that point of the single-page version */
const PAGES=[["home","index.html","Home",0,.4],["dashboard","dashboard.html","Dashboard",.42,.5],["traffic","traffic.html","Traffic",.53,.6],["graph","graph.html","Graph",.65,.72],["alerts","alerts.html","Alerts",.77,.83],["incidents","incidents.html","Incidents",.88,.93],["dev","developer.html","Dev",.95,1]];
const PG=document.body.dataset.page||"home",PI=Math.max(0,PAGES.findIndex(x=>x[0]==PG)),[,,,C0,C1]=PAGES[PI],lk=$("#lk");
PAGES.forEach(([,h,x],i)=>{const a=document.createElement("a");a.textContent=x;a.href=h;if(i==PI){a.className="on";a.setAttribute("aria-current","page")}lk.appendChild(a)});
const pg=$("#pg");if(pg){const pv=PAGES[PI-1],nx=PAGES[PI+1];pg.innerHTML=(pv?`<a class="b" href="${pv[1]}">← ${pv[2]}</a>`:"")+(nx?`<a class="b p" href="${nx[1]}">${PI?nx[2]:"Enter "+nx[2]} →</a>`:"")}
let cur=C0,sy=0;const RV=[...document.querySelectorAll(".rv")],ZM=[["#l1","#r1",.8],["#l2","#r2",1.8],["#l3",null,5]];
function frame(){const mx=document.documentElement.scrollHeight-innerHeight,p=mx>0?cl(scrollY/mx):0;cur+=(C0+p*(C1-C0)-cur)*.09;sy+=(scrollY-sy)*.09;
ZM.forEach(([a,b,k])=>{const t=`scale(${1+cur*k})`;$(a).style.transform=t;if(b)$(b).style.transform=t});
$("#glow").style.opacity=.6+cur*.6;$("#ring").style.opacity=cl(1-cur*14);$("#bar").style.width=p*100+"%";
const s=PI?1:cl(sy/(innerHeight*.9)),W=innerWidth,Hh=innerHeight;
if(ttl){ttl.style.transform=`translateY(${-s*Hh*.3}px) scale(${1+s*.3})`;ttl.style.opacity=cl(1-s*1.4);
$("#hl").style.opacity=$("#hs").style.opacity=cl(1-s*4)}
SH.forEach(h=>{const e=h.el;e.style.transform=`translate(${h.v[0]*s*W*.6}px,${h.v[1]*s*Hh*.8+s*s*220}px) rotate(${h.v[2]*s*360}deg) scale(${.4+s*1.3})`;e.style.opacity=cl(s*14)*cl(1-(s-.5)*2)});
RV.forEach(e=>{const r=e.getBoundingClientRect(),d=Math.abs(r.top+r.height/2-Hh*.5)/(Hh*.5),o=cl(1.7-d*1.5);e.style.opacity=o;e.style.transform=`translateY(${(1-o)*36}px)`});
S.forEach(q=>{if(!q.el)return;q.d+=(q.v-q.d)*.12;q.el.textContent=Math.round(q.d).toLocaleString()});float();requestAnimationFrame(frame)}
// data
const D=["LAP-DEV-07","LAP-FIN-02","PC-HR-11","SRV-BUILD-01"],T=["drive.google.com","slack.com","corp-vpn.internal","github.com","files.mega.nz","transfer.sh","45.77.12.9"],BAD=["files.mega.nz","transfer.sh","45.77.12.9"];
const L={normal:"Normal",suspicious:"Suspicious",high:"High-risk"},bg=r=>`<span class="bg ${r}">${L[r]}</span>`;let n=100,total=12480;
function mk(ts){const t=pick(T),bad=BAD.includes(t),mb=bad&&rnd()>.35?Math.round(300+rnd()*1700):Math.round(1+rnd()*60);return{id:"E"+n++,ts,d:pick(D),t,mb,dur:Math.round(5+rnd()*600),risk:bad&&mb>1000?"high":bad&&mb>200?"suspicious":"normal"}}
/* shared state between pages (sessionStorage, per browser tab) */
const SK="leaklens-state",ST=(()=>{try{return JSON.parse(sessionStorage.getItem(SK))}catch(e){return null}})();
const ev=[];if(ST){ev.push(...ST.ev);n=ST.n;total=ST.total;seed=ST.seed}else{for(let i=0;i<40;i++)ev.push(mk(Date.now()-rnd()*24*H3));ev.sort((a,b)=>b.ts-a.ts)}
const age=e=>(Date.now()-e.ts)/H3,fa=e=>{const h=age(e);return h<1/60?"just now":h<1?Math.round(h*60)+" min ago":h.toFixed(1)+" h ago"};
const S=[0,1,2,3].map(k=>({el:$("#n"+k),d:0,v:0}));
function dash(){if(!$("#ch"))return;const sus=ev.filter(e=>e.risk!="normal"),hi=ev.filter(e=>e.risk=="high");S[0].v=total;S[1].v=sus.length;S[2].v=hi.length;S[3].v=Math.max(1,Math.ceil(hi.length/2));
const b=Array(24).fill(0),r=Array(24).fill(0);ev.forEach(e=>{const k=Math.min(23,Math.floor(age(e)));b[23-k]++;if(e.risk!="normal")r[23-k]++});const mx=Math.max(...b,1);
$("#ch").innerHTML=b.map((v,i)=>{const h=v/mx*140,s=r[i]/mx*140;return`<rect x="${i*25+3}" y="${150-h}" width="19" height="${h}" rx="3" fill="#8fb0e8" opacity=".55"/><rect x="${i*25+3}" y="${150-s}" width="19" height="${s}" rx="3" fill="#ff5a6e"/>`}).join("")+`<text x="0" y="167" font-size="10" fill="#9fb2cf">24 h ago</text><text x="600" y="167" font-size="10" text-anchor="end" fill="#9fb2cf">now</text>`;
$("#rc").innerHTML=sus.slice(0,5).map(e=>`<div><span>${e.d} → ${e.t}<br><small style="color:var(--mu)">${e.mb} MB · ${fa(e)}</small></span>${bg(e.risk)}</div>`).join("")}
function tbl(fresh){if(!$("#rw"))return;const q=$("#q").value.toLowerCase(),r=$("#rkf").value,t=+$("#tm").value,f=ev.filter(e=>age(e)<=t&&(!r||e.risk==r)&&(e.d+e.t).toLowerCase().includes(q));
$("#rw").innerHTML=f.slice(0,30).map(e=>`<tr class="${e.risk} ${e.id==fresh?"new":""}"><td>${fa(e)}</td><td>${e.d}</td><td>${e.t}</td><td>${e.mb} MB</td><td>${Math.floor(e.dur/60)}m ${e.dur%60}s</td><td>${bg(e.risk)}</td></tr>`).join("")||`<tr><td colspan="6">No matching events</td></tr>`;$("#cn").textContent=f.length+" events match"}
["#q","#rkf","#tm"].forEach(s=>$(s)&&$(s).addEventListener("input",()=>tbl()));
const col={device:"#5b8cff",event:"#dbe6f7",dest:"#3ee08f",alert:"#ff5a6e",incident:"#9db6dc"};let N=[],E=[],sel=null,gl=[];
function gbuild(){if(!$("#g"))return;const w=+$("#ts").value;$("#tl").textContent=w+" h";N=[];E=[];
D.forEach((d,i)=>N.push({id:d,k:"device",x:60,y:60+i*95,i:{Type:"Device",Flows:ev.filter(e=>e.d==d).length}}));
T.forEach((d,i)=>N.push({id:d,k:"dest",x:580,y:30+i*57,i:{Type:"External destination",Used_by:new Set(ev.filter(e=>e.t==d).map(e=>e.d)).size+" device(s)"}}));
const se=ev.filter(e=>e.risk!="normal"&&age(e)<=w).slice(0,6);
se.forEach((e,i)=>{N.push({id:e.id,k:"event",x:230,y:45+i*60,i:{Type:"Network event",Sent:e.mb+" MB",Risk:L[e.risk],When:fa(e)}});E.push([e.d,e.id]);E.push([e.id,e.t])});
const hs=se.filter(e=>e.risk=="high").slice(0,2);
hs.forEach((e,i)=>{N.push({id:"ALERT-"+(i+1),k:"alert",x:410,y:100+i*140,i:{Type:"Security alert",Why:"Large upload to rare destination",Device:e.d,Volume:e.mb+" MB"}});E.push([e.id,"ALERT-"+(i+1)])});
if(hs.length){N.push({id:"INC-001",k:"incident",x:500,y:200,i:{Type:"Incident",Status:"Open",Summary:"Possible exfiltration via "+hs[0].t}});E.push(["ALERT-1","INC-001"]);if(hs[1])E.push(["ALERT-2","INC-001"])}
const p=id=>N.find(n=>n.id==id);E=E.filter(e=>p(e[0])&&p(e[1]));
$("#g").innerHTML=E.map(()=>`<line class="edge bad"/>`).join("")+N.map(n=>`<g class="node"><circle class="${n.k=="alert"?"pulse":""}" cx="${n.x}" cy="${n.y}" r="${n.k=="event"?8:14}" fill="${col[n.k]}"/><text x="${n.x}" y="${n.y+(n.k=="event"?21:29)}">${n.id}</text></g>`).join("");
gl=[...$("#g").querySelectorAll("line")];[...$("#g").querySelectorAll(".node")].forEach((g,i)=>{const nd=N[i];nd.el=g;nd.ph=i*1.7;g.onclick=()=>pickN(nd)});if(sel&&p(sel))pickN(p(sel))}
function pickN(nd){sel=nd.id;const rel=new Set([nd.id]);E.forEach(e=>{if(e[0]==nd.id)rel.add(e[1]);if(e[1]==nd.id)rel.add(e[0])});N.forEach(n=>n.el.style.opacity=rel.has(n.id)?1:.25);
$("#dt").innerHTML=`<h3>${nd.id}</h3><dl>${Object.entries(nd.i).map(([k,v])=>`<dt>${k.replace("_"," ")}</dt><dd>${v}</dd>`).join("")}<dt>Connected to</dt><dd>${[...rel].filter(x=>x!=nd.id).join(", ")||"nothing"}</dd></dl>`}
function float(){const t=performance.now()/1000;N.forEach(n=>{if(!n.el)return;n.cx=Math.sin(t+n.ph)*5;n.cy=Math.cos(t*.8+n.ph)*5;n.el.setAttribute("transform",`translate(${n.cx},${n.cy})`)});
const p=id=>N.find(n=>n.id==id);E.forEach((e,i)=>{const a=p(e[0]),b=p(e[1]),l=gl[i];if(!l||!a||!b||a.cx===undefined)return;l.setAttribute("x1",a.x+a.cx);l.setAttribute("y1",a.y+a.cy);l.setAttribute("x2",b.x+b.cx);l.setAttribute("y2",b.y+b.cy)})}
if($("#ts"))$("#ts").addEventListener("input",gbuild);
function toast(m){const t=$("#toast");t.textContent=m;t.classList.add("on");clearTimeout(toast.h);toast.h=setTimeout(()=>t.classList.remove("on"),4000)}
setInterval(()=>{const e=mk(Date.now());if(rnd()>.55&&e.risk=="normal"){e.t=pick(BAD);e.mb=Math.round(400+rnd()*1600);e.risk=e.mb>1000?"high":"suspicious"}
ev.unshift(e);total+=Math.round(40+rnd()*60);dash();tbl(e.id);tickOps();if(e.risk!="normal")gbuild();if(e.risk=="high")toast(`🚨 HIGH-RISK · ${e.d} → ${e.t} · ${e.mb} MB`);save()},2800);
/* ===== Alerts, Incidents, Developer console ===== */
const REV=["Anika Rao (SOC lead)","Dev Mehta (Analyst)","Sameera K. (Reviewer)"],STS=["New","Under Investigation","Resolved"];
const X=s=>String(s).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const INC={},ALW=new Set(),FPS=new Set();let selA=null,selI=null,TH=40,incN=1000;
const tm=ts=>new Date(ts).toLocaleString([],{day:"numeric",month:"short",hour:"2-digit",minute:"2-digit"});
function feat(e){const h=new Date(e.ts).getHours(),mpm=e.mb/(e.dur/60);return{bytes_out_mb:e.mb,duration_s:e.dur,mb_per_min:+mpm.toFixed(1),volume_zscore:+((e.mb-18)/22).toFixed(2),off_hours:+(h<6||h>=22),rare_destination:+BAD.includes(e.t),hour_of_day:h}}
function score(e){const f=feat(e),an=1-Math.exp(-Math.max(0,f.volume_zscore)/25),w={volume:.55*an,destination:.25*f.rare_destination,timing:.1*f.off_hours,rate:.1*Math.min(1,f.mb_per_min/60)};return{f,an:+an.toFixed(3),w,risk:Math.round(100*Object.values(w).reduce((a,b)=>a+b,0))}}
function why(e,s){const f=s.f,r=[];if(f.volume_zscore>3)r.push([`Upload of ${e.mb} MB is ${f.volume_zscore}σ above this device's usual 18 MB`,s.w.volume]);if(f.rare_destination)r.push([`${e.t} is a file-sharing or unrecognised external destination`,s.w.destination]);if(f.off_hours)r.push([`Transfer at ${f.hour_of_day}:00, outside working hours`,s.w.timing]);if(f.mb_per_min>20)r.push([`Sustained rate of ${f.mb_per_min} MB/min`,s.w.rate]);return r}
const related=e=>ev.filter(x=>x!==e&&(x.d==e.d||x.t==e.t)&&Math.abs(x.ts-e.ts)<24*H3).sort((a,b)=>Math.abs(a.ts-e.ts)-Math.abs(b.ts-e.ts)).slice(0,5);
function alerts(all){return ev.filter(e=>e.risk!="normal").map(e=>{const s=score(e);return{id:"ALT-"+e.id.slice(1),e,s,sev:e.risk=="high"?"High":"Medium",why:why(e,s)}}).filter(a=>all||(!ALW.has(a.e.t)&&!FPS.has(a.id)&&a.s.risk>=TH))}
const A=id=>alerts().find(a=>a.id==id)||(INC[id]&&INC[id].a);
const logAdd=(i,m)=>i.log.unshift([Date.now(),m]);
function mkInc(a){if(!INC[a.id])INC[a.id]={id:"INC-"+(++incN),a,status:"New",who:"Unassigned",notes:0,esc:false,log:[[Date.now(),"Incident created from "+a.id]]};return INC[a.id]}
function openInc(a){selI=mkInc(a).a.id;save();location.href="incidents.html"}
/* alerts page */
function rAl(){if(!$("#alist"))return;const q=$("#aq").value.toLowerCase(),sv=$("#asv").value,L=alerts().filter(a=>(!sv||a.sev==sv)&&(a.e.d+a.e.t+a.id).toLowerCase().includes(q));
if(!selA||!L.find(a=>a.id==selA))selA=L[0]&&L[0].id;
$("#alist").innerHTML=L.map(a=>`<tr data-a="${a.id}" tabindex="0" class="${a.e.risk}${a.id==selA?" sel":""}"><td>${a.id}</td><td>${tm(a.e.ts)}</td><td>${a.e.d} → ${a.e.t}</td><td>${a.s.risk}</td><td>${a.sev}</td></tr>`).join("")||`<tr><td colspan="5">No alerts match. Clear the filters or lower the threshold in the Dev console.</td></tr>`}
function rAd(){const a=A(selA),el=$("#adet");if(!el)return;if(!a){el.innerHTML="<h3>Alert details</h3><p style='margin:0;color:var(--mu)'>Select an alert to see why it was flagged.</p>";return}
const inc=INC[a.id];el.innerHTML=`<h3>${a.id}</h3><p style="margin:0 0 8px;color:var(--mu)">${tm(a.e.ts)}</p>
<div style="display:flex;align-items:center;gap:12px"><span class="hd" style="font-size:52px;font-weight:800;line-height:1">${a.s.risk}</span><div style="flex:1"><div class="mt"><i style="width:${a.s.risk}%"></i></div><span class="bg ${a.e.risk}" style="display:inline-block;margin-top:6px">${a.sev} severity</span></div></div>
<p><strong>Device</strong> ${a.e.d}<br><strong>Destination</strong> ${a.e.t}<br><strong>Sent</strong> ${a.e.mb} MB over ${a.e.dur}s</p>
<h3>Why it was flagged</h3><ul class="rs">${a.why.map(r=>`<li>${X(r[0])}</li>`).join("")}</ul>
<h3>Related events</h3>${related(a.e).map(x=>`<div><span class="ch">${x.id}</span> ${x.d} → ${x.t}, ${x.mb} MB, ${fa(x)}</div>`).join("")||"<span style='color:var(--mu)'>None in the last 24 h.</span>"}
<p style="margin:14px 0 0"><button class="b p" id="aopen">${inc?"Open "+inc.id:"Open investigation"}</button></p>`;$("#aopen").onclick=()=>openInc(a)}
/* incidents page */
function rIl(){if(!$("#ilist"))return;const all=Object.values(INC),sh=$("#ires").checked,L=all.filter(i=>sh||i.status!="Resolved").sort((a,b)=>b.esc-a.esc||STS.indexOf(a.status)-STS.indexOf(b.status)||b.a.s.risk-a.a.s.risk);
$("#icount").textContent=all.filter(i=>i.status!="Resolved").length+" open of "+all.length;
if(!selI||!INC[selI])selI=L[0]&&L[0].a.id;
$("#ilist").innerHTML=L.map(i=>`<button class="il${i.a.id==selI?" sel":""}" data-i="${i.a.id}"><strong>${i.id}</strong> ${i.esc?"<span class='bg high'>Escalated</span> ":""}<span class="bg ${i.status=="Resolved"?"normal":i.status=="New"?"high":"suspicious"}">${i.status}</span><br><small>${i.a.e.d} → ${i.a.e.t} · risk ${i.a.s.risk} · ${X(i.who)}</small></button>`).join("")||"<p style='color:var(--mu);margin:8px'>No open incidents. Open one from an alert.</p>"}
function rId(){const i=INC[selI],el=$("#idet");if(!el)return;if(!i){el.innerHTML="<h3>Incident details</h3><p style='margin:0;color:var(--mu)'>Select an incident, or open one from the Alerts page.</p>";return}
const a=i.a;el.innerHTML=`<h3>${i.id} · from ${a.id}</h3><p style="margin:0 0 8px">Possible exfiltration from ${a.e.d} to ${a.e.t}: ${a.e.mb} MB, risk ${a.s.risk}.${i.esc?" <span class='bg high'>Escalated to CISO</span>":""}</p>
<h3>Supporting evidence</h3><ul class="rs">${a.why.map(r=>`<li>${X(r[0])}</li>`).join("")}</ul><div>${related(a.e).map(x=>`<span class="ch" title="${x.d} → ${x.t}, ${x.mb} MB">${x.id}</span>`).join("")}</div>
<p style="color:var(--mu);font-size:12px;margin:6px 0">Repeated or large transfers alone do not prove theft. Review the context before deciding.</p>
<label class="sl" for="iwho">Assigned reviewer <select id="iwho"><option>Unassigned</option>${REV.map(r=>`<option${r==i.who?" selected":""}>${r}</option>`).join("")}</select></label>
<div class="bar" style="margin:10px 0">${STS.map(s=>`<button class="b${s==i.status?" on":""}" data-st="${s}">${s}</button>`).join("")}<button class="b" id="iesc"${i.esc||i.status=="Resolved"?" disabled":""}>Escalate</button></div>
<textarea id="inote" rows="2" placeholder="What did you check or decide?" aria-label="Investigation note"></textarea> <button class="b p" id="isv" style="margin-top:6px">Save note</button>
<h3 style="margin-top:12px">Activity</h3><div style="max-height:130px;overflow:auto;font-size:13px">${i.log.map(l=>`<div><span style="color:var(--mu)">${tm(l[0])}</span> ${X(l[1])}</div>`).join("")}</div>`}
/* developer console */
const perr=()=>ev.filter(e=>+e.id.slice(1)%7==0||+e.id.slice(1)%11==0).slice(0,6).map(e=>+e.id.slice(1)%11==0?["ERROR",e.id,"flow dropped: duration_s below parser minimum, event not scored"]:["WARN",e.id,"TLS SNI missing, fell back to destination IP for reputation lookup"]);
function rD(){if(!$("#dev"))return;const L=alerts(),a=A(selA),ds=$("#dsel");if(document.activeElement!==ds)ds.innerHTML=L.map(x=>`<option value="${x.id}"${x.id==selA?" selected":""}>${x.id} · ${x.e.d} → ${x.e.t}</option>`).join("")||"<option>No alerts</option>";
const fp=alerts(true).length,er=perr();
let h=`<div class="pd"><h3>Detection settings</h3><label class="sl" for="dth">Alert threshold <input type="range" id="dth" min="20" max="90" value="${TH}"><strong id="dtv">${TH}</strong></label><p style="margin:8px 0 0;font-size:13px;color:var(--mu)">${L.length} of ${fp} flagged events fire at this threshold. ${FPS.size} marked false positive, ${ALW.size} destinations allowlisted.</p></div>
<div class="pd"><h3>Pipeline errors</h3>${er.map(x=>`<div style="font-size:12px"><span class="bg ${x[0]=="ERROR"?"high":"suspicious"}">${x[0]}</span> <span class="ch">${x[1]}</span> ${x[2]}</div>`).join("")||"No errors in the current window."}<p style="margin:8px 0 0;font-size:12px;color:var(--mu)">${ev.filter(e=>+e.id.slice(1)%7==0||+e.id.slice(1)%11==0).length} of ${ev.length} events had parse issues.</p></div>`;
if(a){const s=a.s,fire=s.risk>=TH;h+=`<div class="pd"><h3>Model scores · ${a.id}</h3><table><tr><td>Anomaly score</td><td>${s.an}</td></tr><tr><td>Risk score</td><td>${s.risk}</td></tr><tr><td>Threshold</td><td>${TH}</td></tr><tr><td>Decision</td><td><span class="bg ${fire?"high":"normal"}">${fire?"Alert fired":"Suppressed"}</span></td></tr></table></div>
<div class="pd"><h3>Processed features</h3><pre>${X(JSON.stringify(s.f,null,2))}</pre></div>
<div class="pd"><h3>Detection reasons and weights</h3>${a.why.map(r=>`<div style="font-size:13px">${X(r[0])}<div class="mt"><i style="width:${Math.min(100,r[1]*100/.55)}%"></i></div><small style="color:var(--mu)">contributes ${Math.round(r[1]*100)} points</small></div>`).join("")}</div>
<div class="pd"><h3>Related event IDs</h3>${[a.e,...related(a.e)].map(x=>`<span class="ch">${x.id}</span>`).join("")}</div>
<div class="pd"><h3>False-positive tools</h3><div class="bar"><button class="b" id="dfp">Mark ${a.id} as false positive</button><button class="b" id="dal">Allowlist ${a.e.t}</button></div>
<p style="font-size:12px;color:var(--mu);margin:4px 0">Marked: ${[...FPS].map(x=>`<button class="b" data-rs="${x}">${x} ✕</button>`).join(" ")||"none"}<br>Allowlisted: ${[...ALW].map(x=>`<button class="b" data-ra="${x}">${x} ✕</button>`).join(" ")||"none"}</p></div>`}
else h+=`<div class="pd"><h3>Inspector</h3>No alert selected. Lower the threshold or restore a suppressed alert.</div>`;
$("#dev").innerHTML=h}
function tickOps(){rAl();rIl();if(document.activeElement!==$("#dsel")&&document.activeElement!==$("#dth"))rD()}
function pickA(id){selA=id;rAl();rAd();rD()}
document.addEventListener("click",e=>{const t=e.target,r=t.closest("[data-a]"),il=t.closest("[data-i]"),st=t.closest("[data-st]"),i=INC[selI];
if(r)pickA(r.dataset.a);else if(il){selI=il.dataset.i;rIl();rId()}
else if(st&&i){i.status=st.dataset.st;logAdd(i,"Status changed to "+i.status);rIl();rId()}
else if(t.id=="iesc"&&i){i.esc=true;logAdd(i,"Escalated to CISO with evidence attached");toast("Escalated "+i.id);rIl();rId()}
else if(t.id=="isv"&&i){const v=$("#inote").value.trim();if(v){logAdd(i,"Note: "+v);rId()}else toast("Write a note before saving")}
else if(t.id=="dfp"){const a=A(selA);if(a){FPS.add(a.id);const n=INC[a.id];if(n){n.status="Resolved";logAdd(n,"Closed as false positive")}toast(a.id+" marked false positive");selA=null;rAl();rAd();rIl();rId();rD()}}
else if(t.id=="dal"){const a=A(selA);if(a){ALW.add(a.e.t);toast(a.e.t+" allowlisted");selA=null;rAl();rAd();rD()}}
else if(t.dataset.rs){FPS.delete(t.dataset.rs);rAl();rAd();rD()}else if(t.dataset.ra){ALW.delete(t.dataset.ra);rAl();rAd();rD()}});
document.addEventListener("keydown",e=>{if(e.key=="Enter"&&e.target.dataset&&e.target.dataset.a)pickA(e.target.dataset.a)});
document.addEventListener("change",e=>{const t=e.target;if(t.id=="iwho"&&INC[selI]){INC[selI].who=t.value;logAdd(INC[selI],"Assigned to "+t.value);rIl();rId()}
else if(t.id=="dsel")pickA(t.value);else if(t.id=="ires")rIl();else if(t.id=="asv")rAl()});
document.addEventListener("input",e=>{const t=e.target;if(t.id=="aq")rAl();else if(t.id=="dth"){TH=+t.value;$("#dtv").textContent=TH;rAl();rAd()}});
function save(){try{sessionStorage.setItem(SK,JSON.stringify({ev,n,total,seed,INC,ALW:[...ALW],FPS:[...FPS],TH,incN,selA,selI}))}catch(e){}}
function initOps(){if(ST){Object.assign(INC,ST.INC);Object.values(INC).forEach(i=>i.a.e=ev.find(e=>e.id==i.a.e.id)||i.a.e);ST.ALW.forEach(x=>ALW.add(x));ST.FPS.forEach(x=>FPS.add(x));TH=ST.TH;incN=ST.incN;selA=ST.selA;selI=ST.selI;rAl();rAd();rIl();rId();rD();return}
const hi=alerts().filter(a=>a.e.risk=="high").slice(0,2);hi.forEach((a,k)=>{const i=mkInc(a);if(k){i.status="Under Investigation";i.who=REV[1];logAdd(i,"Assigned to "+REV[1])}});
if(hi[0])selI=hi[0].id;rAl();rAd();rIl();rId();rD()}
dash();tbl();gbuild();initOps();save();frame();if (typeof lldrDeviceUI !== 'undefined') lldrDeviceUI.init();
addEventListener("pagehide",save);["click","change","input"].forEach(t=>document.addEventListener(t,save));
