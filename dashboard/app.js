(function(){
"use strict";

// ── helpers ──
function g(id){return document.getElementById(id);}
function txt(id,v){var e=g(id);if(e)e.textContent=v;}
function htm(id,v){var e=g(id);if(e)e.innerHTML=v;}
function wd(id,p){var e=g(id);if(e)e.style.width=p+"%";}

// ── nav ──
var NAV_PAGES=["dashboard","cmdcentre","history","settings"];
var TITLES={dashboard:"API Fuzzing Dashboard",cmdcentre:"Command Centre",history:"Fuzzing Test History",settings:"Engine Config"};
function showPage(key){
  NAV_PAGES.forEach(function(p){
    var pg=g("page-"+p); if(pg){pg.classList.remove("active");}
    var lk=g("nav-"+p);  if(lk){lk.className="nav-link"+(p===key?(key==="cmdcentre"?" active-purple":" active-amber"):"");}
  });
  var pg=g("page-"+key); if(pg) pg.classList.add("active");
  txt("page-title",TITLES[key]||"");
}
NAV_PAGES.forEach(function(p){
  var lk=g("nav-"+p);
  if(lk) lk.addEventListener("click",function(e){e.preventDefault();showPage(p);});
});

// ── slider ──
var slider=g("conc-slider");
if(slider) slider.addEventListener("input",function(){txt("conc-display",this.value+" threads");});

// ── strategies ──
var S=[
  {lbl:"Malformed JSON: trailing comma",   code:400,mn:12,  mx:25,  cat:"malformed",pay:'{"username":"alice","age":30,}'},
  {lbl:"Malformed JSON: missing brace",    code:400,mn:10,  mx:18,  cat:"malformed",pay:'{"username":"alice","age":30'},
  {lbl:"Malformed JSON: missing separator",code:400,mn:15,  mx:22,  cat:"malformed",pay:'{"username":"alice" "age":30}'},
  {lbl:"Malformed JSON: extra junk bytes", code:400,mn:18,  mx:30,  cat:"malformed",pay:'{"username":"alice","age":30}JUNK'},
  {lbl:"Baseline validation check",        code:200,mn:35,  mx:50,  cat:"success",  pay:{username:"alice",age:30,is_active:true}},
  {lbl:"Empty body fallback",              code:200,mn:32,  mx:45,  cat:"success",  pay:{}},
  {lbl:"Type swap: username → integer",    code:422,mn:22,  mx:40,  cat:"types",    pay:{username:12345,age:30,is_active:true}},
  {lbl:"Type swap: age → boolean",         code:422,mn:20,  mx:38,  cat:"types",    pay:{username:"alice",age:true,is_active:true}},
  {lbl:"Type swap: age → list",            code:422,mn:25,  mx:42,  cat:"types",    pay:{username:"alice",age:[],is_active:true}},
  {lbl:"Type swap: is_active → string",    code:422,mn:21,  mx:35,  cat:"types",    pay:{username:"alice",age:30,is_active:"bad_type"}},
  {lbl:"Overflow: username >5000 chars",   code:500,mn:90,  mx:140, cat:"overflow", msg:"DB Column Overflow",           pay:{username:"A".repeat(60)+"…(6000)",age:30,is_active:true}},
  {lbl:"Overflow: age → 1.79e308",         code:500,mn:85,  mx:130, cat:"overflow", msg:"Arithmetic Error: Float limit",pay:{username:"alice",age:1.79e308,is_active:true}},
  {lbl:"Traversal: ../../etc/passwd",      code:500,mn:110, mx:180, cat:"overflow", msg:"Security Filter Exception",    pay:{username:"../../etc/passwd",age:30,is_active:true}},
  {lbl:"Timeout: age = -1",               code:408,mn:5000,mx:5000,cat:"timeouts", msg:"Read Timeout (5.0s)",          pay:{username:"alice",age:-1,is_active:true}},
  {lbl:"Timeout: age = -2147483648",      code:408,mn:5000,mx:5000,cat:"timeouts", msg:"Read Timeout (5.0s)",          pay:{username:"alice",age:-2147483648,is_active:true}}
];

// ── state ──
var records=[], lastOk={username:"alice",age:30,is_active:true};
var fuzzing=false, timer=null, total=0, failed=0, lats=[];
var MAX=52;

// ── chart ──
var chart=null;
var cv=g("latency-chart");
if(cv&&window.Chart){
  var ctx=cv.getContext("2d");
  var gr=ctx.createLinearGradient(0,0,0,200);
  gr.addColorStop(0,"rgba(245,158,11,.22)"); gr.addColorStop(1,"rgba(245,158,11,0)");
  chart=new Chart(ctx,{
    type:"line",
    data:{labels:[],datasets:[{data:[],borderColor:"#f59e0b",borderWidth:1.5,pointBackgroundColor:"#f59e0b",pointBorderColor:"#070709",pointRadius:2,pointHoverRadius:5,fill:true,backgroundColor:gr,tension:.2,spanGaps:true}]},
    options:{responsive:true,maintainAspectRatio:false,animation:false,plugins:{legend:{display:false}},
      scales:{x:{grid:{display:false},ticks:{color:"#4b5563",font:{size:8}}},y:{grid:{color:"rgba(245,158,11,.02)"},ticks:{color:"#4b5563",font:{size:8}},min:0}}}
  });
}

// ── histogram ──
function bucket(ms){if(ms<10)return 0;if(ms<50)return 1;if(ms<100)return 2;if(ms<250)return 3;if(ms<500)return 4;if(ms<1000)return 5;return 6;}
function updateHist(){
  var b=[0,0,0,0,0,0,0];
  lats.forEach(function(ms){b[bucket(ms)]++;});
  var mx=Math.max.apply(null,b.concat(1));
  for(var i=0;i<7;i++){wd("h"+i,Math.round(b[i]/mx*100));txt("hc"+i,"("+b[i]+")");}
}

// ── cmd centre ──
function updateCmd(){
  var url=g("target-url")?g("target-url").value:"http://127.0.0.1:8000/api/users";
  var mth=g("method-sel")?g("method-sel").value:"POST";
  txt("cmd-target",url); txt("cmd-method",mth);
  var n=total||1;
  var s2=records.filter(function(r){return r.code>=200&&r.code<300;}).length;
  var s3=records.filter(function(r){return r.code>=300&&r.code<400;}).length;
  var s4=records.filter(function(r){return r.code>=400&&r.code<500&&r.code!==408;}).length;
  var s5=records.filter(function(r){return r.code>=500;}).length;
  var st=records.filter(function(r){return r.code===408;}).length;
  var p=function(v){return total?((v/total)*100).toFixed(1)+"%":"0.0%";};
  txt("cmd-s2xx",s2);txt("cmd-s2xx-p",p(s2));
  txt("cmd-s3xx",s3);txt("cmd-s3xx-p",p(s3));
  txt("cmd-s4xx",s4);txt("cmd-s4xx-p",p(s4));
  txt("cmd-s5xx",s5);txt("cmd-s5xx-p",p(s5));
  txt("cmd-sto", st);txt("cmd-sto-p", p(st));
  txt("cmd-sne", 0); txt("cmd-sne-p","0.0%");
  if(lats.length){
    var so=lats.slice().sort(function(a,b){return a-b;});
    var avg=lats.reduce(function(a,b){return a+b;},0)/lats.length;
    var p95v=so[Math.min(Math.ceil(so.length*.95)-1,so.length-1)];
    txt("cmd-min",so[0].toFixed(1)+" ms");txt("cmd-max",so[so.length-1].toFixed(1)+" ms");
    txt("cmd-avg",avg.toFixed(1)+" ms");txt("cmd-p95",p95v.toFixed(1)+" ms");
  }else{["cmd-min","cmd-max","cmd-avg","cmd-p95"].forEach(function(id){txt(id,"0.0 ms");});}
  var prog=total>0?(total/MAX*100):0;
  wd("cmd-prog-fill",Math.min(prog,100));txt("cmd-prog-text",total+" / "+MAX+" ("+prog.toFixed(1)+"%)");
  updateHist();
}

// ── log stream ──
function pushLog(lvl,msg,pay){
  var el=g("cmd-logs"); if(!el)return;
  var d=new Date();
  var ts="["+d.getFullYear()+"-"+String(d.getMonth()+1).padStart(2,"0")+"-"+String(d.getDate()).padStart(2,"0")+" "+d.toLocaleTimeString()+","+String(d.getMilliseconds()).padStart(3,"0")+"]";
  var cls=lvl==="INFO"?"log-info":lvl==="WARN"?"log-warn":"log-err";
  var div=document.createElement("div"); div.className="log-entry";
  div.innerHTML='<span class="log-ts">'+ts+'</span> <span class="'+cls+'">'+lvl+':</span> <span class="log-msg">'+msg+'</span>'+(pay?' <span class="log-pay">'+pay+'</span>':"");
  el.insertBefore(div,el.firstChild);
  while(el.children.length>60) el.removeChild(el.lastChild);
}

// ── summary ──
function showSummary(){
  var s2=records.filter(function(r){return r.code>=200&&r.code<300;}).length;
  var s4=records.filter(function(r){return r.code>=400&&r.code<500&&r.code!==408;}).length;
  var s5=records.filter(function(r){return r.code>=500;}).length;
  var st=records.filter(function(r){return r.code===408;}).length;
  var so=lats.slice().sort(function(a,b){return a-b;});
  var avg=lats.length?(lats.reduce(function(a,b){return a+b;},0)/lats.length).toFixed(1):"0.0";
  var p95=so.length?so[Math.min(Math.ceil(so.length*.95)-1,so.length-1)].toFixed(1):"0.0";
  txt("sum-total",total+" / "+MAX);txt("sum-success",s2);txt("sum-client",s4);txt("sum-server",s5);txt("sum-timeout",st);
  txt("sum-avg",avg+" ms | 95th: "+p95+" ms");
  var box=g("cmd-summary"); if(box) box.classList.add("show");
  pushLog("INFO","Structured results saved to fuzz_results.json");
}

// ── start/stop ──
function startFuzzing(){
  fuzzing=true; total=0; failed=0; lats=[]; records=[];
  var box=g("cmd-summary"); if(box) box.classList.remove("show");
  var logs=g("cmd-logs"); if(logs) logs.innerHTML="";
  var btn=g("btn-start");
  if(btn){btn.className="stopped running";btn.innerHTML='<svg viewBox="0 0 24 24" fill="white" stroke="none" width="16" height="16"><rect x="4" y="4" width="16" height="16" rx="2"/></svg>STOP FUZZING RUN';}
  txt("status-text","Engine Active");
  var dot=g("status-dot"); if(dot) dot.className="dot-active";
  var sv=g("stat-status-val"); if(sv){sv.textContent="ACTIVE";sv.style.color="#f59e0b";}
  var ov=g("chart-overlay"); if(ov) ov.classList.add("hidden-overlay");
  var tb=g("logs-tbody"); if(tb) tb.innerHTML="";
  if(chart){chart.data.labels=[];chart.data.datasets[0].data=[];chart.update("none");}
  updateCmd();
  pushLog("INFO","Starting API Fuzzing Tool...");
  pushLog("INFO","Initializing payload generator, config validation, and async request pool.");
  setTimeout(function(){pushLog("INFO","Successfully loaded JSON template from user_template.json");},350);
  setTimeout(function(){pushLog("INFO","Generated "+MAX+" fuzzed payloads (Type, Boundary, Malformed JSON)");},700);
  setTimeout(function(){pushLog("INFO","Spawning asynchronous execution engine...");},1050);
  var sv2=g("conc-slider"); var iv=Math.max(60,Math.floor(2600/(sv2?parseInt(sv2.value):25)));
  timer=setInterval(function(){if(total>=MAX){stopFuzzing(true);}else{tick();}},iv);
}

function stopFuzzing(done){
  fuzzing=false; clearInterval(timer);
  var btn=g("btn-start");
  if(btn){btn.className="stopped gold-bg";btn.innerHTML='<svg viewBox="0 0 24 24" fill="#070709" stroke="none" width="16" height="16"><polygon points="5 3 19 12 5 21 5 3"/></svg>START FUZZING TEST';}
  if(done){
    txt("status-text","Engine Standby — Scan Complete");
    var dot=g("status-dot"); if(dot) dot.className="dot-idle";
    var sv=g("stat-status-val"); if(sv){sv.textContent="COMPLETE";sv.style.color="#22c55e";}
    updateCmd(); showSummary();
    setTimeout(function(){openReport();},800);
  }else{
    txt("status-text","Engine Standby");
    var dot2=g("status-dot"); if(dot2) dot2.className="dot-idle";
    var sv2=g("stat-status-val"); if(sv2){sv2.textContent="STANDBY";sv2.style.color="#6b7280";}
  }
}

function ri(mn,mx){return Math.floor(Math.random()*(mx-mn+1))+mn;}
function pick(a){return a[Math.floor(Math.random()*a.length)];}

function tick(){
  total++;
  var rng=Math.random(), pool;
  if(rng<.28)      pool=S.filter(function(s){return s.code===200;});
  else if(rng<.78) pool=S.filter(function(s){return s.code===400||s.code===422;});
  else if(rng<.92) pool=S.filter(function(s){return s.code===500;});
  else              pool=S.filter(function(s){return s.code===408;});
  var s=pick(pool), lat=ri(s.mn,s.mx);
  lats.push(lat);
  if(s.code>=400) failed++;
  if(s.code===200&&typeof s.pay==="object"&&Object.keys(s.pay).length>0) lastOk=s.pay;
  var url=g("target-url")?g("target-url").value:"http://127.0.0.1:8000/api/users";
  var mth=g("method-sel")?g("method-sel").value:"POST";
  var rec={ts:new Date().toLocaleTimeString(),url:url,mth:mth,code:s.code,lbl:s.lbl,cat:s.cat,lat:lat,msg:s.msg||"",pay:s.pay};
  records.push(rec);
  // stats
  txt("stat-total",total); txt("stat-failed",failed);
  txt("stat-fail-pct",((failed/total)*100).toFixed(1)+"%");
  var sl=g("conc-slider"); txt("stat-rate",(Math.floor(Math.random()*10)+Math.floor((sl?parseInt(sl.value):25)*.8))+" req/s");
  var al=(lats.reduce(function(a,b){return a+b;},0)/lats.length).toFixed(1);
  txt("stat-latency",al+" ms");
  var so2=lats.slice().sort(function(a,b){return a-b;});
  txt("stat-p95",so2[Math.min(Math.ceil(so2.length*.95)-1,so2.length-1)].toFixed(1)+" ms");
  wd("stat-prog-fill",total/MAX*100);
  // log table
  var fv=g("filter-log")?g("filter-log").value:"all";
  var intrig=[400,403,408,429,500].indexOf(s.code)!==-1;
  if(fv==="all"||(fv==="interesting"&&intrig)) renderRow(rec);
  // chart
  if(chart){chart.data.labels.push("#"+total);chart.data.datasets[0].data.push(lat);if(chart.data.labels.length>20){chart.data.labels.shift();chart.data.datasets[0].data.shift();}chart.update("none");}
  // cmd
  updateCmd();
  if(s.code>=500) pushLog("ERROR","Server Error ("+s.code+") for payload:",typeof s.pay==="object"?JSON.stringify(s.pay):s.pay);
  else if(s.code===408) pushLog("WARN","Timeout (408) — "+(s.msg||"Read timeout exceeded"));
}

// ── row render ──
function badge(c){
  if(c===200) return "code-badge badge-200";
  if(c===422) return "code-badge badge-422";
  if(c===400) return "code-badge badge-400";
  if(c===408) return "code-badge badge-408";
  return "code-badge badge-500";
}
function renderRow(r){
  var tb=g("logs-tbody"); if(!tb) return;
  var tr=document.createElement("tr");
  tr.innerHTML='<td style="color:#6b7280;font-family:JetBrains Mono,monospace">'+r.ts+'</td>'+
    '<td style="font-family:JetBrains Mono,monospace;font-size:10px;color:#d1d5db">'+r.url+'</td>'+
    '<td style="color:#f59e0b;font-weight:700">'+r.mth+'</td>'+
    '<td><span class="'+badge(r.code)+'">'+r.code+'</span></td>'+
    '<td style="color:#9ca3af"><span>'+r.lbl+'</span>'+(r.msg?'<span class="err-tag">'+r.msg+'</span>':"")+'</td>';
  tr.addEventListener("click",function(){openDiff(r);});
  tb.insertBefore(tr,tb.firstChild);
  while(tb.children.length>30) tb.removeChild(tb.lastChild);
}

// ── filter ──
var fl=g("filter-log");
if(fl) fl.addEventListener("change",function(){
  var tb=g("logs-tbody"); if(!tb) return;
  tb.innerHTML="";
  var val=this.value;
  var list=val==="all"?records:records.filter(function(r){return [400,403,408,429,500].indexOf(r.code)!==-1;});
  if(!list.length){tb.innerHTML='<tr class="empty-row"><td colspan="5">No records match filter.</td></tr>';}
  else list.slice(-30).reverse().forEach(renderRow);
});

// ── diff drawer ──
function diffHtml(base,fuzz){
  if(typeof fuzz==="string") return '<span style="background:rgba(220,38,38,.2);color:#f87171;font-weight:700;padding:2px 6px;border-radius:3px;display:inline-block;width:100%">'+fuzz+'</span>';
  var out=["{"];
  Object.keys(fuzz).forEach(function(k,i,arr){
    var v=fuzz[k], diff=base[k]===undefined||JSON.stringify(v)!==JSON.stringify(base[k]);
    var line='  "'+k+'": '+JSON.stringify(v)+(i<arr.length-1?",":"");
    out.push(diff?'<span style="background:rgba(220,38,38,.15);color:#f87171;font-weight:700;padding:1px 4px;border-radius:3px;display:inline-block;width:100%">'+line+'</span>':line);
  });
  out.push("}"); return out.join("\n");
}
function openDiff(r){
  txt("diff-method",r.mth); txt("diff-endpoint",r.url); txt("diff-strategy",r.lbl); txt("diff-code",r.code);
  var dc=g("diff-code");
  if(dc){var cl="code-badge ";cl+=r.code===200?"badge-200":r.code===422?"badge-422":r.code===400?"badge-400":"badge-500";dc.className=cl;}
  txt("diff-baseline",JSON.stringify(lastOk,null,2)); htm("diff-fuzzed",diffHtml(lastOk,r.pay));
  var dw=g("diff-drawer"); if(dw) dw.classList.add("open");
}
function closeDiff(){var dw=g("diff-drawer"); if(dw) dw.classList.remove("open");}
var bd1=g("btn-close-diff"), bd2=g("btn-close-diff-2");
if(bd1) bd1.addEventListener("click",closeDiff);
if(bd2) bd2.addEventListener("click",closeDiff);

// ── report ──
function openReport(){
  txt("rep-total",total);
  txt("rep-rate",total?(((total-failed)/total)*100).toFixed(1)+"%":"0%");
  txt("rep-vulns",failed);
  txt("rep-malformed",records.filter(function(r){return r.cat==="malformed";}).length);
  txt("rep-types",    records.filter(function(r){return r.cat==="types";}).length);
  txt("rep-overflow", records.filter(function(r){return r.cat==="overflow";}).length);
  txt("rep-timeouts", records.filter(function(r){return r.cat==="timeouts";}).length);
  var b=g("report-backdrop"); if(b) b.classList.add("open");
}
function closeReport(){var b=g("report-backdrop"); if(b) b.classList.remove("open");}
var brpt=g("btn-report"), bcr=g("btn-close-report"), rbk=g("report-backdrop");
if(brpt) brpt.addEventListener("click",openReport);
if(bcr)  bcr.addEventListener("click",closeReport);
if(rbk)  rbk.addEventListener("click",function(e){if(e.target===rbk) closeReport();});

// ── CSV ──
function csv(data){
  if(!data.length){alert("No records to export.");return;}
  var hdr=["Timestamp","Endpoint","Method","Code","Strategy","Payload"];
  var rows=data.map(function(r){
    return [r.ts,r.url,r.mth,r.code,r.lbl,typeof r.pay==="object"?JSON.stringify(r.pay):r.pay]
      .map(function(v){return'"'+String(v).replace(/"/g,'""')+'"';}).join(",");
  });
  var blob=new Blob([hdr.join(",")+"\n"+rows.join("\n")],{type:"text/csv"});
  var a=document.createElement("a"); a.href=URL.createObjectURL(blob); a.download="fuzzshield_"+Date.now()+".csv";
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
}
var bex=g("btn-export"), brdl=g("btn-rep-dl");
if(bex)  bex.addEventListener("click",function(){var fv=g("filter-log")?g("filter-log").value:"all";csv(fv==="all"?records:records.filter(function(r){return [400,403,408,429,500].indexOf(r.code)!==-1;}));});
if(brdl) brdl.addEventListener("click",function(){csv(records);});

// ── clear ──
var bcl=g("btn-clear");
if(bcl) bcl.addEventListener("click",function(){var tb=g("logs-tbody");if(tb) tb.innerHTML='<tr class="empty-row"><td colspan="5">Logs cleared.</td></tr>';records=[];});

// ── start/stop btn ──
var bst=g("btn-start");
if(bst) bst.addEventListener("click",function(){if(fuzzing) stopFuzzing(false); else startFuzzing();});

// ── init ──
updateCmd();

})();