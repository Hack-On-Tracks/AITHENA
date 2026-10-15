// Device Risk Engine Tests (plain Node, no framework)
const {detectNetworkChanges, analyseFlows, correlateIdentity, scoreDevice, DEFAULT_CONFIG} = require('../assets/js/device-risk-engine');
const Data = require('../assets/js/device-risk-data');

function assert(cond, msg) { if (!cond) throw new Error('Assertion failed: '+msg); }

function run(){
  console.log('Running Device Risk Engine tests');
  const device={deviceId:'DEV-001',assignedUser:'Alice',department:'Finance',status:'active',trustedNetworks:['corp_wifi','vpn']};
  const baseline={avgBytesOut:100,avgDuration:60,avgConnCount:2};
  // a) network change alone
  const netEvent={type:'network_change',deviceId:'DEV-001',ts:Date.now(),from:{type:'corp_wifi'},to:{type:'unknown'},trusted:false,provenance:'observed'};
  const netSignals=detectNetworkChanges(device,[netEvent]);
  const scoreA=scoreDevice(device,netSignals);
  assert(scoreA.severity!=='Critical','a) Network change alone produced Critical');
  console.log('a) passed');
  // b) suspicious transfer alone
  const flowEvent={type:'flow',deviceId:'DEV-001',ts:Date.now(),srcDevice:'DEV-001',dest:'files.mega.nz',destNovelty:'new',protocol:'HTTPS',durationSec:300,bytesOut:2000,bytesIn:0,connectionCount:1,provenance:'observed'};
  const flowSignals=analyseFlows(device,[flowEvent],baseline);
  const scoreB=scoreDevice(device,flowSignals);
  assert(['Medium','High','Critical'].includes(scoreB.severity),'b) Suspicious transfer gave Low severity');
  console.log('b) passed');
  // c) combined scenario
  const statusEvent={type:'device_status',deviceId:'DEV-001',ts:Date.now(),status:'reported_stolen',provenance:'observed'};
  const authEvent={type:'auth',deviceId:'DEV-001',ts:Date.now(),source:'idp',result:'success',newLocationOrClient:true,resourceAccessed:'admin_portal',anomalyFlags:[],provenance:'observed'};
  const allEvents=[netEvent,flowEvent,statusEvent,authEvent];
  const netS=detectNetworkChanges(device,allEvents);
  const flowS=analyseFlows(device,allEvents,baseline);
  const idS=correlateIdentity(device,[authEvent],[statusEvent]);
  const allSignals=netS.concat(flowS,idS);
  const scoreC=scoreDevice(device,allSignals);
  assert(['High','Critical'].includes(scoreC.severity),'c) Combined signals did not reach High/Critical');
  assert(scoreC.explanation.includes('signal groups'),'c) Explanation missing');
  console.log('c) passed');
  // d) missing telemetry lowers confidence
  const unknownSignal={signal:'unknown_telemetry',group:'vpn',confidence:'Low',description:'No VPN logs',timestamp:Date.now(),provenance:'observed'};
  const scoreD=scoreDevice(device,[unknownSignal]);
  assert(['Low','Medium'].includes(scoreD.confidence),'d) Confidence not lowered');
  console.log('d) passed');
  // e) duplicate signals not double counted
  const dup1={signal:'large_outbound',group:'traffic',confidence:'Medium',description:'big',timestamp:Date.now(),provenance:'observed'};
  const dup2={signal:'large_outbound',group:'traffic',confidence:'Medium',description:'big again',timestamp:Date.now(),provenance:'observed'};
  const scoreE=scoreDevice(device,[dup1,dup2]);
  const points=scoreE.contributions.reduce((a,c)=>a+c.points,0);
  assert(points<=30,'e) Duplicate signals added too many points');
  console.log('e) passed');
  // f) weight change affects score
  const cfg=JSON.parse(JSON.stringify(DEFAULT_CONFIG));
  cfg.weights.traffic=0.8;
  const scoreF1=scoreDevice(device,flowSignals,DEFAULT_CONFIG);
  const scoreF2=scoreDevice(device,flowSignals,cfg);
  assert(scoreF2.score>scoreF1.score,'f) Increased weight did not raise score');
  console.log('f) passed');
  console.log('All tests passed');
}
run();
