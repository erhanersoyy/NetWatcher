import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { collectTargets, filterMapProcesses, mapRatesAvailable, processKey, targetFeatures, validGeo, prepareCountryAtlas } from './radar-data.js';

const geo = { lat: 0, lon: 0, country: 'Fixture' };
const conn = { remoteAddress: '1.1.1.1', remotePort: 443, localPort: 1234, protocol: 'TCP', trafficKey: 'a', geo, bytesIn: 10, bytesOut: 20 };
const proc = { pid: 1, processName: 'Example', identity: { token: 'one' }, connections: [conn] };
test('coordinates: zero is valid, malformed / out-of-range inputs remain unlocated', () => {
  assert.equal(validGeo(geo), true);
  for (const invalid of [null, {}, {lat:'0',lon:0}, {lat:NaN,lon:0}, {lat:91,lon:0}, {lat:0,lon:181}]) assert.equal(validGeo(invalid), false);
  const result = collectTargets([{...proc, connections:[{...conn, geo:null}]}], new Map(), false);
  assert.equal(result.length, 1);
  assert.equal(targetFeatures(result).features.length, 0);
});
test('local-network placeholder coordinates never create a false map location', () => {
  const local = { ...conn, remoteAddress: '192.168.1.1', geo: { lat: 0, lon: 0, country: 'Local', countryCode: 'LO' } };
  const targets = collectTargets([{ ...proc, connections: [local] }], new Map(), false);
  assert.equal(targets.length, 1);
  assert.equal(targets[0].ip, local.remoteAddress);
  assert.equal(targets[0].geo, null);
  assert.deepEqual(targetFeatures(targets).features, []);
});
test('one target retains all processes while shared traffic and duplicate rows are counted once', () => {
  const other = {...proc, pid:2, identity:{token:'two'}};
  const [target] = collectTargets([{...proc, connections:[conn,conn]}, other], new Map([['a',{bytesIn:30,bytesOut:40,rxBps:2,txBps:3}]]), true);
  assert.equal(target.processes.length, 2);
  assert.equal(target.connections, 2);
  assert.equal(target.bytesOut, 40);
  assert.equal(target.txBps, 3);
});
test('missing, paused and partial traffic samples never become zero or a complete sum', () => {
  const [unknown] = collectTargets([proc], new Map(), true);
  assert.equal(unknown.txBps, null);
  const [paused] = collectTargets([proc], new Map([['a',{txBps:9}]]), false);
  assert.equal(paused.txBps, null);
  const [partial] = collectTargets([{...proc, connections:[conn,{...conn,localPort:1235,trafficKey:'b'}]}], new Map([['a',{txBps:9}]]), true);
  assert.equal(partial.txBps, null);
  const [zero] = collectTargets([proc], new Map([['a',{txBps:0}]]), true);
  assert.equal(zero.txBps, 0);
});
test('process identity changes on PID reuse and distinguishes processes sharing an identity token', () => {
  assert.notEqual(processKey(proc), processKey({...proc,identity:{token:'new'}}));
  assert.notEqual(processKey(proc), processKey({...proc,pid:2}));
});
test('map selection filters exact IPs without mutating its context or losing unknown locations', () => {
  const base = [{...proc,connections:[conn,{...conn,remoteAddress:'1.1.1.10',geo:null}]}];
  const filtered = filterMapProcesses(base,{ips:['1.1.1.10']});
  assert.deepEqual(filtered[0].connections.map(c=>c.remoteAddress),['1.1.1.10']);
  assert.equal(base[0].connections.length,2);
  assert.equal(filterMapProcesses(base,null),base);
  assert.deepEqual(filterMapProcesses(base,{ips:['gone']}),[]);
});
test('stable feature identities preserve coordinates across sort changes and handle poles/dateline', () => {
  const targets = [{ip:'a',geo:{lat:90,lon:180}},{ip:'b',geo:{lat:0,lon:-180}}];
  const features = targetFeatures(targets).features;
  assert.deepEqual(features.map(f=>f.geometry.coordinates),[[180,85],[-180,0]]);
  assert.equal(targets[0].geo.lat,90);
  assert.equal(targetFeatures(targets.reverse()).features[1].id,'a');
});
test('stale, paused, failed, and baseline-only streams do not expose live rates', () => {
  const state = {streamHealthy:true,hasRateSample:true,lastDeltaAt:99000,connectionsUpdatedAt:99000,refreshIntervalMs:10000};
  assert.equal(mapRatesAvailable(state,100000),true);
  for (const patch of [{paused:true},{streamHealthy:false},{hasRateSample:false},{lastDeltaAt:0},{lastDeltaAt:95000},{connectionsError:'offline'},{connectionsUpdatedAt:60000}]) assert.equal(mapRatesAvailable({...state,...patch},100000),false);
});
test('10,000 synthetic IPs preserve coverage and unique target count', () => {
  const connections = Array.from({length:10000},(_,i)=>({...conn,remoteAddress:`198.18.${i>>8}.${i%256}`,trafficKey:String(i),geo:i%10 ? geo : null}));
  const targets = collectTargets([{...proc,connections}],new Map(),false);
  assert.equal(targets.length,10000);
  assert.equal(targetFeatures(targets).features.length,9000);
});
test('atlas dateline endpoints do not create transcontinental borders or mutate the atlas', () => {
  const east = [[179,-16],[-180,-16],[180,-17],[179,-16]];
  const west = [[-179,70],[180,70],[-180,69],[-179,70]];
  const antarctic = [[-180,-85],[-100,-80],[0,-80],[100,-80],[180,-85],[-180,-85]];
  const input = {type:'FeatureCollection',features:[{geometry:{type:'MultiPolygon',coordinates:[[east],[west],[antarctic]]}}]};
  const result = prepareCountryAtlas(input).features[0].geometry.coordinates;
  assert.equal(result[0][0][1][0],180);
  assert.equal(result[1][0][1][0],-180);
  assert.deepEqual(result[2][0],antarctic);
  assert.equal(east[1][0],-180);
});
test('the shipped world atlas has no across-world edges outside the polar cap', () => {
  const context = {};
  vm.runInNewContext(readFileSync(new URL('../vendor/topojson-client.min.js', import.meta.url), 'utf8'), context);
  const topology = JSON.parse(readFileSync(new URL('../vendor/countries-110m.json', import.meta.url), 'utf8'));
  const atlas = prepareCountryAtlas(context.topojson.feature(topology, topology.objects.countries));
  for (const feature of atlas.features) {
    if (feature.properties.name === 'Antarctica') continue;
    const polygons = feature.geometry.type === 'Polygon' ? [feature.geometry.coordinates] : feature.geometry.coordinates;
    for (const polygon of polygons) for (const ring of polygon) for (let i = 1; i < ring.length; i++) {
      assert.ok(Math.abs(ring[i][0] - ring[i - 1][0]) <= 180, feature.properties.name);
    }
  }
});
