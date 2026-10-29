/* ============================================================
   NetWatcher — DOM element handles
   All getElementById calls centralised here; consumed via the
   frozen `el` object so callers cannot accidentally reassign.
   ============================================================ */

const $ = (id) => document.getElementById(id);

export function preserveFocus(container) {
  const active = document.activeElement;
  const key = container.contains(active) ? active.dataset.focusKey : null;
  const scroll = container.scrollTop;
  return () => {
    container.scrollTop = scroll;
    if (!key) return;
    const next = container.querySelector(`[data-focus-key="${CSS.escape(key)}"]`);
    (next || document.getElementById('searchInput')).focus({ preventScroll: true });
  };
}

export const el = Object.freeze({
  // queue / search / controls
  queueEl:        $('queue'),
  qEl:            $('searchInput'),
  sortSelect:     $('sortSelect'),
  chipsEl:        $('chips'),
  blockedCountEl: $('blockedCount'),
  statusText:     $('statusText'),
  qToggleBtn:     $('qToggle'),
  qToggleIcon:    $('qToggleIcon'),
  refreshSelect:  $('refreshSelect'),
  refreshNowBtn:  $('refreshNowBtn'),
  pauseBtn:      $('pauseBtn'),
  listStatus:    $('listStatus'),
  queueSummary:  $('queueSummary'),
  trafficStatus: $('trafficStatus'),
  hostStatus:    $('hostStatus'),
  healthStatus:  $('healthStatus'),
  blockedStatus: $('blockedStatus'),
  footAnchor:    $('footAnchor'),

  // stage / health
  tRx:          $('tRx'),
  tTx:          $('tTx'),
  gRx:          $('gRx'),
  gTx:          $('gTx'),
  dProc:        $('dProc'),
  dProcSys:     $('dProcSys'),
  dProcUsr:     $('dProcUsr'),
  dConn:        $('dConn'),
  dConnSub:     $('dConnSub'),
  dCtry:        $('dCtry'),
  dCtrySub:     $('dCtrySub'),
  talkersListEl: $('talkersList'),
  hCPU:         $('hCPU'),
  hCPUbar:      $('hCPUbar'),
  hMem:         $('hMem'),
  hMembar:      $('hMembar'),
  hLoad:        $('hLoad'),

  // blocked panel
  blockedListEl:    $('blockedList'),
  blockedSearch:    $('blockedSearch'),
  blockedCntBig:    $('blockedCntBig'),
  blockedExport:    $('blockedExport'),
  blockedAdd:       $('blockedAdd'),
  blockedHistoryBtn: $('blockedHistory'),

  // foot
  footRefresh: $('footRefresh'),
  footSort:    $('footSort'),
  footTz:      $('footTz'),
  footBlocked: $('footBlocked'),

  // masthead
  clockT:        $('clockT'),
  clockD:        $('clockD'),
  hostHostname:  $('hostHostname'),
  hostLocalIP:   $('hostLocalIP'),
  hostPublicIP:  $('hostPublicIP'),
  hostLocation:  $('hostLocation'),
  hostISP:       $('hostISP'),
  queueISP:      $('queueISP'),
  queueGeo:      $('queueGeo'),
});
