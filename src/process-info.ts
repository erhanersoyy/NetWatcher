// Process knowledge base: short descriptions and system-critical flag.
// Keys are lowercase process name prefixes/exact matches.

interface ProcessMeta {
  description: string;
  system: boolean;
}

const PROCESS_DB: Record<string, ProcessMeta> = {
  // macOS system daemons
  'kernel_task':        { description: 'OS kernel process', system: true },
  'launchd':            { description: 'System service manager', system: true },
  'mds':                { description: 'Spotlight indexing', system: true },
  'mds_stores':         { description: 'Spotlight metadata store', system: true },
  'mdworker':           { description: 'Spotlight index worker', system: true },
  'windowserver':       { description: 'Display window manager', system: true },
  'systemuiserver':     { description: 'Menu bar service', system: true },
  'loginwindow':        { description: 'Login session manager', system: true },
  'opendirectoryd':     { description: 'Directory services daemon', system: true },
  'configd':            { description: 'System configuration daemon', system: true },
  'coreauthd':          { description: 'Authentication framework', system: true },
  'securityd':          { description: 'Security framework daemon', system: true },
  'trustd':             { description: 'Certificate trust daemon', system: true },
  'diskarbitrationd':   { description: 'Disk mount manager', system: true },
  'fseventsd':          { description: 'Filesystem event tracker', system: true },
  'notifyd':            { description: 'System notification daemon', system: true },
  'logd':               { description: 'Unified logging daemon', system: true },
  'syslogd':            { description: 'System log daemon', system: true },
  'powerd':             { description: 'Power management daemon', system: true },
  'thermalmonitord':    { description: 'Thermal monitoring service', system: true },
  'bluetoothd':         { description: 'Bluetooth stack daemon', system: true },
  'airportd':           { description: 'Wi-Fi management daemon', system: true },
  'wifid':              { description: 'Wi-Fi network daemon', system: true },
  'locationd':          { description: 'Location services daemon', system: true },
  'corelocationd':      { description: 'Core location daemon', system: true },
  'coreduetd':          { description: 'Usage prediction engine', system: true },
  'cfprefsd':           { description: 'Preferences sync daemon', system: true },
  'usbd':               { description: 'USB device manager', system: true },
  'ioupsd':             { description: 'UPS monitoring daemon', system: true },
  'corespotlightd':     { description: 'Spotlight core service', system: true },
  'networkd':           { description: 'Network subsystem daemon', system: true },
  'symptomsd':          { description: 'Network diagnostics daemon', system: true },
  'apsd':               { description: 'Apple push notifications', system: true },
  'cloudd':             { description: 'iCloud sync daemon', system: true },
  'bird':               { description: 'iCloud document sync', system: true },
  'identityservicesd':  { description: 'Apple ID auth service', system: true },
  'imagent':            { description: 'iMessage/FaceTime agent', system: true },
  'sharingd':           { description: 'AirDrop/sharing daemon', system: true },
  'rapportd':           { description: 'Device proximity daemon', system: true },
  'timed':              { description: 'Network time sync', system: true },
  'ntpd':               { description: 'Network time protocol', system: true },
  'chronod':            { description: 'Time sync daemon', system: true },
  'mDNSResponder':      { description: 'Bonjour DNS resolver', system: true },
  'mdnsresponder':      { description: 'Bonjour DNS resolver', system: true },
  'networkserviceproxy':{ description: 'Network proxy service', system: true },
  'nesessionmanager':   { description: 'Network extension manager', system: true },
  'nehelper':           { description: 'Network extension helper', system: true },
  'trustdFileHelper':   { description: 'Certificate trust helper', system: true },
  'fileproviderd':      { description: 'Cloud file provider', system: true },
  'nsurlsessiond':      { description: 'URL session daemon', system: true },
  'com.apple.WebKit':   { description: 'WebKit content process', system: false },
  'softwareupdated':    { description: 'Software update daemon', system: true },
  'analyticsd':         { description: 'System analytics daemon', system: true },
  'diagnosticd':        { description: 'Diagnostics framework', system: true },
  'corespeechd':        { description: 'Speech recognition daemon', system: true },
  'audiomxd':           { description: 'Audio mixing daemon', system: true },
  'coreaudiod':         { description: 'Core audio daemon', system: true },
  'UserEventAgent':     { description: 'User event handler', system: true },
  'usereventagent':     { description: 'User event handler', system: true },
  'distnoted':          { description: 'Distributed notifications', system: true },

  // Browsers
  'google chrome':      { description: 'Web browser', system: false },
  'google chrome helper': { description: 'Chrome sub-process', system: false },
  'chrome':             { description: 'Web browser', system: false },
  'firefox':            { description: 'Web browser', system: false },
  'safari':             { description: 'Apple web browser', system: false },
  'safariviewservice':  { description: 'Safari embedded view', system: false },
  'webkit':             { description: 'WebKit rendering engine', system: false },
  'brave browser':      { description: 'Privacy web browser', system: false },
  'microsoft edge':     { description: 'Web browser', system: false },
  'arc':                { description: 'Web browser', system: false },
  'opera':              { description: 'Web browser', system: false },
  'vivaldi':            { description: 'Web browser', system: false },

  // Dev tools
  'node':               { description: 'JavaScript runtime', system: false },
  'deno':               { description: 'JavaScript runtime', system: false },
  'bun':                { description: 'JavaScript runtime', system: false },
  'python':             { description: 'Python interpreter', system: false },
  'python3':            { description: 'Python interpreter', system: false },
  'ruby':               { description: 'Ruby interpreter', system: false },
  'java':               { description: 'Java virtual machine', system: false },
  'go':                 { description: 'Go binary process', system: false },
  'cargo':              { description: 'Rust package manager', system: false },
  'rustc':              { description: 'Rust compiler', system: false },
  'git':                { description: 'Version control system', system: false },
  'git-remote-http':    { description: 'Git HTTP transport', system: false },
  'ssh':                { description: 'Secure shell client', system: false },
  'sshd':               { description: 'SSH server daemon', system: true },
  'code':               { description: 'VS Code editor', system: false },
  'code helper':        { description: 'VS Code sub-process', system: false },
  'cursor':             { description: 'AI code editor', system: false },
  'copilot':            { description: 'AI coding assistant', system: false },

  // Communication apps
  'slack':              { description: 'Team messaging app', system: false },
  'slack helper':       { description: 'Slack sub-process', system: false },
  'discord':            { description: 'Voice/text chat app', system: false },
  'zoom.us':            { description: 'Video conferencing', system: false },
  'teams':              { description: 'Microsoft Teams app', system: false },
  'telegram':           { description: 'Messaging app', system: false },
  'whatsapp':           { description: 'Messaging app', system: false },
  'signal':             { description: 'Encrypted messaging app', system: false },
  'messages':           { description: 'Apple iMessage client', system: false },
  'mail':               { description: 'Apple email client', system: false },
  'outlook':            { description: 'Microsoft email client', system: false },
  'thunderbird':        { description: 'Email client app', system: false },

  // Media/Cloud
  'spotify':            { description: 'Music streaming app', system: false },
  'music':              { description: 'Apple Music app', system: false },
  'vlc':                { description: 'Media player app', system: false },
  'iterm2':             { description: 'Terminal emulator', system: false },
  'terminal':           { description: 'macOS terminal app', system: false },
  'dropbox':            { description: 'Cloud file sync', system: false },
  'onedrive':           { description: 'Microsoft cloud sync', system: false },
  'docker':             { description: 'Container runtime', system: false },
  'com.docker':         { description: 'Docker daemon process', system: false },
  'vpnkit':             { description: 'Docker VPN bridge', system: false },
  'kubectl':            { description: 'Kubernetes CLI tool', system: false },
  'postgres':           { description: 'PostgreSQL database', system: false },
  'mysqld':             { description: 'MySQL database server', system: false },
  'mongod':             { description: 'MongoDB database server', system: false },
  'redis-server':       { description: 'Redis cache server', system: false },
  'nginx':              { description: 'Web/proxy server', system: false },
  'httpd':              { description: 'Apache web server', system: false },
  'curl':               { description: 'HTTP transfer tool', system: false },
  'wget':               { description: 'File download tool', system: false },

  // Productivity
  'finder':             { description: 'File manager app', system: true },
  'dock':               { description: 'App dock manager', system: true },
  'spotlight':          { description: 'System search service', system: true },
  'notes':              { description: 'Apple Notes app', system: false },
  'reminders':          { description: 'Apple Reminders app', system: false },
  'calendar':           { description: 'Apple Calendar app', system: false },
  'preview':            { description: 'Document viewer app', system: false },
  'textedit':           { description: 'Text editor app', system: false },
  'pages':              { description: 'Apple word processor', system: false },
  'numbers':            { description: 'Apple spreadsheet app', system: false },
  'keynote':            { description: 'Apple presentation app', system: false },

  // Security / VPN
  'openvpn':            { description: 'VPN tunnel client', system: false },
  'wireguard-go':       { description: 'WireGuard VPN tunnel', system: false },
  'tailscaled':         { description: 'Tailscale VPN daemon', system: false },
  'little snitch':      { description: 'Network firewall app', system: false },

  // Apple services
  'appstoreagent':      { description: 'App Store updater', system: false },
  'storedownloadd':     { description: 'App Store downloads', system: false },
  'akd':                { description: 'AuthKit daemon', system: true },
  'accountsd':          { description: 'Account management daemon', system: true },
  'callservicesd':      { description: 'Phone call relay service', system: true },
  'parsec':             { description: 'Siri knowledge service', system: true },
  'assistantd':         { description: 'Siri assistant daemon', system: true },
  'searchpartyd':       { description: 'Find My network daemon', system: true },
  'mediaremoted':       { description: 'Media remote control', system: true },
  'amp':                { description: 'Apple media process', system: false },

  // netwatcher itself
  'tsx':                { description: 'TypeScript executor', system: false },
  'netwatcher':         { description: 'This application', system: false },
};

export function getProcessMeta(name: string): { description: string; isSystem: boolean } {
  const lower = name.toLowerCase();

  // Exact match first
  if (PROCESS_DB[lower]) {
    return { description: PROCESS_DB[lower].description, isSystem: PROCESS_DB[lower].system };
  }

  // Try matching known key as prefix of the process name.
  // Sort longest key first so `mailchimp` wins over `mail`; only allow substring
  // matches for keys of ≥5 chars to avoid `go`/`code` matching everything.
  const sortedKeys = Object.keys(PROCESS_DB).sort((a, b) => b.length - a.length);
  for (const key of sortedKeys) {
    if (lower.startsWith(key) || (key.length >= 5 && lower.includes(key))) {
      const meta = PROCESS_DB[key];
      return { description: meta.description, isSystem: meta.system };
    }
  }

  // Heuristic: paths starting with /usr/libexec, /System, /usr/sbin are likely system
  // Process names with com.apple. prefix are Apple system processes
  if (lower.startsWith('com.apple.')) {
    return { description: 'Apple system service', isSystem: true };
  }

  return { description: 'Unknown process', isSystem: false };
}
