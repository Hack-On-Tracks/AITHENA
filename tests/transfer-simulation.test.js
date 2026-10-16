const Simulation = require('../assets/js/transfer-simulation');

function assert(condition, message) {
  if (!condition) throw new Error(`Assertion failed: ${message}`);
}

function run() {
  console.log('Running simulated transfer tests');
  const insider = Simulation.createTransfer(2, 1000);
  assert(insider.sourceDeviceId === 'DEV-003', 'insider transfer has the wrong source');
  assert(insider.destinationDeviceId === 'DEV-004', 'insider transfer has the wrong destination');
  assert(insider.provenance === 'SIMULATED' && insider.status === 'SIMULATED', 'insider transfer is not explicitly simulated');
  assert(insider.timestamp === new Date(1000).toISOString(), 'event timestamp is not structured');

  const background = Simulation.createTransfer(1, 2000);
  assert(background.sourceDeviceId !== 'DEV-003', 'background transfer unexpectedly uses the insider');
  assert(background.bytes < 1000000, 'background transfer should remain normal-volume');
  assert(['HTTPS', 'SMB'].includes(background.protocol), 'background transfer protocol is missing');
  console.log('All simulated transfer tests passed');
}

run();
