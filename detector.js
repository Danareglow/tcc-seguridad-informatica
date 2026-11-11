const { exec } = require('child_process');
const cron = require('node-cron');
const fs = require('fs');

const GATEWAY_IP = process.env.GATEWAY_IP || '172.18.0.2';
const INTERVALO_CRON = '*/5 * * * * *';

let macConocida = null;
const logPath = 'alertas-arp.log';

function registrar(mensaje) {
  const linea = `[${new Date().toISOString()}] ${mensaje}`;
  console.log(linea);
  fs.appendFileSync(logPath, linea + '\n');
}

function obtenerMacDeVecino(ip, callback) {
  exec(`ip neigh show ${ip}`, (error, stdout) => {
    if (error) return callback(error, null);
    const match = stdout.match(/lladdr\s+([0-9a-f:]{17})/i);
    if (!match) return callback(null, null);
    return callback(null, match[1].toLowerCase());
  });
}

function verificar() {
  obtenerMacDeVecino(GATEWAY_IP, (err, macActual) => {
    if (err) {
      registrar(`ERROR al consultar la tabla ARP: ${err.message}`);
      return;
    }
    if (!macActual) {
      exec(`ping -c 1 -W 1 ${GATEWAY_IP}`, () => {});
      return;
    }
    if (macConocida === null) {
      macConocida = macActual;
      registrar(`Línea base registrada: ${GATEWAY_IP} -> ${macConocida}`);
      return;
    }
    if (macActual !== macConocida) {
      registrar(
        `*** ALERTA DE POSIBLE ARP SPOOFING ***  ` +
        `La MAC de la puerta de enlace (${GATEWAY_IP}) cambió de ${macConocida} a ${macActual}`
      );
      macConocida = macActual;
    }
  });
}

registrar(`Detector de ARP Spoofing iniciado. Vigilando ${GATEWAY_IP} cada 5 segundos.`);
verificar();
cron.schedule(INTERVALO_CRON, verificar);
