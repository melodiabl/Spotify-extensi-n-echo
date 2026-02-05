const fs = require('fs');
require('dotenv').config();

/**
 * Gestiona la obtención de nodos Lavalink según la configuración del .env
 */
function getLavalinkNodes() {
    const mode = process.env.LAVALINK_MODE || 'list';

    if (mode === 'custom') {
        console.log('Modo: Servidor Personalizado (.env)');
        return [{
            id: 'CustomNode',
            host: process.env.LAVALINK_HOST,
            port: parseInt(process.env.LAVALINK_PORT),
            password: process.env.LAVALINK_PASS,
            secure: process.env.LAVALINK_SECURE === 'true'
        }];
    } else {
        console.log('Modo: Lista de Servidores (lavalinks.json)');
        try {
            const data = fs.readFileSync('./lavalinks.json', 'utf8');
            const nodes = JSON.parse(data);
            return nodes.map((node, index) => ({
                id: node.name || `Node-${index}`,
                host: node.host,
                port: node.port,
                password: node.password,
                secure: node.secure || false
            }));
        } catch (error) {
            console.error('Error al leer lavalinks.json, usando valores por defecto:', error.message);
            return [];
        }
    }
}

// Ejemplo de uso para tu bot (con librerías como lavalink-client o erela.js)
const nodes = getLavalinkNodes();
console.log('Nodos cargados:', JSON.stringify(nodes, null, 2));

module.exports = { getLavalinkNodes };
