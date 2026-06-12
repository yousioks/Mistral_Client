// ══════════════════════════════════════════════════════════════════════════════
// CYBER THREAT MAP (3D GLOBE) & DOCKER NETWORK TOPOLOGY GRAPH
// ══════════════════════════════════════════════════════════════════════════════

// Simplified lat/lon coordinate approximations of global landmasses for 3D Globe representation
const LAND_COORDINATES = [];
function initLandCoordinates() {
    // Generate a set of points representing continents
    const continentBounds = [
        { minLat: 15, maxLat: 70, minLon: -160, maxLon: -50 },  // North America
        { minLat: -55, maxLat: 12, minLon: -80, maxLon: -35 },  // South America
        { minLat: 35, maxLat: 70, minLon: -10, maxLon: 40 },   // Europe
        { minLat: -35, maxLat: 35, minLon: -18, maxLon: 51 },   // Africa
        { minLat: 5, maxLat: 75, minLon: 40, maxLon: 180 },    // Asia
        { minLat: -42, maxLat: -10, minLon: 112, maxLon: 154 }  // Australia
    ];
    
    // Sample sparse points
    for (let c of continentBounds) {
        for (let lat = c.minLat; lat <= c.maxLat; lat += 6) {
            for (let lon = c.minLon; lon <= c.maxLon; lon += 6) {
                // Add noise for realistic continental shapes
                if (Math.random() > 0.35) {
                    LAND_COORDINATES.push({
                        lat: lat + (Math.random() - 0.5) * 3,
                        lon: lon + (Math.random() - 0.5) * 3
                    });
                }
            }
        }
    }
}
initLandCoordinates();

// 3D vector helper functions
function latLonToVector3(lat, lon, radius = 1) {
    const phi = (90 - lat) * Math.PI / 180;
    const theta = (lon + 180) * Math.PI / 180;
    
    return {
        x: -(radius * Math.sin(phi) * Math.sin(theta)),
        y: radius * Math.cos(phi),
        z: radius * Math.sin(phi) * Math.cos(theta)
    };
}

function rotateY(v, angle) {
    const cos = Math.cos(angle);
    const sin = Math.sin(angle);
    return {
        x: v.x * cos - v.z * sin,
        y: v.y,
        z: v.x * sin + v.z * cos
    };
}

// Spherical linear interpolation (Slerp) approximation
function getSlerpPoint(v1, v2, t, radius) {
    // Basic linear interpolation followed by normalization to project onto the sphere surface
    const x = v1.x + (v2.x - v1.x) * t;
    const y = v1.y + (v2.y - v1.y) * t;
    const z = v1.z + (v2.z - v1.z) * t;
    const len = Math.sqrt(x*x + y*y + z*z);
    
    return {
        x: (x / len) * radius,
        y: (y / len) * radius,
        z: (z / len) * radius
    };
}

// ══════════════════════════════════════════════════════════════════════════════
// CLASS: CYBERMAP (3D WIREFRAME NEON GLOBE)
// ══════════════════════════════════════════════════════════════════════════════
class CyberMap {
    constructor(canvasId) {
        this.canvas = document.getElementById(canvasId);
        if (!this.canvas) return;
        this.ctx = this.canvas.getContext('2d');
        
        this.attacks = [];
        this.explosions = [];
        this.shieldFlashes = [];
        this.filterType = 'ALL';
        
        this.rotationAngle = 0;
        this.globeRadius = 0;
        
        this.mistralNode = { name: "MISTRAL CENTER", country: "Россия", code: "RU", lat: 55.75, lon: 37.61 }; // Moscow
        this.remonNode = { name: "REMON WEBSITE", host: "raemon.ru", lat: 59.93, lon: 30.36 }; // St. Petersburg
        
        this.resize();
        window.addEventListener('resize', () => this.resize());
        
        this.animate = this.animate.bind(this);
        requestAnimationFrame(this.animate);
    }
    
    resize() {
        if (!this.canvas) return;
        const rect = this.canvas.getBoundingClientRect();
        this.canvas.width = rect.width;
        this.canvas.height = rect.height;
        this.width = this.canvas.width;
        this.height = this.canvas.height;
        
        // Dynamic radius fitting
        this.globeRadius = Math.min(this.width, this.height) * 0.38;
        this.cx = this.width / 2;
        this.cy = this.height / 2;
    }
    
    animateAttack(geoPayload, type = 'Intrusion') {
        if (!geoPayload) return;
        
        let lat = geoPayload.lat;
        let lon = geoPayload.lon;
        if (lat === undefined || lon === undefined) {
            lat = 55.75;
            lon = 37.61;
        }
        
        if (this.filterType && this.filterType !== 'ALL') {
            const tLower = (type || '').toLowerCase();
            if (this.filterType === 'INTRUSION' && !tLower.includes('intrusion') && !tLower.includes('scan') && !tLower.includes('phish') && !tLower.includes('malware')) return;
            if (this.filterType === 'DDOS' && !tLower.includes('ddos') && !tLower.includes('flood') && !tLower.includes('syn')) return;
            if (this.filterType === 'BRUTEFORCE' && !tLower.includes('brute') && !tLower.includes('login') && !tLower.includes('auth')) return;
        }
        
        const isWeb = (type || '').toLowerCase().includes('sql') || (type || '').toLowerCase().includes('xss') || (type || '').toLowerCase().includes('web') || (type || '').toLowerCase().includes('honeypot');
        const target = isWeb ? this.remonNode : this.mistralNode;
        
        // Color mapping severity / reputation
        let color = '#3B82F6'; // Blue
        if (geoPayload.reputation > 70) color = '#EF4444'; // Red
        else if (geoPayload.reputation > 40) color = '#F59E0B'; // Orange
        
        const attack = {
            id: Math.random().toString(36).substring(2),
            srcLat: lat,
            srcLon: lon,
            destLat: target.lat,
            destLon: target.lon,
            progress: 0,
            speed: 0.008 + Math.random() * 0.012,
            color,
            ip: geoPayload.ip || 'Локальный IP',
            country: geoPayload.country || 'Локальная сеть / РФ',
            code: geoPayload.code || 'RU',
            isp: geoPayload.isp || 'Внутренний провайдер',
            type
        };
        
        this.attacks.push(attack);
        
        // Also trigger Docker Network graph attack animation if active
        if (window.dockerTopologyMap) {
            window.dockerTopologyMap.triggerAttackAnimation(type);
        }
        
        // Append entry to Cyber Intel Stream
        const feed = document.getElementById('map-log-feed');
        if (feed) {
            const entry = document.createElement('div');
            entry.style.cssText = `
                padding: 6px 8px;
                background: rgba(10,14,25,0.7);
                border-radius: 4px;
                border-left: 2px solid ${color};
                font-size: 10px;
                display: flex;
                flex-direction: column;
                gap: 2px;
                animation: slideIn 0.3s ease forwards;
            `;
            
            const time = new Date().toLocaleTimeString();
            const flag = geoPayload.code ? `<span style="font-size:11px; margin-right:4px;">${this.getFlagEmoji(geoPayload.code)}</span>` : '';
            
            entry.innerHTML = `
                <div style="display:flex; justify-content:space-between; font-weight:700;">
                    <span style="color:${color}">${type.toUpperCase()}</span>
                    <span style="color:var(--muted)">${time}</span>
                </div>
                <div style="color:#ccc;">${flag}<strong>${geoPayload.ip || '—'}</strong> (${geoPayload.country || '—'})</div>
                <div style="color:var(--muted); font-size:9px; font-family:monospace; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">ISP: ${geoPayload.isp || '—'}</div>
            `;
            
            feed.insertBefore(entry, feed.firstChild);
            if (feed.children.length > 25) {
                feed.removeChild(feed.lastChild);
            }
        }
    }
    
    getFlagEmoji(countryCode) {
        if (!countryCode || countryCode === '?') return '';
        return `[${countryCode.toUpperCase()}]`;
    }
    
    createExplosion(lat, lon, color) {
        this.explosions.push({
            lat, lon,
            radius: 1,
            maxRadius: 25,
            alpha: 1,
            color
        });
    }
    
    createShieldFlash(lat, lon, color, ip) {
        this.shieldFlashes.push({
            lat, lon,
            radius: 8,
            maxRadius: 22,
            alpha: 1.0,
            color: '#06B6D4',
            ip
        });
    }
    
    animate() {
        if (!this.canvas) return;
        this.ctx.clearRect(0, 0, this.width, this.height);
        
        // Auto rotate
        this.rotationAngle += 0.0035;
        const r = this.globeRadius;
        
        // 1. Draw glowing background sphere
        const radGrad = this.ctx.createRadialGradient(this.cx, this.cy, r * 0.4, this.cx, this.cy, r);
        radGrad.addColorStop(0, '#040815');
        radGrad.addColorStop(0.7, '#070f2b');
        radGrad.addColorStop(1, '#020205');
        
        this.ctx.fillStyle = radGrad;
        this.ctx.beginPath();
        this.ctx.arc(this.cx, this.cy, r, 0, Math.PI * 2);
        this.ctx.fill();
        
        // Outer glow circle
        this.ctx.strokeStyle = 'rgba(0, 150, 255, 0.25)';
        this.ctx.lineWidth = 2;
        this.ctx.shadowBlur = 15;
        this.ctx.shadowColor = '#0080ff';
        this.ctx.stroke();
        
        this.ctx.shadowBlur = 0; // Reset shadow
        
        // 2. Draw rotating wireframe grid lines (lat/lon)
        this.ctx.strokeStyle = 'rgba(0, 150, 255, 0.08)';
        this.ctx.lineWidth = 1;
        
        // Draw horizontal latitudes
        for (let lat = -75; lat <= 75; lat += 15) {
            const rad = lat * Math.PI / 180;
            const h = r * Math.sin(rad);
            const w = r * Math.cos(rad);
            // Draw ellipse projected onto 2D canvas
            this.ctx.beginPath();
            this.ctx.ellipse(this.cx, this.cy + h, w, w * 0.15, 0, 0, Math.PI * 2);
            this.ctx.stroke();
        }
        
        // Draw rotating vertical longitudes
        for (let lon = 0; lon < 180; lon += 20) {
            const rad = (lon + this.rotationAngle * 180 / Math.PI) * Math.PI / 180;
            const w = r * Math.cos(rad);
            this.ctx.beginPath();
            this.ctx.ellipse(this.cx, this.cy, Math.abs(w), r, 0, 0, Math.PI * 2);
            this.ctx.stroke();
        }
        
        // 3. Draw rotating land dots (mapping geographical points onto 3D sphere)
        for (let dot of LAND_COORDINATES) {
            const vRaw = latLonToVector3(dot.lat, dot.lon, r);
            const vRot = rotateY(vRaw, this.rotationAngle);
            
            // Only draw dots on the front side (Z > 0)
            if (vRot.z > 0) {
                const alpha = (vRot.z / r) * 0.25; // fade near edges
                this.ctx.fillStyle = `rgba(0, 180, 255, ${alpha})`;
                this.ctx.fillRect(this.cx + vRot.x - 1, this.cy - vRot.y - 1, 2, 2);
            }
        }
        
        // 4. Draw fixed/target hubs on the globe surface
        const drawHub = (node, name, color) => {
            const vRaw = latLonToVector3(node.lat, node.lon, r);
            const vRot = rotateY(vRaw, this.rotationAngle);
            if (vRot.z > 0) {
                const px = this.cx + vRot.x;
                const py = this.cy - vRot.y;
                
                // Ring pulses
                const scale = (Date.now() * 0.015) % 15;
                this.ctx.strokeStyle = color + `${1 - scale / 15}`;
                this.ctx.lineWidth = 1;
                this.ctx.beginPath();
                this.ctx.arc(px, py, scale, 0, Math.PI * 2);
                this.ctx.stroke();
                
                // Core dot
                this.ctx.fillStyle = color;
                this.ctx.beginPath();
                this.ctx.arc(px, py, 4, 0, Math.PI * 2);
                this.ctx.fill();
                
                this.ctx.fillStyle = '#fff';
                this.ctx.font = "bold 8px 'JetBrains Mono', monospace";
                this.ctx.textAlign = 'center';
                this.ctx.fillText(name, px, py - 10);
            }
        };
        drawHub(this.mistralNode, "MISTRAL HUB", "#22C55E");
        drawHub(this.remonNode, "REMON WAF", "#06B6D4");
        
        // 5. Update & Draw 3D Spherical Attack Arcs
        for (let i = this.attacks.length - 1; i >= 0; i--) {
            const a = this.attacks[i];
            a.progress += a.speed;
            
            const isQuarantined = window.quarantinedIps && window.quarantinedIps.some(q => q.ip === a.ip);
            
            if (a.progress >= 1) {
                if (isQuarantined) {
                    this.createShieldFlash(a.destLat, a.destLon, a.color, a.ip);
                } else {
                    this.createExplosion(a.destLat, a.destLon, a.color);
                }
                this.attacks.splice(i, 1);
                continue;
            }
            
            const vSrc = latLonToVector3(a.srcLat, a.srcLon, r);
            const vDest = latLonToVector3(a.destLat, a.destLon, r);
            
            // Build intermediate points to draw standard 3D arcs
            this.ctx.beginPath();
            let isFirst = true;
            let frontCount = 0;
            
            const pointsCount = 20;
            for (let t = 0; t <= 1; t += 1/pointsCount) {
                // Calculate spherical slerp dot on surface
                const surfaceVec = getSlerpPoint(vSrc, vDest, t, r);
                
                // Add height offset (the arc shape)
                const height = Math.sin(t * Math.PI) * (r * 0.15); // max height
                const arcVec = {
                    x: surfaceVec.x + (surfaceVec.x / r) * height,
                    y: surfaceVec.y + (surfaceVec.y / r) * height,
                    z: surfaceVec.z + (surfaceVec.z / r) * height
                };
                
                // Rotate vector
                const rotVec = rotateY(arcVec, this.rotationAngle);
                
                if (rotVec.z > 0) {
                    frontCount++;
                    const px = this.cx + rotVec.x;
                    const py = this.cy - rotVec.y;
                    if (isFirst) {
                        this.ctx.moveTo(px, py);
                        isFirst = false;
                    } else {
                        this.ctx.lineTo(px, py);
                    }
                }
            }
            
            if (frontCount > 2) {
                this.ctx.strokeStyle = a.color;
                this.ctx.globalAlpha = 0.35;
                this.ctx.lineWidth = 1.5;
                this.ctx.stroke();
                this.ctx.globalAlpha = 1.0;
            }
            
            // Flying packet
            const midSurface = getSlerpPoint(vSrc, vDest, a.progress, r);
            const height = Math.sin(a.progress * Math.PI) * (r * 0.15);
            const packetVec = {
                x: midSurface.x + (midSurface.x / r) * height,
                y: midSurface.y + (midSurface.y / r) * height,
                z: midSurface.z + (midSurface.z / r) * height
            };
            const rotPacket = rotateY(packetVec, this.rotationAngle);
            
            if (rotPacket.z > 0) {
                const px = this.cx + rotPacket.x;
                const py = this.cy - rotPacket.y;
                
                // Draw light packet
                this.ctx.fillStyle = a.color;
                this.ctx.beginPath();
                this.ctx.arc(px, py, 3, 0, Math.PI * 2);
                this.ctx.fill();
                
                // Draw label for origin at progress = 0
                if (a.progress < 0.25) {
                    const rotSrc = rotateY(vSrc, this.rotationAngle);
                    if (rotSrc.z > 0) {
                        this.ctx.fillStyle = a.color;
                        this.ctx.font = "bold 8px 'JetBrains Mono', monospace";
                        this.ctx.textAlign = 'center';
                        this.ctx.fillText(`${a.code} [${a.ip}]`, this.cx + rotSrc.x, this.cy - rotSrc.y - 6);
                    }
                }
            }
        }
        
        // 6. Update & Draw Explosions on 3D surface
        for (let i = this.explosions.length - 1; i >= 0; i--) {
            const ex = this.explosions[i];
            ex.radius += (ex.maxRadius - ex.radius) * 0.1;
            ex.alpha -= 0.035;
            
            if (ex.alpha <= 0) {
                this.explosions.splice(i, 1);
                continue;
            }
            
            const vRaw = latLonToVector3(ex.lat, ex.lon, r);
            const vRot = rotateY(vRaw, this.rotationAngle);
            
            if (vRot.z > 0) {
                const px = this.cx + vRot.x;
                const py = this.cy - vRot.y;
                
                this.ctx.save();
                this.ctx.globalAlpha = ex.alpha;
                this.ctx.strokeStyle = ex.color;
                this.ctx.lineWidth = 2;
                this.ctx.beginPath();
                this.ctx.arc(px, py, ex.radius, 0, Math.PI * 2);
                this.ctx.stroke();
                
                // Spark particles
                for (let j = 0; j < 8; j++) {
                    const ang = (j * Math.PI / 4) + (ex.radius * 0.05);
                    const sx = px + Math.cos(ang) * (ex.radius * 1.2);
                    const sy = py + Math.sin(ang) * (ex.radius * 1.2);
                    this.ctx.fillStyle = ex.color;
                    this.ctx.fillRect(sx, sy, 2, 2);
                }
                this.ctx.restore();
            }
        }
        
        // 7. Update & Draw WAF Shield Flashes
        for (let i = this.shieldFlashes.length - 1; i >= 0; i--) {
            const sf = this.shieldFlashes[i];
            sf.radius += (sf.maxRadius - sf.radius) * 0.15;
            sf.alpha -= 0.04;
            
            if (sf.alpha <= 0) {
                this.shieldFlashes.splice(i, 1);
                continue;
            }
            
            const vRaw = latLonToVector3(sf.lat, sf.lon, r);
            const vRot = rotateY(vRaw, this.rotationAngle);
            
            if (vRot.z > 0) {
                const px = this.cx + vRot.x;
                const py = this.cy - vRot.y;
                
                this.ctx.save();
                this.ctx.globalAlpha = sf.alpha;
                this.ctx.strokeStyle = sf.color;
                this.ctx.lineWidth = 2;
                this.ctx.beginPath();
                this.ctx.arc(px, py, sf.radius, 0, Math.PI * 2);
                this.ctx.stroke();
                
                // Shield hex lines indicator
                this.ctx.strokeStyle = 'rgba(6, 182, 212, 0.2)';
                this.ctx.lineWidth = 4;
                this.ctx.beginPath();
                this.ctx.arc(px, py, sf.radius + 3, 0, Math.PI * 2);
                this.ctx.stroke();
                
                this.ctx.fillStyle = '#06B6D4';
                this.ctx.font = "bold 8px 'JetBrains Mono', monospace";
                this.ctx.textAlign = 'center';
                this.ctx.fillText("WAF BLOCKED", px, py + sf.radius + 10);
                this.ctx.restore();
            }
        }
        
        requestAnimationFrame(this.animate);
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// CLASS: DOCKER NETWORK TOPOLOGY GRAPH (VISUAL CONTAINER MAP)
// ══════════════════════════════════════════════════════════════════════════════
class DockerTopologyMap {
    constructor(canvasId) {
        this.canvas = document.getElementById(canvasId);
        if (!this.canvas) return;
        this.ctx = this.canvas.getContext('2d');
        
        this.nodes = [];
        this.links = [];
        this.packets = [];
        
        this.hoveredNode = null;
        
        this.resize();
        window.addEventListener('resize', () => this.resize());
        this.initTopology();
        
        // Mouse move listener for node hovering
        this.canvas.addEventListener('mousemove', (e) => this.handleMouseMove(e));
        
        this.animate = this.animate.bind(this);
        requestAnimationFrame(this.animate);
    }
    
    resize() {
        if (!this.canvas) return;
        const rect = this.canvas.getBoundingClientRect();
        this.canvas.width = rect.width;
        this.canvas.height = rect.height;
        this.width = this.canvas.width;
        this.height = this.canvas.height;
        this.recalculateNodePositions();
    }
    
    initTopology() {
        // Define docker nodes
        this.nodes = [
            { id: 'server', name: 'Mistral Server', label: 'SOC Core Agent', x: 0.5, y: 0.35, size: 28, color: '#22C55E', shadow: '#22C55E', status: 'ONLINE', details: 'Node.js Core SIEM / SOAR' },
            { id: 'nginx',  name: 'Nginx WAF', label: 'OpenResty Proxy', x: 0.5, y: 0.7,  size: 24, color: '#06B6D4', shadow: '#06B6D4', status: 'ONLINE', details: 'Reverse Proxy & Traffic Inspect' },
            { id: 'web_fe', name: 'Next.js FE', label: 'Remon Client', x: 0.22, y: 0.8, size: 20, color: '#3B82F6', shadow: '#3B82F6', status: 'ONLINE', details: 'Remon Website Frontend' },
            { id: 'web_be', name: 'Express API', label: 'Remon Backend', x: 0.78, y: 0.8, size: 20, color: '#3B82F6', shadow: '#3B82F6', status: 'ONLINE', details: 'Remon Express REST Endpoints' },
            { id: 'pg_db',  name: 'Postgres DB', label: 'Data Warehouse', x: 0.82, y: 0.45, size: 20, color: '#A855F7', shadow: '#A855F7', status: 'ONLINE', details: 'Relational Database Store' },
            { id: 'decoy',  name: 'Honeypot', label: 'Port 8081 Gateway', x: 0.18, y: 0.3, size: 22, color: '#EAB308', shadow: '#EAB308', status: 'ONLINE', details: 'Decoy Payment Gate Trigger' }
        ];
        
        // Connections
        this.links = [
            { from: 'nginx', to: 'server', color: 'rgba(6, 182, 212, 0.25)', label: 'Syslogs' },
            { from: 'web_fe', to: 'nginx', color: 'rgba(59, 130, 246, 0.2)' },
            { from: 'web_be', to: 'nginx', color: 'rgba(59, 130, 246, 0.2)' },
            { from: 'web_be', to: 'pg_db', color: 'rgba(168, 85, 247, 0.25)' },
            { from: 'decoy', to: 'server', color: 'rgba(234, 179, 8, 0.3)' }
        ];
        
        this.recalculateNodePositions();
    }
    
    recalculateNodePositions() {
        if (!this.width || !this.height) return;
        this.nodes.forEach(n => {
            n.px = n.x * this.width;
            n.py = n.y * this.height;
        });
    }
    
    handleMouseMove(e) {
        const rect = this.canvas.getBoundingClientRect();
        const mx = e.clientX - rect.left;
        const my = e.clientY - rect.top;
        
        let found = null;
        for (let n of this.nodes) {
            const dx = mx - n.px;
            const dy = my - n.py;
            if (Math.sqrt(dx*dx + dy*dy) < n.size + 4) {
                found = n;
                break;
            }
        }
        this.hoveredNode = found;
        this.canvas.style.cursor = found ? 'pointer' : 'default';
    }
    
    triggerAttackAnimation(attackType) {
        const typeLower = (attackType || '').toLowerCase();
        
        let targetId = 'server'; // default
        let startX = Math.random() > 0.5 ? 0 : this.width;
        let startY = Math.random() * this.height;
        
        if (typeLower.includes('sql') || typeLower.includes('xss') || typeLower.includes('waf')) {
            targetId = 'nginx';
        } else if (typeLower.includes('honeypot') || typeLower.includes('8081')) {
            targetId = 'decoy';
        }
        
        const targetNode = this.nodes.find(n => n.id === targetId);
        if (targetNode) {
            // Launch red attack packet from edge of network
            this.packets.push({
                x: startX,
                y: startY,
                tx: targetNode.px,
                ty: targetNode.py,
                progress: 0,
                speed: 0.02,
                color: '#EF4444',
                size: 4,
                isAttack: true,
                targetId: targetId
            });
        }
    }
    
    animate() {
        if (!this.canvas) return;
        this.ctx.clearRect(0, 0, this.width, this.height);
        const now = Date.now();
        
        // Sync container statuses from live system metrics
        if (window.lastMetricsData && window.lastMetricsData.docker) {
            this.nodes.forEach(n => {
                // Find matching docker status
                let containerName = '';
                if (n.id === 'web_fe') containerName = 'frontend';
                else if (n.id === 'web_be') containerName = 'backend';
                else if (n.id === 'pg_db') containerName = 'db';
                else if (n.id === 'nginx') containerName = 'nginx';
                
                if (containerName) {
                    const dockerInfo = window.lastMetricsData.docker.find(d => String(d.name || '').includes(containerName));
                    if (dockerInfo) {
                        n.status = dockerInfo.status.includes('Up') ? 'ONLINE' : 'OFFLINE';
                        n.color = n.status === 'ONLINE' ? (n.id === 'nginx' ? '#06B6D4' : '#3B82F6') : '#ef4444';
                    }
                }
            });
        }
        
        // 1. Draw connections links
        this.links.forEach(l => {
            const fromNode = this.nodes.find(n => n.id === l.from);
            const toNode = this.nodes.find(n => n.id === l.to);
            if (!fromNode || !toNode) return;
            
            // Draw link line
            this.ctx.strokeStyle = l.color || 'rgba(255,255,255,0.1)';
            this.ctx.lineWidth = 2;
            this.ctx.beginPath();
            this.ctx.moveTo(fromNode.px, fromNode.py);
            this.ctx.lineTo(toNode.px, toNode.py);
            this.ctx.stroke();
            
            // Add tiny moving flow dot for network traffic visualization
            const flowSpeed = 0.0015;
            const t = (now * flowSpeed) % 1.0;
            const fx = fromNode.px + (toNode.px - fromNode.px) * t;
            const fy = fromNode.py + (toNode.py - fromNode.py) * t;
            
            this.ctx.fillStyle = fromNode.color;
            this.ctx.beginPath();
            this.ctx.arc(fx, fy, 2, 0, Math.PI * 2);
            this.ctx.fill();
        });
        
        // 2. Update and Draw packets (attacks or alerts)
        for (let i = this.packets.length - 1; i >= 0; i--) {
            const p = this.packets[i];
            p.progress += p.speed;
            
            if (p.progress >= 1) {
                // Packet reached target: create a shockwave flash on target node
                const targetNode = this.nodes.find(n => n.id === p.targetId);
                if (targetNode) {
                    targetNode.flash = 1.0;
                    targetNode.shake = 10;
                    
                    // If it was an attack packet reaching WAF/Honeypot, trigger alert flow to Server Core
                    if (p.isAttack && p.targetId !== 'server') {
                        const serverNode = this.nodes.find(n => n.id === 'server');
                        if (serverNode) {
                            this.packets.push({
                                x: targetNode.px,
                                y: targetNode.py,
                                tx: serverNode.px,
                                ty: serverNode.py,
                                progress: 0,
                                speed: 0.03,
                                color: '#EAB308',
                                size: 3,
                                isAttack: false,
                                targetId: 'server'
                            });
                        }
                    }
                }
                this.packets.splice(i, 1);
                continue;
            }
            
            const currX = p.x + (p.tx - p.x) * p.progress;
            const currY = p.y + (p.ty - p.y) * p.progress;
            
            this.ctx.shadowBlur = p.isAttack ? 10 : 5;
            this.ctx.shadowColor = p.color;
            this.ctx.fillStyle = p.color;
            this.ctx.beginPath();
            this.ctx.arc(currX, currY, p.size, 0, Math.PI * 2);
            this.ctx.fill();
            this.ctx.shadowBlur = 0; // reset
        }
        
        // 3. Draw container nodes
        this.nodes.forEach(n => {
            n.flash = n.flash ? n.flash - 0.05 : 0;
            if (n.flash < 0) n.flash = 0;
            
            // Node shake animation on impact
            let ox = 0, oy = 0;
            if (n.shake) {
                ox = (Math.random() - 0.5) * n.shake;
                oy = (Math.random() - 0.5) * n.shake;
                n.shake = n.shake - 1;
                if (n.shake < 0) n.shake = 0;
            }
            
            const nx = n.px + ox;
            const ny = n.py + oy;
            
            // Base shadow glow for nodes
            this.ctx.shadowBlur = n.status === 'ONLINE' ? 12 + Math.sin(now * 0.005) * 4 : 4;
            this.ctx.shadowColor = n.color;
            
            // Draw central node pulse rings
            if (n.id === 'server' && n.status === 'ONLINE') {
                const rScale = (now * 0.015) % 25;
                this.ctx.strokeStyle = `rgba(34, 197, 94, ${1 - rScale/25})`;
                this.ctx.lineWidth = 1;
                this.ctx.beginPath();
                this.ctx.arc(nx, ny, n.size + rScale, 0, Math.PI * 2);
                this.ctx.stroke();
            }
            
            // Node core fill
            this.ctx.fillStyle = n.flash > 0 ? `rgba(239, 68, 68, ${n.flash})` : '#070c19';
            this.ctx.strokeStyle = n.color;
            this.ctx.lineWidth = 3;
            this.ctx.beginPath();
            this.ctx.arc(nx, ny, n.size, 0, Math.PI * 2);
            this.ctx.fill();
            this.ctx.stroke();
            
            this.ctx.shadowBlur = 0; // reset
            
            // Node texts
            this.ctx.fillStyle = '#fff';
            this.ctx.font = "bold 9px 'JetBrains Mono', monospace";
            this.ctx.textAlign = 'center';
            this.ctx.fillText(n.name, nx, ny + 2);
            
            this.ctx.fillStyle = 'var(--muted)';
            this.ctx.font = "8px 'Inter', sans-serif";
            this.ctx.fillText(n.label, nx, ny + n.size + 10);
            
            // Draw status badge
            const bColor = n.status === 'ONLINE' ? '#22C55E' : '#EF4444';
            this.ctx.fillStyle = bColor;
            this.ctx.font = "bold 7px 'JetBrains Mono', monospace";
            this.ctx.fillText(n.status, nx, ny - n.size - 4);
        });
        
        // 4. Draw detailed hover popover/tooltip
        if (this.hoveredNode) {
            const n = this.hoveredNode;
            const tx = n.px;
            const ty = n.py - n.size - 24;
            
            this.ctx.save();
            this.ctx.fillStyle = 'rgba(10,14,25,0.95)';
            this.ctx.strokeStyle = n.color;
            this.ctx.lineWidth = 1.5;
            this.ctx.shadowBlur = 10;
            this.ctx.shadowColor = 'rgba(0,0,0,0.5)';
            
            const w = 150;
            const h = 50;
            this.ctx.beginPath();
            this.ctx.roundRect(tx - w/2, ty - h/2, w, h, 6);
            this.ctx.fill();
            this.ctx.stroke();
            this.ctx.shadowBlur = 0;
            
            // Text contents in popup
            this.ctx.fillStyle = '#fff';
            this.ctx.font = "bold 9px 'JetBrains Mono', monospace";
            this.ctx.textAlign = 'left';
            this.ctx.fillText(n.name, tx - w/2 + 8, ty - h/2 + 14);
            
            this.ctx.fillStyle = 'var(--muted)';
            this.ctx.font = "8px 'Inter', sans-serif";
            this.ctx.fillText(n.details, tx - w/2 + 8, ty - h/2 + 28);
            
            const stateColor = n.status === 'ONLINE' ? 'var(--green)' : 'var(--red)';
            this.ctx.fillStyle = stateColor;
            this.ctx.font = "bold 8px 'JetBrains Mono', monospace";
            this.ctx.fillText(`STATUS: ${n.status}`, tx - w/2 + 8, ty - h/2 + 42);
            this.ctx.restore();
        }
        
        requestAnimationFrame(this.animate);
    }
}

// Bind to window context
window.CyberMap = CyberMap;
window.DockerTopologyMap = DockerTopologyMap;
window.MiniGlobeRenderer = MiniGlobeRenderer;

window.setMapFilter = function(filter) {
    if (cyberMap) {
        cyberMap.filterType = filter;
        cyberMap.attacks = []; // Clear current flying lines
        
        if (window.allIncidents && Array.isArray(window.allIncidents)) {
            // Filter historical incidents
            const matching = window.allIncidents.filter(inc => {
                if (!inc.geo) return false;
                const typeLower = (inc.type || '').toLowerCase();
                const descLower = (inc.description || '').toLowerCase();
                const monitorLower = (inc.monitor || '').toLowerCase();
                
                if (filter === 'ALL') return true;
                if (filter === 'INTRUSION') {
                    return typeLower.includes('intrusion') || typeLower.includes('scan') || typeLower.includes('phish') || typeLower.includes('malware') || descLower.includes('intrusion') || descLower.includes('scan') || descLower.includes('phish') || descLower.includes('malware');
                }
                if (filter === 'DDOS') {
                    return typeLower.includes('ddos') || typeLower.includes('flood') || typeLower.includes('syn') || descLower.includes('ddos') || descLower.includes('flood') || descLower.includes('syn') || monitorLower.includes('ddos');
                }
                if (filter === 'BRUTEFORCE') {
                    return typeLower.includes('brute') || typeLower.includes('login') || typeLower.includes('auth') || descLower.includes('brute') || descLower.includes('login') || descLower.includes('auth');
                }
                return false;
            });
            
            // Limit to the 20 most recent
            const recent = matching.slice(0, 20);
            recent.forEach(inc => {
                cyberMap.animateAttack(inc.geo, inc.type);
            });
        }
    }
    document.querySelectorAll('[id^="map-filter-"]').forEach(btn => {
        btn.classList.remove('active');
        btn.style.background = 'transparent';
        btn.style.borderColor = 'var(--border)';
    });
    const activeBtn = document.getElementById('map-filter-' + filter.toLowerCase());
    if (activeBtn) {
        activeBtn.classList.add('active');
        activeBtn.style.background = 'rgba(0, 150, 255, 0.12)';
        activeBtn.style.borderColor = 'var(--cyan)';
    }
};
