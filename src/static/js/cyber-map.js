// ══════════════════════════════════════════════════════════════════════════════
// CYBER THREAT MAP & ROTATING MINI-GLOBE MODULE
// ══════════════════════════════════════════════════════════════════════════════

// Simplified vector continent circles/ellipses for offline-compatible grid generation
const LAND_REGIONS = [
    { cx: 0.22, cy: 0.35, rx: 0.10, ry: 0.12, tilt: -0.05 }, // North America
    { cx: 0.18, cy: 0.20, rx: 0.12, ry: 0.09, tilt: 0.1 },  // Canada/Alaska
    { cx: 0.40, cy: 0.13, rx: 0.05, ry: 0.06, tilt: 0.2 },  // Greenland
    { cx: 0.32, cy: 0.68, rx: 0.07, ry: 0.17, tilt: 0.1 },  // South America
    { cx: 0.52, cy: 0.56, rx: 0.09, ry: 0.15, tilt: -0.05 }, // Africa
    { cx: 0.52, cy: 0.25, rx: 0.07, ry: 0.07, tilt: -0.1 },  // Europe
    { cx: 0.53, cy: 0.17, rx: 0.04, ry: 0.06, tilt: 0.3 },  // Scandinavia
    { cx: 0.60, cy: 0.42, rx: 0.06, ry: 0.05, tilt: -0.1 },  // Middle East
    { cx: 0.72, cy: 0.25, rx: 0.18, ry: 0.12, tilt: 0 },     // Siberia/North Asia
    { cx: 0.74, cy: 0.38, rx: 0.12, ry: 0.08, tilt: -0.1 }, // China/East Asia
    { cx: 0.71, cy: 0.48, rx: 0.03, ry: 0.05, tilt: 0.25 }, // India
    { cx: 0.81, cy: 0.56, rx: 0.05, ry: 0.07, tilt: -0.3 }, // SE Asia/Indonesia
    { cx: 0.85, cy: 0.75, rx: 0.08, ry: 0.07, tilt: 0.1 },  // Australia
    { cx: 0.86, cy: 0.32, rx: 0.015, ry: 0.04, tilt: -0.4 } // Japan
];

// Helper to determine if normalized coordinates lie on land
function checkInLand(px, py) {
    for (let r of LAND_REGIONS) {
        let dx = px - r.cx;
        let dy = py - r.cy;
        if (r.tilt) {
            let cos = Math.cos(r.tilt);
            let sin = Math.sin(r.tilt);
            let rx = dx * cos - dy * sin;
            let ry = dx * sin + dy * cos;
            dx = rx;
            dy = ry;
        }
        if ((dx * dx) / (r.rx * r.rx) + (dy * dy) / (r.ry * r.ry) <= 1) {
            return true;
        }
    }
    return false;
}

// Convert Lat/Lon to XY on canvas
function latLonToCanvasXY(lat, lon, width, height) {
    // X maps from lon [-180, 180] to [0, width]
    const x = ((lon + 180) / 360) * width;
    // Y maps from lat [90, -90] to [0, height]
    const y = ((90 - lat) / 180) * height;
    return { x, y };
}

// Bezier interpolation helper
function getQuadBezierPoint(x1, y1, cx, cy, x2, y2, t) {
    const u = 1 - t;
    return {
        x: u * u * x1 + 2 * u * t * cx + t * t * x2,
        y: u * u * y1 + 2 * u * t * cy + t * t * y2
    };
}

// ══════════════════════════════════════════════════════════════════════════════
// CLASS: CYBERMAP
// ══════════════════════════════════════════════════════════════════════════════
class CyberMap {
    constructor(canvasId) {
        this.canvas = document.getElementById(canvasId);
        if (!this.canvas) return;
        this.ctx = this.canvas.getContext('2d');
        this.width = this.canvas.width;
        this.height = this.canvas.height;
        
        this.dots = [];
        this.attacks = [];
        this.explosions = [];
        this.filterType = 'ALL';
        this.targetNode = { country: "Россия", code: "RU", lat: 55.75, lon: 37.61 }; // Moscow
        
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
        this.initGrid();
    }
    
    initGrid() {
        this.dots = [];
        const step = 14; // Space between grid dots
        for (let x = 0; x < this.width; x += step) {
            for (let y = 0; y < this.height; y += step) {
                const px = x / this.width;
                const py = y / this.height;
                if (checkInLand(px, py)) {
                    this.dots.push({
                        x, y,
                        baseAlpha: 0.15 + Math.random() * 0.25,
                        phase: Math.random() * Math.PI * 2
                    });
                }
            }
        }
    }
    
    animateAttack(geoPayload, type = 'Intrusion') {
        if (!geoPayload || geoPayload.lat === undefined || geoPayload.lon === undefined) return;
        
        if (this.filterType && this.filterType !== 'ALL') {
            const tLower = (type || '').toLowerCase();
            if (this.filterType === 'INTRUSION' && !tLower.includes('intrusion') && !tLower.includes('scan') && !tLower.includes('phish') && !tLower.includes('malware')) return;
            if (this.filterType === 'DDOS' && !tLower.includes('ddos') && !tLower.includes('flood') && !tLower.includes('syn')) return;
            if (this.filterType === 'BRUTEFORCE' && !tLower.includes('brute') && !tLower.includes('login') && !tLower.includes('auth')) return;
        }
        
        const src = latLonToCanvasXY(geoPayload.lat, geoPayload.lon, this.width, this.height);
        const dest = latLonToCanvasXY(this.targetNode.lat, this.targetNode.lon, this.width, this.height);
        
        // Random control point offset for bezier arc height
        const dx = dest.x - src.x;
        const dy = dest.y - src.y;
        const distance = Math.sqrt(dx * dx + dy * dy);
        const arcHeight = Math.max(50, distance * 0.25);
        const cx = (src.x + dest.x) / 2;
        const cy = (src.y + dest.y) / 2 - arcHeight;
        
        // Color matching severity / reputation
        let color = '#3B82F6'; // Blue
        if (geoPayload.reputation > 70) color = '#EF4444'; // Red
        else if (geoPayload.reputation > 40) color = '#F59E0B'; // Orange
        
        const attack = {
            id: Math.random().toString(36).substring(2),
            x1: src.x, y1: src.y,
            x2: dest.x, y2: dest.y,
            cx, cy,
            progress: 0,
            speed: 0.01 + Math.random() * 0.015,
            color,
            ip: geoPayload.ip || 'Unknown IP',
            country: geoPayload.country || 'Unknown',
            code: geoPayload.code || '?',
            isp: geoPayload.isp || 'Unknown ISP',
            type
        };
        
        this.attacks.push(attack);
        
        // Append entry to Cyber Intel Stream
        const feed = document.getElementById('map-log-feed');
        if (feed) {
            const entry = document.createElement('div');
            entry.style.cssText = `
                padding: 6px 8px;
                background: rgba(255,255,255,0.02);
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
    
    createExplosion(x, y, color) {
        const particles = [];
        const count = 15;
        for (let i = 0; i < count; i++) {
            const angle = Math.random() * Math.PI * 2;
            const speed = 0.5 + Math.random() * 2;
            particles.push({
                x, y,
                vx: Math.cos(angle) * speed,
                vy: Math.sin(angle) * speed,
                alpha: 1,
                decay: 0.02 + Math.random() * 0.02
            });
        }
        
        this.explosions.push({
            x, y,
            radius: 1,
            maxRadius: 30 + Math.random() * 20,
            alpha: 1,
            color,
            particles
        });
    }
    
    animate() {
        if (!this.canvas) return;
        this.ctx.clearRect(0, 0, this.width, this.height);
        
        const now = Date.now();
        
        // 1. Draw grid dots (continents)
        for (let dot of this.dots) {
            const alpha = dot.baseAlpha + Math.sin(now * 0.0015 + dot.phase) * 0.08;
            this.ctx.fillStyle = `rgba(0, 180, 255, ${alpha})`;
            this.ctx.fillRect(dot.x, dot.y, 2, 2);
        }
        
        // 2. Draw destination hub (Moscow)
        const dest = latLonToCanvasXY(this.targetNode.lat, this.targetNode.lon, this.width, this.height);
        
        // Target pulse rings
        const ringRadius = (now * 0.02) % 40;
        this.ctx.strokeStyle = `rgba(34, 197, 94, ${1 - ringRadius / 40})`;
        this.ctx.lineWidth = 1;
        this.ctx.beginPath();
        this.ctx.arc(dest.x, dest.y, ringRadius, 0, Math.PI * 2);
        this.ctx.stroke();
        
        // Target core dot
        this.ctx.fillStyle = '#22C55E'; // green
        this.ctx.beginPath();
        this.ctx.arc(dest.x, dest.y, 4, 0, Math.PI * 2);
        this.ctx.fill();
        
        // Label
        this.ctx.fillStyle = '#22C55E';
        this.ctx.font = "bold 9px 'JetBrains Mono', monospace";
        this.ctx.textAlign = 'center';
        this.ctx.fillText("MISTRAL SERVER (RU)", dest.x, dest.y - 12);
        
        // 3. Update & Draw Attack Beziers
        for (let i = this.attacks.length - 1; i >= 0; i--) {
            const a = this.attacks[i];
            a.progress += a.speed;
            
            if (a.progress >= 1) {
                // Trigger destination explosion
                this.createExplosion(a.x2, a.y2, a.color);
                this.attacks.splice(i, 1);
                continue;
            }
            
            // Draw path curve
            this.ctx.beginPath();
            this.ctx.moveTo(a.x1, a.y1);
            this.ctx.quadraticCurveTo(a.cx, a.cy, a.x2, a.y2);
            this.ctx.strokeStyle = a.color;
            this.ctx.globalAlpha = 0.15;
            this.ctx.lineWidth = 1.5;
            this.ctx.stroke();
            this.ctx.globalAlpha = 1.0;
            
            // Draw flying light pulse
            const pt = getQuadBezierPoint(a.x1, a.y1, a.cx, a.cy, a.x2, a.y2, a.progress);
            this.ctx.fillStyle = a.color;
            this.ctx.beginPath();
            this.ctx.arc(pt.x, pt.y, 3, 0, Math.PI * 2);
            this.ctx.fill();
            
            // Source dot indicator
            this.ctx.fillStyle = a.color;
            this.ctx.beginPath();
            this.ctx.arc(a.x1, a.y1, 2, 0, Math.PI * 2);
            this.ctx.fill();
            this.ctx.fillText(`${a.code} [${a.ip}]`, a.x1, a.y1 - 6);
        }
        
        // 4. Update & Draw Explosions
        for (let i = this.explosions.length - 1; i >= 0; i--) {
            const ex = this.explosions[i];
            ex.radius += (ex.maxRadius - ex.radius) * 0.1;
            ex.alpha -= 0.03;
            
            if (ex.alpha <= 0) {
                this.explosions.splice(i, 1);
                continue;
            }
            
            // Draw ring
            this.ctx.strokeStyle = ex.color;
            this.ctx.globalAlpha = ex.alpha;
            this.ctx.lineWidth = 1.5;
            this.ctx.beginPath();
            this.ctx.arc(ex.x, ex.y, ex.radius, 0, Math.PI * 2);
            this.ctx.stroke();
            
            // Draw particles
            for (let p of ex.particles) {
                p.x += p.vx;
                p.y += p.vy;
                p.alpha -= p.decay;
                if (p.alpha > 0) {
                    this.ctx.fillStyle = ex.color;
                    this.ctx.globalAlpha = p.alpha;
                    this.ctx.fillRect(p.x, p.y, 2, 2);
                }
            }
            this.ctx.globalAlpha = 1.0; // reset
        }
        
        requestAnimationFrame(this.animate);
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// CLASS: MINIGLOBERENDERER
// ══════════════════════════════════════════════════════════════════════════════
class MiniGlobeRenderer {
    constructor(canvasId) {
        this.canvas = document.getElementById(canvasId);
        if (!this.canvas) return;
        this.ctx = this.canvas.getContext('2d');
        this.radius = this.canvas.width / 2 - 4;
        this.cx = this.canvas.width / 2;
        this.cy = this.canvas.height / 2;
        this.angle = 0;
        
        this.flashes = [];
        
        this.animate = this.animate.bind(this);
        requestAnimationFrame(this.animate);
    }
    
    animateThreat(geoPayload, techId) {
        if (!geoPayload) return;
        
        // Push a flash to the mini-globe
        this.flashes.push({
            phase: Math.random() * Math.PI * 2,
            radius: 1,
            maxRadius: 15,
            alpha: 1
        });
        
        if (techId) {
            // Trigger beautiful tracer to cell
            this.animateTracerToCell(techId, geoPayload);
        }
    }
    
    animateTracerToCell(techId, geoPayload) {
        const cell = document.getElementById(techId);
        if (!cell || !this.canvas) return;
        
        const globeRect = this.canvas.getBoundingClientRect();
        const cellRect = cell.getBoundingClientRect();
        
        const startX = globeRect.left + globeRect.width / 2 + window.scrollX;
        const startY = globeRect.top + globeRect.height / 2 + window.scrollY;
        const endX = cellRect.left + cellRect.width / 2 + window.scrollX;
        const endY = cellRect.top + cellRect.height / 2 + window.scrollY;
        
        // Color based on reputation
        let color = 'var(--blue)';
        if (geoPayload.reputation > 70) color = 'var(--red)';
        else if (geoPayload.reputation > 40) color = 'var(--orange)';
        
        const tracer = document.createElement('div');
        tracer.style.cssText = `
            position: absolute;
            left: ${startX}px;
            top: ${startY}px;
            width: 8px;
            height: 8px;
            background: ${color};
            border-radius: 50%;
            box-shadow: 0 0 10px ${color}, 0 0 20px ${color};
            z-index: 999999;
            pointer-events: none;
            transition: all 1.2s cubic-bezier(0.25, 0.46, 0.45, 0.94);
        `;
        document.body.appendChild(tracer);
        
        // Trigger motion next frame
        requestAnimationFrame(() => {
            tracer.style.left = `${endX}px`;
            tracer.style.top = `${endY}px`;
            tracer.style.transform = 'scale(0.5)';
        });
        
        setTimeout(() => {
            tracer.remove();
            
            // Impact flash at cell
            cell.style.background = 'rgba(255, 50, 50, 0.35)';
            cell.style.boxShadow = '0 0 15px rgba(255, 50, 50, 0.5)';
            cell.style.transition = 'all 0.1s';
            
            setTimeout(() => {
                cell.style.background = '';
                cell.style.boxShadow = '';
                cell.style.transition = '';
                cell.classList.add('active-threat');
            }, 300);
        }, 1200);
    }
    
    animate() {
        if (!this.canvas) return;
        this.ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);
        
        this.angle += 0.4; // rotation speed
        
        this.ctx.strokeStyle = 'rgba(0, 150, 255, 0.35)';
        this.ctx.lineWidth = 1;
        
        // Sphere outer circle boundary
        this.ctx.beginPath();
        this.ctx.arc(this.cx, this.cy, this.radius, 0, Math.PI * 2);
        this.ctx.stroke();
        
        // Latitudes (horizontal slices)
        for (let lat = -60; lat <= 60; lat += 30) {
            const rad = lat * Math.PI / 180;
            const h = this.radius * Math.sin(rad);
            const w = this.radius * Math.cos(rad);
            this.ctx.beginPath();
            this.ctx.ellipse(this.cx, this.cy + h, w, w * 0.15, 0, 0, Math.PI * 2);
            this.ctx.stroke();
        }
        
        // Longitudes (vertical slices rotating)
        for (let lon = 0; lon < 180; lon += 30) {
            const rad = (lon + this.angle) * Math.PI / 180;
            const w = this.radius * Math.cos(rad);
            this.ctx.beginPath();
            this.ctx.ellipse(this.cx, this.cy, Math.abs(w), this.radius, 0, 0, Math.PI * 2);
            this.ctx.stroke();
        }
        
        // Draw active threat flashes on globe core
        for (let i = this.flashes.length - 1; i >= 0; i--) {
            const f = this.flashes[i];
            f.radius += (f.maxRadius - f.radius) * 0.1;
            f.alpha -= 0.04;
            
            if (f.alpha <= 0) {
                this.flashes.splice(i, 1);
                continue;
            }
            
            this.ctx.strokeStyle = 'rgba(239, 68, 68, ' + f.alpha + ')';
            this.ctx.lineWidth = 1.5;
            this.ctx.beginPath();
            this.ctx.arc(this.cx, this.cy, f.radius, 0, Math.PI * 2);
            this.ctx.stroke();
        }
        
        requestAnimationFrame(this.animate);
    }
}

// Bind to window
window.CyberMap = CyberMap;
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
