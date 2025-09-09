// streaming.js - Kompletní StreamingManager
const config = require('./config');
const crypto = require('crypto');
const axios = require('axios');
const { performance } = require('perf_hooks');

class StreamingManager {
    constructor() {
        this.streamingMethod = config.getStreamingMethod();
        this.rateLimitMap = new Map();
        this.urlVerificationCache = new Map();
        this.serverMetrics = {
            totalRequests: 0,
            directRequests: 0,
            proxyRequests: 0,
            hybridRequests: 0,
            errors: 0,
            lastReset: Date.now()
        };
        
        // Cleanup rate limit map každých 5 minút
        setInterval(() => this.cleanupRateLimit(), 5 * 60 * 1000);
        
        // Reset metrics každú hodinu
        setInterval(() => this.resetMetrics(), 60 * 60 * 1000);
        
        console.log(`🚀 StreamingManager inicializovaný s metódou: ${this.streamingMethod}`);
    }

    /**
     * Hlavná funkcia pre spracovanie stream požiadavky
     */
    async handleStreamRequest(req, res, rdUrl, torrentInfo) {
        const startTime = performance.now();
        this.serverMetrics.totalRequests++;
        
        try {
            // Validácia vstupov
            this.validateInputs(rdUrl, torrentInfo);
            
            // Rate limiting check
            this.checkRateLimit(req.ip);
            
            let result;
            switch (this.streamingMethod) {
                case 'DIRECT':
                    this.serverMetrics.directRequests++;
                    result = await this.handleDirectStream(req, res, rdUrl, torrentInfo);
                    break;
                    
                case 'PROXY':
                    this.serverMetrics.proxyRequests++;
                    result = await this.handleProxyStream(req, res, rdUrl, torrentInfo);
                    break;
                    
                case 'HYBRID':
                    this.serverMetrics.hybridRequests++;
                    result = await this.handleHybridStream(req, res, rdUrl, torrentInfo);
                    break;
                    
                default:
                    console.warn(`Neznáma streaming metóda: ${this.streamingMethod}, používam PROXY`);
                    this.serverMetrics.proxyRequests++;
                    result = await this.handleProxyStream(req, res, rdUrl, torrentInfo);
                    break;
            }
            
            // Logovanie úspešného requestu
            this.logStreamRequest('SUCCESS', this.streamingMethod, torrentInfo, req.ip, performance.now() - startTime);
            return result;
            
        } catch (error) {
            this.serverMetrics.errors++;
            console.error('❌ Chyba pri streamingu:', error.message);
            
            // Fallback logika
            if (config.DIRECT_STREAMING.FALLBACK_TO_PROXY && 
                this.streamingMethod !== 'PROXY' && 
                !error.message.includes('Rate limit') &&
                !error.message.includes('Validation error')) {
                
                console.log('🔄 Pokúšam sa o fallback na proxy streaming...');
                try {
                    const fallbackResult = await this.handleProxyStream(req, res, rdUrl, torrentInfo);
                    this.logStreamRequest('FALLBACK_SUCCESS', 'PROXY', torrentInfo, req.ip, performance.now() - startTime);
                    return fallbackResult;
                } catch (fallbackError) {
                    console.error('❌ Fallback proxy tiež zlyhal:', fallbackError.message);
                }
            }
            
            // Error response
            this.logStreamRequest('ERROR', this.streamingMethod, torrentInfo, req.ip, performance.now() - startTime, error.message);
            
            if (!res.headersSent) {
                return res.status(500).json({ 
                    error: 'Chyba pri streamingu',
                    details: config.isDevelopment() ? error.message : 'Internal server error',
                    method: this.streamingMethod,
                    fallbackAvailable: config.DIRECT_STREAMING.FALLBACK_TO_PROXY && this.streamingMethod !== 'PROXY'
                });
            }
        }
    }

    /**
     * Direct streaming - redirect na Real-Debrid URL
     */
    async handleDirectStream(req, res, rdUrl, torrentInfo) {
        console.log(`🎬 Direct streaming: ${torrentInfo.title} (${this.formatFileSize(torrentInfo.size)})`);
        
        // Validácia URL
        if (!this.isValidRdUrl(rdUrl)) {
            throw new Error('Neplatné Real-Debrid URL');
        }

        // Test pripojenia k RD (ak je povolený)
        if (config.DIRECT_STREAMING.VERIFY_BEFORE_REDIRECT) {
            await this.verifyRdUrlAccessible(rdUrl);
        }

        // Vytvorenie finálneho URL
        let finalUrl = rdUrl;
        if (config.DIRECT_STREAMING.USE_SIGNED_URLS) {
            finalUrl = this.createSignedUrl(rdUrl, torrentInfo);
        }

        // Nastavenie headers pre optimálne video streaming
        this.setStreamingHeaders(res, torrentInfo, 'DIRECT');
        
        console.log(`↗️ Direct redirect na Real-Debrid (expires: ${config.DIRECT_STREAMING.LINK_EXPIRY}min)`);
        return res.redirect(302, finalUrl);
    }

    /**
     * Proxy streaming - data idú cez náš server
     */
    async handleProxyStream(req, res, rdUrl, torrentInfo) {
        console.log(`🔄 Proxy streaming: ${torrentInfo.title} (${this.formatFileSize(torrentInfo.size)})`);
        
        if (!this.isValidRdUrl(rdUrl)) {
            throw new Error('Neplatné Real-Debrid URL');
        }

        // Príprava headers pre request
        const requestHeaders = this.buildProxyHeaders(req);
        
        try {
            const axiosConfig = {
                method: 'GET',
                url: rdUrl,
                headers: requestHeaders,
                responseType: 'stream',
                timeout: config.PROXY_STREAMING.TIMEOUT,
                maxRedirects: config.PROXY_STREAMING.MAX_REDIRECTS,
                validateStatus: (status) => status < 500 // Accept redirects and client errors
            };

            console.log(`📡 Pripájam sa k Real-Debrid...`);
            const streamResponse = await axios(axiosConfig);
            
            // Check for error status codes
            if (streamResponse.status >= 400) {
                throw new Error(`Real-Debrid error: ${streamResponse.status} ${streamResponse.statusText}`);
            }

            // Nastavenie response headers
            this.setProxyResponseHeaders(res, streamResponse.headers, req.headers.range, torrentInfo);
            
            console.log(`🔄 Streaming ${this.formatFileSize(streamResponse.headers['content-length'])} cez proxy server`);
            
            // Error handling pre stream
            streamResponse.data.on('error', (error) => {
                console.error('❌ Stream pipe error:', error.message);
                if (!res.destroyed && !res.headersSent) {
                    res.status(500).end();
                }
            });

            // Connection handling
            req.on('close', () => {
                if (streamResponse.data && !streamResponse.data.destroyed) {
                    streamResponse.data.destroy();
                }
            });

            req.on('aborted', () => {
                if (streamResponse.data && !streamResponse.data.destroyed) {
                    streamResponse.data.destroy();
                }
            });

            // Pipe stream data
            streamResponse.data.pipe(res);
            
        } catch (error) {
            console.error('❌ Proxy streaming chyba:', error.message);
            
            // Špecifické error handling
            if (error.code === 'ECONNABORTED') {
                throw new Error('Timeout pri pripojení k Real-Debrid');
            } else if (error.code === 'ENOTFOUND') {
                throw new Error('Real-Debrid server nedostupný');
            } else if (error.response) {
                const status = error.response.status;
                if (status === 404) {
                    throw new Error('Súbor nebol nájdený na Real-Debrid');
                } else if (status === 403) {
                    throw new Error('Prístup k súboru zamietnutý (možno expirovaný link)');
                } else if (status >= 500) {
                    throw new Error('Real-Debrid server error');
                }
            }
            
            throw new Error(`Proxy streaming chyba: ${error.message}`);
        }
    }

    /**
     * Hybrid streaming - inteligentný výber na základe podmienok
     */
    async handleHybridStream(req, res, rdUrl, torrentInfo) {
        const decision = this.makeHybridDecision(req, torrentInfo);
        
        console.log(`🎯 Hybrid rozhodnutie: ${decision.method} (${decision.reason})`);
        
        if (decision.method === 'DIRECT') {
            return await this.handleDirectStream(req, res, rdUrl, torrentInfo);
        } else {
            return await this.handleProxyStream(req, res, rdUrl, torrentInfo);
        }
    }

    /**
     * Rozhodovacia logika pre hybrid mód
     */
    makeHybridDecision(req, torrentInfo) {
        const fileSize = torrentInfo.size || 0;
        const hasRange = !!req.headers.range;
        const isSmallFile = fileSize < config.HYBRID_STREAMING.SMALL_FILE_THRESHOLD;
        const isMobile = this.isMobileClient(req);
        const serverLoad = this.getServerLoad();
        const isHighQuality = this.isHighQualityContent(torrentInfo);
        
        // Pravidlá pre direct streaming (v poradí priority)
        
        // 1. Vysoká záťaž servera -> direct
        if (serverLoad > config.HYBRID_STREAMING.SERVER_LOAD_THRESHOLD) {
            return { method: 'DIRECT', reason: `vysoká záťaž servera (${serverLoad}%)` };
        }
        
        // 2. Malý súbor bez range -> direct
        if (isSmallFile && !hasRange) {
            return { method: 'DIRECT', reason: `malý súbor (${this.formatFileSize(fileSize)}) bez range` };
        }
        
        // 3. Mobilný klient a malý súbor -> direct (ak je povolené)
        if (isMobile && config.HYBRID_STREAMING.MOBILE_PREFER_DIRECT && isSmallFile) {
            return { method: 'DIRECT', reason: 'mobilný klient s malým súborom' };
        }
        
        // 4. Veľmi malý súbor (< 100MB) -> vždy direct
        if (fileSize < 100 * 1024 * 1024) {
            return { method: 'DIRECT', reason: `veľmi malý súbor (${this.formatFileSize(fileSize)})` };
        }
        
        // 5. High-quality obsah s range requests -> proxy (lepšia kontrola)
        if (isHighQuality && hasRange) {
            return { method: 'PROXY', reason: `vysoká kvalita s range requests` };
        }
        
        // Default rozhodnutie na základe celkovej situácie
        if (serverLoad < 30 && !isMobile) {
            return { method: 'PROXY', reason: 'nízka záťaž servera, desktop klient' };
        }
        
        return { method: 'DIRECT', reason: 'default voľba pre optimalizáciu' };
    }

    /**
     * Validácia vstupných parametrov
     */
    validateInputs(rdUrl, torrentInfo) {
        if (!rdUrl || typeof rdUrl !== 'string') {
            throw new Error('Validation error: Chýba Real-Debrid URL');
        }
        
        if (!torrentInfo || typeof torrentInfo !== 'object') {
            throw new Error('Validation error: Chýbajú informácie o torrente');
        }
        
        if (!torrentInfo.title) {
            throw new Error('Validation error: Chýba názov torrenta');
        }
    }

    /**
     * Validácia Real-Debrid URL
     */
    isValidRdUrl(url) {
        if (!url || typeof url !== 'string') return false;
        
        // Real-Debrid domény
        const validDomains = [
            'real-debrid.com',
            'rd.rdeb.io',
            'fc.rdeb.io',
            'rdeb.io',
            'real-debrid.org'
        ];
        
        try {
            const parsedUrl = new URL(url);
            const isValidDomain = validDomains.some(domain => 
                parsedUrl.hostname === domain || parsedUrl.hostname.endsWith('.' + domain)
            );
            
            if (!isValidDomain) {
                console.warn(`⚠️ Neplatná RD doména: ${parsedUrl.hostname}`);
                return false;
            }
            
            // Check protocol
            if (!['https:', 'http:'].includes(parsedUrl.protocol)) {
                console.warn(`⚠️ Neplatný protokol: ${parsedUrl.protocol}`);
                return false;
            }
            
            return true;
        } catch (error) {
            console.warn(`⚠️ Chyba pri parsovaní URL: ${error.message}`);
            return false;
        }
    }

    /**
     * Test dostupnosti RD URL pred redirect
     */
    async verifyRdUrlAccessible(rdUrl) {
        // Check cache first
        const cacheKey = crypto.createHash('md5').update(rdUrl).digest('hex');
        const cached = this.urlVerificationCache.get(cacheKey);
        
        if (cached && (Date.now() - cached.timestamp) < config.DIRECT_STREAMING.URL_VERIFICATION_CACHE * 1000) {
            if (!cached.accessible) {
                throw new Error('Real-Debrid link je nedostupný (cached)');
            }
            return;
        }
        
        try {
            console.log('🔍 Verifikujem Real-Debrid URL...');
            const response = await axios.head(rdUrl, { 
                timeout: 5000,
                maxRedirects: 2,
                validateStatus: (status) => status < 400
            });
            
            // Cache successful result
            this.urlVerificationCache.set(cacheKey, {
                accessible: true,
                timestamp: Date.now(),
                status: response.status
            });
            
            console.log(`✅ RD URL je dostupný (status: ${response.status})`);
            
        } catch (error) {
            // Cache failed result for shorter time
            this.urlVerificationCache.set(cacheKey, {
                accessible: false,
                timestamp: Date.now(),
                error: error.message
            });
            
            console.warn(`❌ RD URL verification failed: ${error.message}`);
            throw new Error('Real-Debrid link je momentálne nedostupný');
        }
    }

    /**
     * Vytvorenie signed URL s expiry a podpisom
     */
    createSignedUrl(rdUrl, torrentInfo) {
        const expiry = Date.now() + (config.DIRECT_STREAMING.LINK_EXPIRY * 60 * 1000);
        const payload = `${rdUrl}:${expiry}:${torrentInfo.id || 'unknown'}`;
        const signature = crypto
            .createHmac('sha256', config.ADDON_API_KEY)
            .update(payload)
            .digest('hex');
        
        const separator = rdUrl.includes('?') ? '&' : '?';
        return `${rdUrl}${separator}_exp=${expiry}&_sig=${signature}&_id=${encodeURIComponent(torrentInfo.id || '')}`;
    }

    /**
     * Nastavenie headers pre streaming
     */
    setStreamingHeaders(res, torrentInfo, method) {
        res.setHeader('Accept-Ranges', 'bytes');
        res.setHeader('Content-Type', this.getContentType(torrentInfo.title));
        res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
        res.setHeader('Pragma', 'no-cache');
        res.setHeader('Expires', '0');
        res.setHeader('X-Streaming-Method', method);
        res.setHeader('X-Content-Title', encodeURIComponent(torrentInfo.title));
        
        // CORS headers
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Range, Content-Type, Authorization');
        res.setHeader('Access-Control-Expose-Headers', 'Content-Range, Content-Length, Accept-Ranges');
        
        // Security headers
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('X-Frame-Options', 'DENY');
    }

    /**
     * Build headers pre proxy request
     */
    buildProxyHeaders(req) {
        const headers = {
            'User-Agent': 'SKTorrent-Hybrid-Addon/2.0 (Proxy-Mode)',
            'Accept': '*/*',
            'Accept-Encoding': 'identity',
            'Connection': config.PROXY_STREAMING.KEEP_ALIVE ? 'keep-alive' : 'close'
        };
        
        // Forward range header pre seeking
        if (req.headers.range) {
            headers.Range = req.headers.range;
            console.log(`📍 Range request: ${req.headers.range}`);
        }
        
        // Forward authorization ak existuje
        if (req.headers.authorization) {
            headers.Authorization = req.headers.authorization;
        }
        
        return headers;
    }

    /**
     * Nastavenie response headers pre proxy streaming
     */
    setProxyResponseHeaders(res, sourceHeaders, requestRange, torrentInfo) {
        // Content headers
        if (sourceHeaders['content-length']) {
            res.setHeader('Content-Length', sourceHeaders['content-length']);
        }
        
        if (sourceHeaders['content-range']) {
            res.setHeader('Content-Range', sourceHeaders['content-range']);
        }
        
        if (sourceHeaders['content-type']) {
            res.setHeader('Content-Type', sourceHeaders['content-type']);
        } else {
            res.setHeader('Content-Type', this.getContentType(torrentInfo.title));
        }
        
        // Range support
        res.setHeader('Accept-Ranges', 'bytes');
        
        // Streaming optimalizácia
        res.setHeader('Cache-Control', 'no-cache');
        res.setHeader('X-Streaming-Method', 'PROXY');
        res.setHeader('X-Proxy-Server', 'SKTorrent-Hybrid');
        
        // CORS headers
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Expose-Headers', 'Content-Range, Content-Length, Accept-Ranges');
        
        // Status code pre range requests
        if (requestRange && sourceHeaders['content-range']) {
            res.status(206);
            console.log(`📍 Partial content response: ${sourceHeaders['content-range']}`);
        } else {
            res.status(200);
        }
    }

    /**
     * Detekcia content type na základe názvu súboru
     */
    getContentType(filename) {
        if (!filename) return 'application/octet-stream';
        
        const ext = filename.split('.').pop()?.toLowerCase();
        const videoTypes = {
            'mp4': 'video/mp4',
            'avi': 'video/x-msvideo',
            'mkv': 'video/x-matroska',
            'mov': 'video/quicktime',
            'wmv': 'video/x-ms-wmv',
            'flv': 'video/x-flv',
            'webm': 'video/webm',
            'm4v': 'video/mp4',
            'mpg': 'video/mpeg',
            'mpeg': 'video/mpeg',
            '3gp': 'video/3gpp',
            'ogv': 'video/ogg'
        };
        
        return videoTypes[ext] || 'video/mp4';
    }

    /**
     * Rate limiting
     */
    checkRateLimit(clientIp) {
        const now = Date.now();
        const windowMs = 60 * 1000; // 1 minúta
        const maxRequests = config.DIRECT_STREAMING.MAX_REQUESTS_PER_MINUTE;
        
        if (!this.rateLimitMap.has(clientIp)) {
            this.rateLimitMap.set(clientIp, { 
                count: 1, 
                resetTime: now + windowMs,
                firstRequest: now
            });
            return;
        }
        
        const clientData = this.rateLimitMap.get(clientIp);
        
        if (now > clientData.resetTime) {
            // Reset window
            clientData.count = 1;
            clientData.resetTime = now + windowMs;
            clientData.firstRequest = now;
        } else {
            clientData.count++;
        }
        
        if (clientData.count > maxRequests) {
            const remainingTime = Math.ceil((clientData.resetTime - now) / 1000);
            throw new Error(`Rate limit exceeded: max ${maxRequests} requests per minute. Try again in ${remainingTime}s`);
        }
    }

    /**
     * Cleanup rate limit map
     */
    cleanupRateLimit() {
        const now = Date.now();
        let cleanedCount = 0;
        
        for (const [ip, data] of this.rateLimitMap.entries()) {
            if (now > data.resetTime + 300000) { // 5 minút po expiry
                this.rateLimitMap.delete(ip);
                cleanedCount++;
            }
        }
        
        if (cleanedCount > 0) {
            console.log(`🧹 Cleanup: Odstránených ${cleanedCount} starých rate limit záznamov`);
        }
    }

    /**
     * Detekcia mobilného klienta
     */
    isMobileClient(req) {
        const userAgent = req.headers['user-agent'] || '';
        return /Mobile|Android|iPhone|iPad|iPod|BlackBerry|Windows Phone/i.test(userAgent);
    }

    /**
     * Detekcia high-quality obsahu
     */
    isHighQualityContent(torrentInfo) {
        const title = torrentInfo.title?.toLowerCase() || '';
        const size = torrentInfo.size || 0;
        
        // Veľký súbor alebo high-quality indikátory
        return size > 2 * 1024 * 1024 * 1024 || // > 2GB
               title.includes('4k') ||
               title.includes('2160p') ||
               title.includes('1080p') ||
               title.includes('bluray') ||
               title.includes('remux');
    }

    /**
     * Získanie záťaže serveru
     */
    getServerLoad() {
        // Jednoduchá simulácia na základe počtu requestov
        const now = Date.now();
        const windowMs = 60 * 1000; // 1 minúta
        
        // Reset metrics ak je potreba
        if (now - this.serverMetrics.lastReset > windowMs) {
            const load = Math.min(100, (this.serverMetrics.totalRequests / 60) * 10); // Približná záťaž
            this.serverMetrics = {
                ...this.serverMetrics,
                totalRequests: 0,
                lastReset: now
            };
            return load;
        }
        
        return Math.min(100, (this.serverMetrics.totalRequests / 30) * 10);
    }

    /**
     * Reset metrics
     */
    resetMetrics() {
        console.log(`📊 Hourly metrics reset. Last hour: ${JSON.stringify({
            total: this.serverMetrics.totalRequests,
            direct: this.serverMetrics.directRequests,
            proxy: this.serverMetrics.proxyRequests,
            hybrid: this.serverMetrics.hybridRequests,
            errors: this.serverMetrics.errors
        })}`);
        
        this.serverMetrics = {
            totalRequests: 0,
            directRequests: 0,
            proxyRequests: 0,
            hybridRequests: 0,
            errors: 0,
            lastReset: Date.now()
        };
    }

    /**
     * Formátovanie veľkosti súboru
     */
    formatFileSize(bytes) {
        if (!bytes || bytes === 0) return 'unknown size';
        
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(1024));
        return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i];
    }

    /**
     * Logovanie stream requestov
     */
    logStreamRequest(status, method, torrentInfo, clientIp, duration, error = null) {
        const logEntry = {
            timestamp: new Date().toISOString(),
            status: status,
            method: method,
            title: torrentInfo.title,
            size: torrentInfo.size,
            formattedSize: this.formatFileSize(torrentInfo.size),
            clientIp: clientIp,
            id: torrentInfo.id,
            duration: Math.round(duration),
            error: error
        };
        
        const emoji = {
            'SUCCESS': '✅',
            'ERROR': '❌',
            'FALLBACK_SUCCESS': '🔄'
        }[status] || '📊';
        
        console.log(`${emoji} Stream ${status}: ${method} | ${logEntry.formattedSize} | ${logEntry.duration}ms | ${logEntry.title}`);
        
        if (config.LOGGING.ENABLE_ACCESS_LOG) {
            // Tu by sa mohlo posielať do externého logovacieho systému
        }
    }

    /**
     * Získanie aktuálnych metrik
     */
    getMetrics() {
        return {
            ...this.serverMetrics,
            rateLimitEntries: this.rateLimitMap.size,
            cacheEntries: this.urlVerificationCache.size,
            uptime: Date.now() - this.serverMetrics.lastReset
        };
    }

    /**
     * Health check endpoint
     */
    healthCheck() {
        const metrics = this.getMetrics();
        return {
            status: 'healthy',
            streamingMethod: this.streamingMethod,
            version: '2.0.0',
            metrics: metrics,
            config: {
                directStreaming: config.DIRECT_STREAMING,
                proxyStreaming: config.PROXY_STREAMING,
                hybridStreaming: config.HYBRID_STREAMING
            }
        };
    }
}

module.exports = StreamingManager;
