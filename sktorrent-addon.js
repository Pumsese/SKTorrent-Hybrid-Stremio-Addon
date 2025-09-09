// sktorrent-addon.js - Kompletný hlavný súbor addonu
const { addonBuilder } = require('stremio-addon-sdk');
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const compression = require('compression');

// Import modulov
const config = require('./config');
const StreamingManager = require('./streaming');
const RealDebridManager = require('./realdebrid');
const TorrentSearchManager = require('./torrent-search');
const AuthManager = require('./auth');
const BaseUrlManager = require('./base-url-manager');
const TemplateManager = require('./templates');

// Inicializácia manažérov
const streamingManager = new StreamingManager();
const realDebridManager = new RealDebridManager();
const torrentSearchManager = new TorrentSearchManager();
const authManager = new AuthManager();
const baseUrlManager = new BaseUrlManager();
const templateManager = new TemplateManager();

// Validácia konfigurácie pri spustení
const configErrors = config.validateConfiguration();
if (configErrors.length > 0) {
    console.error('❌ Konfiguračné chyby:');
    configErrors.forEach(error => console.error(`  - ${error}`));
    process.exit(1);
}

// Definícia Stremio addonu
const manifest = {
    id: config.ADDON.ID,
    version: config.ADDON.VERSION,
    name: config.ADDON.NAME,
    description: config.ADDON.DESCRIPTION,
    logo: config.ADDON.LOGO,
    background: config.ADDON.BACKGROUND,
    resources: config.ADDON.RESOURCES,
    types: config.ADDON.TYPES,
    idPrefixes: config.ADDON.ID_PREFIXES,
    catalogs: config.ADDON.CATALOGS,
    behaviorHints: {
        configurable: true,
        configurationRequired: false
    }
};

console.log(`🚀 Spúšťam SKTorrent Hybrid Addon v${config.ADDON.VERSION}`);
console.log(`📡 Streaming metóda: ${config.getStreamingMethod()}`);
console.log(`🎬 Stream mód: ${config.STREAM_MODE}`);

// Vytvorenie addon buildera
const builder = addonBuilder(manifest);

// Definícia stream handlera
builder.defineStreamHandler(async function(args) {
    try {
        console.log(`🔍 Stream request pre: ${args.type}:${args.id}`);
        
        // Extrakcia IMDB ID
        const imdbId = args.id.replace('tt', '');
        if (!imdbId || !/^\d+$/.test(imdbId)) {
            console.warn(`❌ Neplatné IMDB ID: ${args.id}`);
            return { streams: [] };
        }

        const searchResults = {
            realDebridStreams: [],
            torrentStreams: []
        };

        // Real-Debrid vyhľadávanie (ak je povolené)
        if (config.STREAM_MODE !== 'TORRENT_ONLY' && config.REALDEBRID_API_KEY) {
            try {
                console.log('🔍 Vyhľadávam Real-Debrid streamy...');
                const rdStreams = await realDebridManager.findStreams(args);
                searchResults.realDebridStreams = rdStreams;
                console.log(`✅ Nájdených ${rdStreams.length} Real-Debrid streamov`);
            } catch (error) {
                console.error('❌ Real-Debrid search error:', error.message);
            }
        }

        // SKTorrent vyhľadávanie (ak je povolené)
        if (config.STREAM_MODE !== 'RD_ONLY') {
            try {
                console.log('🔍 Vyhľadávam SKTorrent streamy...');
                const sktStreams = await torrentSearchManager.findStreams(args);
                searchResults.torrentStreams = sktStreams;
                console.log(`✅ Nájdených ${sktStreams.length} torrent streamov`);
            } catch (error) {
                console.error('❌ SKTorrent search error:', error.message);
            }
        }

        // Spracovanie a kombinácia výsledkov
        const processedStreams = await processStreamResults(searchResults, args);
        
        console.log(`📊 Celkom ${processedStreams.length} streamov pre ${args.id}`);
        
        return { streams: processedStreams };
        
    } catch (error) {
        console.error('❌ Stream handler error:', error.message);
        return { streams: [] };
    }
});

/**
 * Spracovanie a kombinácia stream výsledkov
 */
async function processStreamResults(searchResults, args) {
    const allStreams = [];
    const apiKey = getApiKeyFromRequest(); // Implementované nižšie
    
    // Spracovanie Real-Debrid streamov
    for (const rdStream of searchResults.realDebridStreams) {
        const streamUrl = createStreamUrl('rd', rdStream, args, apiKey);
        
        allStreams.push({
            name: `⚡ ${rdStream.title}`,
            title: `${rdStream.quality} | ${rdStream.size} | ${rdStream.language}`,
            url: streamUrl,
            quality: rdStream.quality,
            size: rdStream.sizeBytes,
            seeders: rdStream.seeders || 0,
            isRealDebrid: true,
            streamingMethod: config.getStreamingMethod(),
            behaviorHints: {
                bingeGroup: `rd-${rdStream.quality}`,
                countryWhitelist: ['CZ', 'SK']
            }
        });
    }
    
    // Spracovanie torrent streamov
    for (const torrentStream of searchResults.torrentStreams) {
        const streamUrl = createStreamUrl('torrent', torrentStream, args, apiKey);
        
        allStreams.push({
            name: `🎬 ${torrentStream.title}`,
            title: `${torrentStream.quality} | ${torrentStream.size} | S:${torrentStream.seeders}`,
            url: streamUrl,
            quality: torrentStream.quality,
            size: torrentStream.sizeBytes,
            seeders: torrentStream.seeders || 0,
            isRealDebrid: false,
            behaviorHints: {
                bingeGroup: `torrent-${torrentStream.quality}`,
                countryWhitelist: ['CZ', 'SK']
            }
        });
    }
    
    // Zoradenie streamov (RD streamy prvé, potom podľa kvality a seederov)
    return allStreams.sort((a, b) => {
        // RD streamy majú prioritu
        if (a.isRealDebrid && !b.isRealDebrid) return -1;
        if (!a.isRealDebrid && b.isRealDebrid) return 1;
        
        // Potom podľa seederov
        if (b.seeders !== a.seeders) return b.seeders - a.seeders;
        
        // Nakoniec podľa veľkosti
        return (b.size || 0) - (a.size || 0);
    });
}

/**
 * Vytvorenie stream URL
 */
function createStreamUrl(type, stream, args, apiKey) {
    const baseUrl = baseUrlManager.getBaseUrl();
    
    if (type === 'rd') {
        // Real-Debrid stream URL
        const rdUrl = encodeURIComponent(stream.rdUrl);
        const title = encodeURIComponent(stream.title);
        const size = stream.sizeBytes || 0;
        
        return `${baseUrl}/stream/rd/${rdUrl}/${args.id}?api_key=${apiKey}&title=${title}&size=${size}`;
    } else {
        // Torrent stream URL
        const magnetUrl = encodeURIComponent(stream.magnetUrl);
        const title = encodeURIComponent(stream.title);
        
        return `${baseUrl}/stream/torrent/${magnetUrl}/${args.id}?api_key=${apiKey}&title=${title}`;
    }
}

/**
 * Získanie API kľúča z requestu (implementované v auth middleware)
 */
function getApiKeyFromRequest() {
    // Toto bude nastavené v middleware
    return global.currentApiKey || config.ADDON_API_KEY;
}

// Vytvorenie Express aplikácie
const app = express();

// Security middleware
app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
}));

// Compression
app.use(compression());

// CORS konfigurácia
app.use(cors({
    origin: config.SECURITY.CORS_ORIGINS,
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Range'],
    exposedHeaders: ['Content-Range', 'Accept-Ranges', 'Content-Length']
}));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minút
    max: config.SECURITY.GLOBAL_RATE_LIMIT,
    message: 'Príliš veľa requestov, skúste neskôr',
    standardHeaders: true,
    legacyHeaders: false
});
app.use(limiter);

// JSON parsing
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// Request logging middleware
app.use((req, res, next) => {
    if (config.LOGGING.ENABLE_ACCESS_LOG) {
        console.log(`📡 ${req.method} ${req.path} - ${req.ip} - ${req.headers['user-agent']?.substring(0, 100)}`);
    }
    next();
});

// Auth middleware pre API endpoints
function authenticateApiKey(req, res, next) {
    try {
        const apiKey = req.query.api_key || req.headers['x-api-key'];
        
        if (!config.SECURITY.REQUIRE_API_KEY) {
            global.currentApiKey = config.ADDON_API_KEY;
            return next();
        }
        
        if (!apiKey) {
            return res.status(401).json({ 
                error: 'API key je povinný',
                hint: 'Pridajte ?api_key=YOUR_KEY do URL'
            });
        }
        
        if (apiKey !== config.ADDON_API_KEY) {
            console.warn(`❌ Neplatný API key pokus od ${req.ip}: ${apiKey.substring(0, 8)}...`);
            return res.status(403).json({ 
                error: 'Neplatný API key'
            });
        }
        
        global.currentApiKey = apiKey;
        next();
    } catch (error) {
        console.error('❌ Auth middleware error:', error);
        return res.status(500).json({ error: 'Authentication error' });
    }
}

// IP whitelist middleware
function checkIpWhitelist(req, res, next) {
    if (config.SECURITY.IP_WHITELIST.length === 0) {
        return next();
    }
    
    const clientIp = req.ip || req.connection.remoteAddress;
    if (!config.SECURITY.IP_WHITELIST.includes(clientIp)) {
        console.warn(`❌ Nepovolená IP adresa: ${clientIp}`);
        return res.status(403).json({ error: 'IP adresa nie je na whitelist' });
    }
    
    next();
}

// Aplikácia middleware
app.use(checkIpWhitelist);

// Hlavná stránka
app.get('/', (req, res) => {
    const html = templateManager.renderHomePage({
        manifest: manifest,
        config: {
            streamingMethod: config.getStreamingMethod(),
            streamMode: config.STREAM_MODE,
            version: config.ADDON.VERSION
        },
        baseUrl: baseUrlManager.getBaseUrl()
    });
    
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(html);
});

// Manifest endpoint
app.get('/manifest.json', authenticateApiKey, (req, res) => {
    res.json(manifest);
});

// Configure endpoint pre Stremio
app.get('/configure', (req, res) => {
    const html = templateManager.renderConfigurePage({
        manifest: manifest,
        baseUrl: baseUrlManager.getBaseUrl()
    });
    
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(html);
});

// Real-Debrid stream endpoint
app.get('/stream/rd/:rdUrl/:id', authenticateApiKey, async (req, res) => {
    try {
        const rdUrl = decodeURIComponent(req.params.rdUrl);
        const torrentInfo = {
            id: req.params.id,
            title: decodeURIComponent(req.query.title || 'Unknown'),
            size: parseInt(req.query.size) || 0
        };
        
        console.log(`🎬 RD Stream request: ${torrentInfo.title} (${streamingManager.formatFileSize(torrentInfo.size)})`);
        
        return await streamingManager.handleStreamRequest(req, res, rdUrl, torrentInfo);
        
    } catch (error) {
        console.error('❌ RD stream endpoint error:', error.message);
        
        if (!res.headersSent) {
            return res.status(500).json({ 
                error: 'Stream error',
                details: config.isDevelopment() ? error.message : 'Internal server error'
            });
        }
    }
});

// Torrent stream endpoint
app.get('/stream/torrent/:magnetUrl/:id', authenticateApiKey, async (req, res) => {
    try {
        const magnetUrl = decodeURIComponent(req.params.magnetUrl);
        const torrentInfo = {
            id: req.params.id,
            title: decodeURIComponent(req.query.title || 'Unknown'),
            magnetUrl: magnetUrl
        };
        
        console.log(`🎬 Torrent stream request: ${torrentInfo.title}`);
        
        // Pre torrent streamy vrátime magnet link
        res.redirect(302, magnetUrl);
        
    } catch (error) {
        console.error('❌ Torrent stream endpoint error:', error.message);
        
        if (!res.headersSent) {
            return res.status(500).json({ 
                error: 'Torrent stream error',
                details: config.isDevelopment() ? error.message : 'Internal server error'
            });
        }
    }
});

// Health check endpoint
app.get('/health', (req, res) => {
    const health = streamingManager.healthCheck();
    
    res.json({
        ...health,
        timestamp: new Date().toISOString(),
        addon: {
            name: manifest.name,
            version: manifest.version,
            id: manifest.id
        }
    });
});

// Metrics endpoint (protected)
app.get('/metrics', authenticateApiKey, (req, res) => {
    const metrics = streamingManager.getMetrics();
    
    res.json({
        metrics: metrics,
        config: {
            streamingMethod: config.getStreamingMethod(),
            streamMode: config.STREAM_MODE,
            directStreamingConfig: config.DIRECT_STREAMING,
            proxyStreamingConfig: config.PROXY_STREAMING
        },
        timestamp: new Date().toISOString()
    });
});

// Debug endpoint (iba v development móde)
if (config.isDevelopment()) {
    app.get('/debug', authenticateApiKey, (req, res) => {
        res.json({
            config: {
                NODE_ENV: config.NODE_ENV,
                STREAMING_METHOD: config.getStreamingMethod(),
                STREAM_MODE: config.STREAM_MODE,
                DIRECT_STREAMING: config.DIRECT_STREAMING,
                PROXY_STREAMING: config.PROXY_STREAMING,
                HYBRID_STREAMING: config.HYBRID_STREAMING
            },
            metrics: streamingManager.getMetrics(),
            manifest: manifest
        });
    });
}

// Stremio addon endpoints
app.use(builder.getRouter());

// 404 handler
app.use('*', (req, res) => {
    console.warn(`❌ 404 Not Found: ${req.method} ${req.originalUrl} - ${req.ip}`);
    res.status(404).json({ 
        error: 'Endpoint not found',
        availableEndpoints: [
            'GET /',
            'GET /manifest.json?api_key=YOUR_KEY',
            'GET /health',
            'GET /stream/rd/:rdUrl/:id?api_key=YOUR_KEY',
            'GET /stream/torrent/:magnetUrl/:id?api_key=YOUR_KEY'
        ]
    });
});

// Global error handler
app.use((error, req, res, next) => {
    console.error('❌ Global error handler:', error);
    
    if (config.LOGGING.ENABLE_ERROR_LOG) {
        // Tu by sa mohlo logovať do súboru alebo externého systému
    }
    
    if (!res.headersSent) {
        res.status(500).json({ 
            error: 'Internal server error',
            details: config.isDevelopment() ? error.message : 'Something went wrong'
        });
    }
});

// Graceful shutdown handling
process.on('SIGTERM', () => {
    console.log('🛑 SIGTERM received, shutting down gracefully...');
    process.exit(0);
});

process.on('SIGINT', () => {
    console.log('🛑 SIGINT received, shutting down gracefully...');
    process.exit(0);
});

process.on('uncaughtException', (error) => {
    console.error('❌ Uncaught Exception:', error);
    process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
    process.exit(1);
});

// Spustenie servera
const server = app.listen(config.PORT, () => {
    console.log(`\n🚀 SKTorrent Hybrid Addon je spustený!`);
    console.log(`📡 Server beží na porte: ${config.PORT}`);
    console.log(`🌐 Manifest URL: ${config.getManifestUrl()}?api_key=YOUR_API_KEY`);
    console.log(`🎬 Streaming metóda: ${config.getStreamingMethod()}`);
    console.log(`📊 Stream mód: ${config.STREAM_MODE}`);
    console.log(`🔐 API Key required: ${config.SECURITY.REQUIRE_API_KEY}`);
    console.log(`\n✅ Addon je pripravený na použitie!`);
});

// Export pre testovanie
module.exports = { app, server, streamingManager, config };
