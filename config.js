// config.js - Kompletní konfigurační soubor
const path = require('path');

module.exports = {
    // Server konfigurace
    PORT: parseInt(process.env.PORT) || 7000,
    NODE_ENV: process.env.NODE_ENV || 'development',
    EXTERNAL_DOMAIN: process.env.EXTERNAL_DOMAIN || 'localhost',
    
    // Real-Debrid konfigurace
    REALDEBRID_API_KEY: process.env.REALDEBRID_API_KEY || '',
    REALDEBRID_BASE_URL: 'https://api.real-debrid.com/rest/1.0',
    REALDEBRID_TIMEOUT: 30000,
    
    // SKTorrent.eu konfigurace
    SKT_UID: process.env.SKT_UID || '',
    SKT_PASS: process.env.SKT_PASS || '',
    SKT_BASE_URL: 'https://sktorrent.eu',
    SKT_SEARCH_TIMEOUT: 15000,
    
    // API klíč pro zabezpečení addonu
    ADDON_API_KEY: process.env.ADDON_API_KEY || 'skt_default_api_key',
    
    // Stream módy
    STREAM_MODE: process.env.STREAM_MODE || 'BOTH', // 'RD_ONLY', 'BOTH', 'TORRENT_ONLY'
    
    // NOVÁ KONFIGURACE - Streaming metódy
    STREAMING_METHOD: process.env.STREAMING_METHOD || 'PROXY', // 'PROXY', 'DIRECT', 'HYBRID'
    
    // Direct streaming konfigurace
    DIRECT_STREAMING: {
        // Čas expiry pre direct linky (v minútach)
        LINK_EXPIRY: parseInt(process.env.DIRECT_LINK_EXPIRY) || 60,
        
        // Či použiť signed URLs pre dodatočnú bezpečnosť
        USE_SIGNED_URLS: process.env.USE_SIGNED_URLS === 'true',
        
        // Fallback na proxy pri zlyhaní direct streaming
        FALLBACK_TO_PROXY: process.env.FALLBACK_TO_PROXY !== 'false',
        
        // Verifikácia RD URL pred redirect
        VERIFY_BEFORE_REDIRECT: process.env.VERIFY_BEFORE_REDIRECT === 'true',
        
        // Rate limiting pre direct streams
        MAX_REQUESTS_PER_MINUTE: parseInt(process.env.MAX_REQUESTS_PER_MINUTE) || 30,
        
        // Cache pre RD URL verifikáciu (v sekundách)
        URL_VERIFICATION_CACHE: parseInt(process.env.URL_VERIFICATION_CACHE) || 300
    },
    
    // Proxy streaming konfigurace
    PROXY_STREAMING: {
        // Timeout pre proxy requesty
        TIMEOUT: parseInt(process.env.PROXY_TIMEOUT) || 30000,
        
        // Max redirecty
        MAX_REDIRECTS: parseInt(process.env.PROXY_MAX_REDIRECTS) || 3,
        
        // Buffer size pre streaming
        BUFFER_SIZE: parseInt(process.env.PROXY_BUFFER_SIZE) || 64 * 1024, // 64KB
        
        // Keep-alive pre proxy connections
        KEEP_ALIVE: process.env.PROXY_KEEP_ALIVE !== 'false'
    },
    
    // Hybrid streaming konfigurace
    HYBRID_STREAMING: {
        // Limit veľkosti súboru pre direct streaming (v bajtoch)
        SMALL_FILE_THRESHOLD: parseInt(process.env.SMALL_FILE_THRESHOLD) || 500 * 1024 * 1024, // 500MB
        
        // Server load threshold pre direct streaming
        SERVER_LOAD_THRESHOLD: parseInt(process.env.SERVER_LOAD_THRESHOLD) || 80,
        
        // Preferencia pre mobilné zariadenia
        MOBILE_PREFER_DIRECT: process.env.MOBILE_PREFER_DIRECT === 'true'
    },
    
    // Vyhľadávanie konfigurace
    SEARCH: {
        MAX_RESULTS: parseInt(process.env.MAX_SEARCH_RESULTS) || 20,
        TIMEOUT: parseInt(process.env.SEARCH_TIMEOUT) || 15000,
        RETRY_ATTEMPTS: parseInt(process.env.SEARCH_RETRY_ATTEMPTS) || 3
    },
    
    // Cache konfigurace
    CACHE: {
        ENABLED: process.env.CACHE_ENABLED !== 'false',
        TTL: parseInt(process.env.CACHE_TTL) || 3600, // 1 hodina
        MAX_SIZE: parseInt(process.env.CACHE_MAX_SIZE) || 1000
    },
    
    // Logging konfigurace
    LOGGING: {
        LEVEL: process.env.LOG_LEVEL || 'info',
        ENABLE_ACCESS_LOG: process.env.ENABLE_ACCESS_LOG === 'true',
        ENABLE_ERROR_LOG: process.env.ENABLE_ERROR_LOG !== 'false',
        LOG_DIRECTORY: process.env.LOG_DIRECTORY || './logs'
    },
    
    // Stremio addon konfigurace
    ADDON: {
        ID: 'org.sktorrent.hybrid',
        VERSION: '2.0.0',
        NAME: 'SKTorrent Hybrid',
        DESCRIPTION: 'SKTorrent.eu s Real-Debrid integráciou a direct streaming',
        LOGO: 'https://your-domain.com/sktorrent-addon-logo.png',
        BACKGROUND: 'https://your-domain.com/addon-background.jpg',
        CATALOGS: [],
        RESOURCES: ['stream'],
        TYPES: ['movie', 'series'],
        ID_PREFIXES: ['tt']
    },
    
    // Bezpečnostné nastavenia
    SECURITY: {
        // API key validation
        REQUIRE_API_KEY: process.env.REQUIRE_API_KEY !== 'false',
        
        // IP whitelisting
        IP_WHITELIST: process.env.IP_WHITELIST ? process.env.IP_WHITELIST.split(',') : [],
        
        // CORS nastavenia
        CORS_ORIGINS: process.env.CORS_ORIGINS ? process.env.CORS_ORIGINS.split(',') : ['*'],
        
        // Rate limiting globálne
        GLOBAL_RATE_LIMIT: parseInt(process.env.GLOBAL_RATE_LIMIT) || 100,
        
        // Session timeout
        SESSION_TIMEOUT: parseInt(process.env.SESSION_TIMEOUT) || 3600000 // 1 hodina
    },
    
    // Development nastavenia
    DEVELOPMENT: {
        ENABLE_MOCK_DATA: process.env.ENABLE_MOCK_DATA === 'true',
        ENABLE_DEBUG_LOGS: process.env.ENABLE_DEBUG_LOGS === 'true',
        DISABLE_SSL_VERIFY: process.env.DISABLE_SSL_VERIFY === 'true'
    },
    
    // Utility funkcie
    isProduction: () => process.env.NODE_ENV === 'production',
    isDevelopment: () => process.env.NODE_ENV === 'development',
    
    getManifestUrl: () => {
        const protocol = module.exports.isProduction() ? 'https' : 'http';
        const domain = process.env.EXTERNAL_DOMAIN || 'localhost';
        const port = module.exports.isProduction() ? '' : `:${module.exports.PORT}`;
        return `${protocol}://${domain}${port}/manifest.json`;
    },
    
    getStreamingMethod: () => {
        const method = process.env.STREAMING_METHOD || 'PROXY';
        if (['PROXY', 'DIRECT', 'HYBRID'].includes(method)) {
            return method;
        }
        console.warn(`Neplatná streaming metóda: ${method}, používam PROXY`);
        return 'PROXY';
    },
    
    validateConfiguration: () => {
        const errors = [];
        
        if (!process.env.ADDON_API_KEY || process.env.ADDON_API_KEY === 'skt_default_api_key') {
            errors.push('ADDON_API_KEY nie je nastavený alebo používa default hodnotu');
        }
        
        if (!process.env.SKT_UID) {
            errors.push('SKT_UID nie je nastavený');
        }
        
        if (!process.env.SKT_PASS) {
            errors.push('SKT_PASS nie je nastavený');
        }
        
        if (process.env.STREAM_MODE !== 'TORRENT_ONLY' && !process.env.REALDEBRID_API_KEY) {
            errors.push('REALDEBRID_API_KEY nie je nastavený (potrebný pre RD funkcionalitu)');
        }
        
        return errors;
    }
};

// Validácia konfigurácie pri načítaní
if (require.main === module) {
    const errors = module.exports.validateConfiguration();
    if (errors.length > 0) {
        console.error('❌ Konfiguračné chyby:');
        errors.forEach(error => console.error(`  - ${error}`));
        process.exit(1);
    } else {
        console.log('✅ Konfigurácia je platná');
    }
}
