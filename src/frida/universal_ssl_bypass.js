/*
 * ═══════════════════════════════════════════════════════════════════
 *  NULLSEC iOS FRIDA UNIVERSAL SSL BYPASS
 *  Bypass SSL certificate pinning on iOS applications
 *  @author bad-antics | discord.gg/killers
 * ═══════════════════════════════════════════════════════════════════
 */

const VERSION = "2.0.0";
const AUTHOR = "bad-antics";
const DISCORD = "discord.gg/killers";

const BANNER = `
  ██████   ██████  ██▓        ▄▄▄▄ ▓██   ██▓ ██▓███   ▄▄▄        ██████   ██████ 
▒██    ▒ ▒██    ▒ ▓██▒       ▓█████▄▒██  ██▒▓██░  ██▒▒████▄    ▒██    ▒ ▒██    ▒ 
░ ▓██▄   ░ ▓██▄   ▒██░       ▒██▒ ▄██▒██ ██░▓██░ ██▓▒▒██  ▀█▄  ░ ▓██▄   ░ ▓██▄   
  ▒   ██▒  ▒   ██▒▒██░       ▒██░█▀  ░ ▐██▓░▒██▄█▓▒ ▒░██▄▄▄▄██   ▒   ██▒  ▒   ██▒
▒██████▒▒▒██████▒▒░██████▒   ░▓█  ▀█▓░ ██▒▓░▒██▒ ░  ░ ▓█   ▓██▒▒██████▒▒▒██████▒▒
▒ ▒▓▒ ▒ ░▒ ▒▓▒ ▒ ░░ ▒░▓  ░   ░▒▓███▀▒ ██▒▒▒ ▒▓▒░ ░  ░ ▒▒   ▓▒█░▒ ▒▓▒ ▒ ░▒ ▒▓▒ ▒ ░
░ ░▒  ░ ░░ ░▒  ░ ░░ ░ ▒  ░   ▒░▒   ░▓██ ░▒░ ░▒ ░       ▒   ▒▒ ░░ ░▒  ░ ░░ ░▒  ░ ░
░  ░  ░  ░  ░  ░    ░ ░       ░    ░▒ ▒ ░░  ░░         ░   ▒   ░  ░  ░  ░  ░  ░  
      ░        ░      ░  ░    ░     ░ ░                    ░  ░      ░        ░   
   ░              ░                ░░ ░                                    ▄▄▄▄▄▄
                    🔓 SSL BYPASS | bad-antics | discord.gg/killers
`;

// ═══════════════════════════════════════════════════════════════════
// License Management
// ═══════════════════════════════════════════════════════════════════

const LicenseTier = {
    FREE: 0,
    PREMIUM: 1,
    ENTERPRISE: 2
};

let currentLicense = {
    key: "",
    tier: LicenseTier.FREE,
    valid: false
};

function validateLicense(key) {
    if (!key || key.length !== 24) return false;
    if (!key.startsWith("NIOS-")) return false;
    
    currentLicense.key = key;
    currentLicense.valid = true;
    
    const typeCode = key.substring(5, 7);
    if (typeCode === "PR") {
        currentLicense.tier = LicenseTier.PREMIUM;
    } else if (typeCode === "EN") {
        currentLicense.tier = LicenseTier.ENTERPRISE;
    } else {
        currentLicense.tier = LicenseTier.FREE;
    }
    
    return true;
}

function isPremium() {
    return currentLicense.valid && currentLicense.tier !== LicenseTier.FREE;
}

// ═══════════════════════════════════════════════════════════════════
// Logging
// ═══════════════════════════════════════════════════════════════════

function log(msg) {
    console.log(`[NullSec SSL] ${msg}`);
}

function logSuccess(msg) {
    console.log(`[NullSec SSL] ✅ ${msg}`);
}

function logError(msg) {
    console.log(`[NullSec SSL] ❌ ${msg}`);
}

function logWarning(msg) {
    console.log(`[NullSec SSL] ⚠️ ${msg}`);
}

// ═══════════════════════════════════════════════════════════════════
// SSL Bypass Methods
// ═══════════════════════════════════════════════════════════════════

// Track bypassed methods
let bypassedMethods = [];

/**
 * Bypass NSURLSession certificate validation
 */
function bypassNSURLSession() {
    try {
        const NSURLSessionClass = ObjC.classes.NSURLSession;
        if (!NSURLSessionClass) {
            logWarning("NSURLSession not found");
            return false;
        }

        // Hook URLSession:didReceiveChallenge:completionHandler:
        const className = "NSURLSession";
        
        // Find classes implementing URLSessionDelegate
        for (const className in ObjC.classes) {
            const cls = ObjC.classes[className];
            
            if (cls["- URLSession:didReceiveChallenge:completionHandler:"]) {
                Interceptor.attach(cls["- URLSession:didReceiveChallenge:completionHandler:"].implementation, {
                    onEnter: function(args) {
                        const challenge = new ObjC.Object(args[3]);
                        const protectionSpace = challenge.protectionSpace();
                        const authMethod = protectionSpace.authenticationMethod().toString();
                        
                        if (authMethod === "NSURLAuthenticationMethodServerTrust") {
                            const completionHandler = new ObjC.Block(args[4]);
                            const credential = ObjC.classes.NSURLCredential.credentialForTrust_(
                                protectionSpace.serverTrust()
                            );
                            
                            completionHandler.implementation(0, credential); // NSURLSessionAuthChallengeUseCredential = 0
                            
                            logSuccess(`Bypassed SSL for: ${protectionSpace.host()}`);
                        }
                    }
                });
                
                bypassedMethods.push(`${className} URLSession:didReceiveChallenge:`);
            }
        }
        
        return true;
    } catch (e) {
        logError(`NSURLSession bypass error: ${e}`);
        return false;
    }
}

/**
 * Bypass Security.framework SecTrustEvaluate
 */
function bypassSecTrust() {
    try {
        // SecTrustEvaluate
        const SecTrustEvaluate = Module.findExportByName("Security", "SecTrustEvaluate");
        if (SecTrustEvaluate) {
            Interceptor.attach(SecTrustEvaluate, {
                onLeave: function(retval) {
                    // Always return success (errSecSuccess = 0)
                    retval.replace(0);
                }
            });
            bypassedMethods.push("SecTrustEvaluate");
            logSuccess("Hooked SecTrustEvaluate");
        }
        
        // SecTrustEvaluateWithError (iOS 12+)
        const SecTrustEvaluateWithError = Module.findExportByName("Security", "SecTrustEvaluateWithError");
        if (SecTrustEvaluateWithError) {
            Interceptor.attach(SecTrustEvaluateWithError, {
                onLeave: function(retval) {
                    retval.replace(1); // Return true
                }
            });
            bypassedMethods.push("SecTrustEvaluateWithError");
            logSuccess("Hooked SecTrustEvaluateWithError");
        }
        
        // SecTrustEvaluateAsync
        const SecTrustEvaluateAsync = Module.findExportByName("Security", "SecTrustEvaluateAsync");
        if (SecTrustEvaluateAsync) {
            Interceptor.attach(SecTrustEvaluateAsync, {
                onEnter: function(args) {
                    // Modify the callback to always succeed
                    const callback = args[2];
                    args[2] = new NativeCallback(function(trust, result) {
                        // Call original with kSecTrustResultProceed (1)
                        callback(trust, 1);
                    }, 'void', ['pointer', 'int']);
                }
            });
            bypassedMethods.push("SecTrustEvaluateAsync");
            logSuccess("Hooked SecTrustEvaluateAsync");
        }
        
        return true;
    } catch (e) {
        logError(`SecTrust bypass error: ${e}`);
        return false;
    }
}

/**
 * Bypass AFNetworking SSL Pinning
 */
function bypassAFNetworking() {
    try {
        const AFSecurityPolicy = ObjC.classes.AFSecurityPolicy;
        if (!AFSecurityPolicy) {
            return false;
        }
        
        // Hook setSSLPinningMode:
        if (AFSecurityPolicy["- setSSLPinningMode:"]) {
            Interceptor.attach(AFSecurityPolicy["- setSSLPinningMode:"].implementation, {
                onEnter: function(args) {
                    args[2] = ptr(0); // AFSSLPinningModeNone = 0
                    logSuccess("AFNetworking: Disabled SSL pinning mode");
                }
            });
            bypassedMethods.push("AFSecurityPolicy setSSLPinningMode:");
        }
        
        // Hook setAllowInvalidCertificates:
        if (AFSecurityPolicy["- setAllowInvalidCertificates:"]) {
            Interceptor.attach(AFSecurityPolicy["- setAllowInvalidCertificates:"].implementation, {
                onEnter: function(args) {
                    args[2] = ptr(1); // YES
                    logSuccess("AFNetworking: Allowing invalid certificates");
                }
            });
            bypassedMethods.push("AFSecurityPolicy setAllowInvalidCertificates:");
        }
        
        // Hook evaluateServerTrust:forDomain:
        if (AFSecurityPolicy["- evaluateServerTrust:forDomain:"]) {
            Interceptor.attach(AFSecurityPolicy["- evaluateServerTrust:forDomain:"].implementation, {
                onLeave: function(retval) {
                    retval.replace(1); // Return YES
                }
            });
            bypassedMethods.push("AFSecurityPolicy evaluateServerTrust:forDomain:");
        }
        
        logSuccess("AFNetworking SSL bypass applied");
        return true;
    } catch (e) {
        logError(`AFNetworking bypass error: ${e}`);
        return false;
    }
}

/**
 * Bypass Alamofire SSL Pinning (Swift)
 */
function bypassAlamofire() {
    try {
        // ServerTrustPolicy.evaluate is the key method
        // Swift class names are mangled, so we search for them
        
        for (const className in ObjC.classes) {
            if (className.includes("ServerTrustPolicy") || 
                className.includes("ServerTrustManager")) {
                
                const cls = ObjC.classes[className];
                
                // Look for evaluate methods
                const methods = cls.$methods;
                for (const method of methods) {
                    if (method.includes("evaluate")) {
                        try {
                            Interceptor.attach(cls[method].implementation, {
                                onLeave: function(retval) {
                                    retval.replace(1); // Return true
                                }
                            });
                            bypassedMethods.push(`${className} ${method}`);
                            logSuccess(`Alamofire: Hooked ${className}.${method}`);
                        } catch (e) {
                            // Method might not be hookable
                        }
                    }
                }
            }
        }
        
        return true;
    } catch (e) {
        logError(`Alamofire bypass error: ${e}`);
        return false;
    }
}

/**
 * Bypass TrustKit SSL Pinning
 */
function bypassTrustKit() {
    try {
        const TrustKit = ObjC.classes.TrustKit;
        if (!TrustKit) {
            return false;
        }
        
        // Hook verifyPublicKeyPin:
        if (TrustKit["+ verifyPublicKeyPin:forHostname:reportUri:includeSubdomains:enforcePinning:"]) {
            Interceptor.attach(TrustKit["+ verifyPublicKeyPin:forHostname:reportUri:includeSubdomains:enforcePinning:"].implementation, {
                onLeave: function(retval) {
                    retval.replace(0); // TSKPinValidationResultSuccess = 0
                }
            });
            bypassedMethods.push("TrustKit verifyPublicKeyPin:");
            logSuccess("TrustKit SSL bypass applied");
        }
        
        return true;
    } catch (e) {
        logError(`TrustKit bypass error: ${e}`);
        return false;
    }
}

/**
 * Bypass custom certificate validation
 */
function bypassCustomValidation() {
    try {
        // Look for common certificate validation patterns
        const patterns = [
            "validateCertificate",
            "verifyCertificate",
            "checkCertificate",
            "isCertificateValid",
            "pinCertificate",
            "checkPinning"
        ];
        
        for (const className in ObjC.classes) {
            const cls = ObjC.classes[className];
            const methods = cls.$methods || [];
            
            for (const method of methods) {
                for (const pattern of patterns) {
                    if (method.toLowerCase().includes(pattern.toLowerCase())) {
                        try {
                            Interceptor.attach(cls[method].implementation, {
                                onLeave: function(retval) {
                                    // Assume return YES/true for validation
                                    retval.replace(1);
                                }
                            });
                            bypassedMethods.push(`${className} ${method}`);
                            logSuccess(`Custom: Hooked ${className}.${method}`);
                        } catch (e) {
                            // Method might not be hookable
                        }
                    }
                }
            }
        }
        
        return true;
    } catch (e) {
        logError(`Custom validation bypass error: ${e}`);
        return false;
    }
}

// ═══════════════════════════════════════════════════════════════════
// Network Logging (Premium)
// ═══════════════════════════════════════════════════════════════════

function enableNetworkLogging() {
    if (!isPremium()) {
        logWarning(`Network logging is a Premium feature. Get keys at: ${DISCORD}`);
        return;
    }
    
    try {
        // Hook NSURLSession dataTaskWithRequest:
        const NSURLSession = ObjC.classes.NSURLSession;
        
        Interceptor.attach(NSURLSession["- dataTaskWithRequest:completionHandler:"].implementation, {
            onEnter: function(args) {
                const request = new ObjC.Object(args[2]);
                const url = request.URL().absoluteString().toString();
                const method = request.HTTPMethod().toString();
                
                log(`📤 ${method} ${url}`);
                
                // Log headers
                const headers = request.allHTTPHeaderFields();
                if (headers) {
                    const keys = headers.allKeys();
                    for (let i = 0; i < keys.count(); i++) {
                        const key = keys.objectAtIndex_(i).toString();
                        const value = headers.objectForKey_(key).toString();
                        log(`   ${key}: ${value}`);
                    }
                }
            }
        });
        
        logSuccess("Network logging enabled");
    } catch (e) {
        logError(`Network logging error: ${e}`);
    }
}

// ═══════════════════════════════════════════════════════════════════
// Main
// ═══════════════════════════════════════════════════════════════════

function main() {
    console.log(BANNER);
    console.log(`  Version ${VERSION} | ${AUTHOR}`);
    console.log(`  🔑 Premium: ${DISCORD}\n`);
    
    log("Initializing SSL bypass...\n");
    
    // Apply all bypass methods
    bypassSecTrust();
    bypassNSURLSession();
    bypassAFNetworking();
    bypassAlamofire();
    bypassTrustKit();
    
    if (isPremium()) {
        bypassCustomValidation();
        enableNetworkLogging();
    }
    
    // Summary
    log("\n═══════════════════════════════════════════");
    log(`  Bypassed ${bypassedMethods.length} SSL pinning methods`);
    log("═══════════════════════════════════════════\n");
    
    if (bypassedMethods.length > 0) {
        logSuccess("SSL pinning bypass active!");
    } else {
        logWarning("No SSL pinning methods found to bypass");
    }
}

// Run on script load
main();

// Export functions for REPL usage
rpc.exports = {
    status: function() {
        return {
            bypassed: bypassedMethods,
            premium: isPremium()
        };
    },
    setLicense: function(key) {
        return validateLicense(key);
    }
};
