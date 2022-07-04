import {ClientJS} from 'clientjs';
import {CryptoJS} from 'crypto-js';
import {Buffer} from 'buffer';


export default class Xfxfp{
    
    constructor(){}
    
    async HMACSHA256(stringToSign, secret){
        return  CryptoJS.HmacSHA256(stringToSign, secret);
    }

    async _base64(value){
        return await Buffer.from(value).toString('base64');
    }
    
    async _setToken(data, fk){
        const header = {
            "alg": "HS256",
            "typ": "JWT",
            "kid": "vpaas-magic-cookie-1fc542a3e4414a44b2611668195e2bfe/4f4910"
        }
        const encodedHeaders = await this._base64(JSON.stringify(header));

        const encodedPlayload = await this._base64(JSON.stringify({data: data}));	
    
        const signature = this.HMACSHA256(`${encodedHeaders}.${encodedPlayload}`,fk);

        const encodedSignature = await this._base64(signature.toString());
    
        const jwt = `${encodedHeaders}.${encodedPlayload}.${encodedSignature}`;
    
        return jwt;
    
    }

    //Obtiene la info recopilada
    async getDeviceData(){
        
        return new Promise((resolve, reject) => {
            
            const client = new ClientJS();
    
            const fingerprint = {
                hash: client.getFingerprint()
            };
            
            const browserInfo = {
                userAgent: client.getUserAgent(),
                userAgentLowerCase: client.getUserAgentLowerCase(),
                browserInfo: client.getBrowserData(),
                browser:client.getBrowser(),
                browserVersion:client.getBrowserVersion(),
                browserMajorVersion:client.getBrowserMajorVersion(),
                isIE:client.isIE(),
                isChrome:client.isChrome(),
                isFirefox:client.isFirefox(),
                isSafari:client.isSafari(),
                isOpera: client.isOpera(),
                plugins:client.getPlugins(),
                isLocalStorage: client.isLocalStorage(),
                isSessionStorage: client.isSessionStorage(),
                isCookie: client.isCookie(),
                getLanguage: client.getLanguage(),
                getTimeZone: client.getTimeZone()
            }
    
            const engineInfo = {
                engine: client.getEngine(),
                engineVersion: client.getEngineVersion(),
            }
    
            const osInfo = {
                oS: client.getOS(),
                oSVersion: client.getOSVersion(),
                isWindows: client.isWindows(),
                isMac: client.isMac(),
                isLinux: client.isLinux(),
                isUbuntu: client.isUbuntu(),
                isSolaris: client.isSolaris(),
            }
    
            const deviceInfo = {
                device: client.getDevice(),
                deviceType: client.getDeviceType(),
                deviceVendor: client.getDeviceVendor(),
                cpu: client.getCPU()
            }
    
            const mobileInfo = {
                isMobile: client.isMobile(),
                isMobileMajor:client.isMobileMajor(),
                isMobileAndroid:client.isMobileAndroid(),
                isMobileOpera:client.isMobileOpera(),
                isMobileWindows:client.isMobileWindows(),
                isMobileBlackBerry:client.isMobileBlackBerry(),
                isMobileIOS:client.isMobileIOS(),
                isIphone:client.isIphone(),
                isIpad:client.isIpad(),
                isIpod: client.isIpod()
            }
    
            const screenInfo = {
                screenPrint:client.getScreenPrint(),
                colorDepth: client.getColorDepth(),
                currentResolution:client.getCurrentResolution(),
                availableResolution:client.getAvailableResolution(),
                deviceXDPI:client.getDeviceXDPI(),
                deviceYDPI:client.getDeviceYDPI()
            }
    
            const fontInfo = {
                mimeTypes: client.getMimeTypes(),
                isMimeTypes: client.isMimeTypes(),
                isFont: client.isFont(),
                getFonts: client.getFonts(),
            }
    
            const generalInfo = {
                systemLanguage : client.getSystemLanguage(),
                isCanvas: client.isCanvas(),
                getCanvasPrint: client.getCanvasPrint(),
            }
    
            let _data = {...fingerprint, ...browserInfo, ...engineInfo, ...osInfo, ...deviceInfo, ...mobileInfo, ...screenInfo, ...fontInfo, ...generalInfo};

            resolve(_data);
        })

    }
    //Obtiene el hash asignado al fingerprint
    async getHash(){
        return new Promise((resolve, reject) => {
            let client = new ClientJS();
            resolve(client.getFingerprint());
        })
    }
    //Obtiene el token asignado al fingerprint
    async getFingerprint(){
        return new Promise(async (resolve, reject) => {
            this.getDeviceData()
            .then((_dData) => this._setToken(_dData, "xfxfp14624982brjs"))
            .then((tk) => { 
                resolve(tk); 
            }).catch((e)=>{
                reject(e.message);
            });
        })
    }   
    //Valida el fingerprint cointra el backend
    async validFingerprint(){}

};