# Fingerprint #



# Uso:
## En ReactJS/React Native:
```cmd
npm install xfxfp
```

```javascript
import Xfxfp from 'xfxfp';

function App() {
  
  const [fp, setFp] = useState("");

  const finger = new Xfxfp();

  useEffect(() => {
    finger.getFingerprint().then((fingerprint:any) => {
      setFp(fingerprint);
    });
  },[])

  return (
    <div className="App">
      <header className="App-header">
        <img src={logo} className="App-logo" alt="logo" />
        <h3>Fingerprint Token</h3>
        <div>
          <p>{fp}</p>
        </div>
      </header>
    </div>
  );
}

export default App;
```
<br/>

# Métodos

### Get Fingerprint:
```javascript
fp.getFingerprint().then(fingerprint => {
    console.log(fingerprint);
});

//OR

const _fingerprint = await fp.getFingerprint();
console.log(_fingerprint);

// return eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InZwYWFzLW1hZ2ljLWNvb2tpZS0xZmM1NDJhM2U0NDE0YTQ0YjI2MTE2NjgxOTVlMmJmZS80ZjQ5MTAifQ==.eyJoYXNoIjoyNzgzMDgxMzI0LCJ1c2VyQWdlbnQiOiJNb3ppbGxhLzUuMCAoV2luZG93cyBOVCAxMC4wOyBXaW42NDsgeDY0OyBydjoxMDMuMCkgR2Vja28vMjAxMDAxMDEgRmlyZWZveC8xMDMuMCIsInVzZXJBZ2VudExvd2VyQ2FzZSI6Im1vemlsbGEvNS4wICh3aW5kb3dzIG50IDEwLjA7IHdpbjY0OyB4NjQ7IHJ2OjEwMy4wKSBnZWNrby8yMDEwMDEw...
```

### Get Fingerprint Hash:
```javascript
fp.getHash().then(hash => {
    console.log(hash);
});

//OR

const _fpHash = await fp.getHash();
console.log(_fpHash);

//return 2783081324
```

### Get Device Info:
```javascript
fp.getDeviceData().then(data => {
    console.log(data);
});

//OR

const _devideInfo = await fp.getDeviceData();
console.log(_devideInfo);

//return { hash: 2783081324, userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:103.0) Gecko/20100101 Firefox/103.0", userAgentLowerCase: "mozilla/5.0...
```

## Datos que se obtienen:
- availableResolution
- browser
- browserInfo
- browserMajorVersion
- browserVersion
- colorDepth
- cpu
- currentResolution
- device
- deviceType
- deviceVendor
- deviceXDPI
- deviceYDPI
- engine
- engineVersion
- flashVersion
- canvasPrint
- fonts
- language
- timeZone
- isCanvas
- isChrome
- isCookie
- isFirefox
- isFlash
- isFont
- isIE
- isIpad
- isIphone
- isIpod
- isJava
- isLinux
- isLocalStorage
- isMac
- isMimeTypes
- isMobile
- isMobileAndroid
- isMobileBlackBerry
- isMobileIOS
- isMobileMajor
- isMobileOpera
- isMobileWindows
- isOpera
- isSafari
- isSessionStorage
- isSilverlight
- isSolaris
- isUbuntu
- isWindows
- javaVersion
- mimeTypes
- oS
- oSVersion
- plugins
- screenPrint
- silverlightVersion
- systemLanguage
- userAgent
- userAgentLowerCase