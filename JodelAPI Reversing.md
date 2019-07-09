# "Hacking" Jodel
## How does the HMAC-Signing work?
First of all read [this](https://en.wikipedia.org/wiki/HMAC)! It's important to understand what HMAC is used for in order to understand what Jodel is doing there.

Hmac requires a key. Jodel stores this key not in plain text, as it would be way too easy to read it. They are storing it XORed with the APKs signature inside a shared object. (<apk>/lib/<arch>/libx.so). The signing inside the jodel application works as follows:
	
The class `com.jodelapp.jodelandroidv3.api.HmacInterceptor` is responsible for the signing. It has three methods which refer to JNI:
```
- private native void init();
- private native synchronized void register(String str);
- private native synchronized byte[] sign(String str, String str2, byte[] bArr);
```

### private native void init();
This method generates the HMAC-Key in ram. It refers to `sym.Java_com_jodelapp_jodelandroidv3_api_HmacInterceptor_init` in the corresponding shared object.

Reading the assembler code (of the x86 binary) looks like this:
```
<snip>
mov byte [eax + 0x198], 0x95
mov dword [eax + 0x194], 0x9f8effc2
mov byte [eax + 0x19d], 4
mov dword [eax + 0x199], 0x8c0dd9e9
<snip>
```

Thinking of `eax` as the start of a byte[], the assembler code just fills a byte array.

### private native synchronized void register(String str);
This method refers to `sym.Java_com_jodelapp_jodelandroidv3_api_HmacInterceptor_register`. It takes one String parameter which describes what kind of request is going to be signed. For instance:
```
GET@/api/v3/user/config
```

Not sure what it is useful for.

### private native synchronized byte[] sign(String sig, String method, byte[] payload);
Sign refers to `sym.Java_com_jodelapp_jodelandroidv3_api_HmacInterceptor_sign`. It takes three arguments:
```
sig: The APKs SHA1 signature: a4a8d4d7b09736a0f65596a868cc6fd620920fb0 (should be always this value!)
method: Same string which gets called to register(String str): GET@/api/v3/user/recommendedChannels
payload: GET%api.go-tellm.com%443%/api/v3/posts/location/combo%39422506-d25adbe9-4c85ef1a-1dca-4771-abd7-249e4eb16047%49.6679;9.9074%2019-01-12T12:03:32Z%channels%true%home%false%lat%49.667938232421875%lng%9.907393455505371%radius%true%skipHometown%false%stickies%true%
```


As of that, i wrote a python script which disassembles the shared object, collects the bytes and decrypts it (credits for the decryption magic to [cfib90](https://bitbucket.org/cfib90/ojoc-keyhack)). To make it look better i developed this keyhack with fancy angular gui.

---

### Bypass SSL-Pinning
This script is for use with [frida](https://frida.re/). As Jodel is heavily obfuscated, hooking the Jodels enableSslPinning method is nearly impossible. 
But: Jodel is using the `okhttp3.CertificatePinner$Pin` which utilizes `okio.ByteString#equals` to compare the certificates. By letting `equals` always return `true`, any ServerCertificate, provided by you will get accepted. 

Keep in mind that Android version 7 and above only accepts certificates installed in the system CA store (and ignores the one installed by the user). To circumvent this restriction patching the NetworkSecurityConfig is one possibility, another is utilizing [this Magisk module](https://github.com/NVISO-BE/MagiskTrustUserCerts) to move user certificates to the system store. 
```
import frida, sys, time

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

jscode = """
Java.perform(function () {
	var ByteString = Java.use('okio.ByteString');
	
	ByteString.equals.overload('java.lang.Object').implementation = function(obj) {
		send('SSLPinning bypassed!');
		return true;
	}

});
"""

pid = frida.get_usb_device().spawn('com.tellm.android.app')
frida.get_usb_device().resume(pid)
#time.sleep(1) #Without it Java.perform silently fails
session = frida.get_usb_device().attach(pid)
script = session.create_script(jscode)
script.on('message', on_message)
print('Running...')
script.load()
sys.stdin.read()
```
---
